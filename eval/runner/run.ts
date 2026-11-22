import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type {
  AblationRow,
  DetectorOutput,
  DetectorSummary,
  DoseResponse,
  EvalEnvironment,
  EvalResults,
  FamilyScorecard,
  GroundTruth,
  SensitivityRow,
  TraceEvaluation,
  TraceManifest,
  TraceRecord,
  TuningResult,
} from '../types.ts';
import type { DetectorId, Family } from '../config.ts';
import {
  CALIBRATION_PATH,
  DEFAULT_CONTAINMENT_LATENCY_MS,
  DEFAULT_FPR_BUDGET,
  DEFAULT_GENERATION_SEED,
  DEFAULT_RUN_SEED,
  EVAL_DATA_DIR,
  FAMILIES,
  FAST_TRACES_PER_FAMILY,
  LIVE_VALIDATION_PATH,
  MANIFEST_PATH,
  RESULTS_DIR,
} from '../config.ts';
import { hashString } from '../prng.ts';
import { DETECTORS, tuningGridFor } from '../detectors/index.ts';
import { evaluateTrace, summarize } from '../metrics.ts';
import { median, wilsonInterval } from '../stats.ts';
import { readTrace } from '../generator/generate.ts';
import { loadCalibrationProfile } from '../generator/calibration.ts';
import { renderScorecard } from './scorecard.ts';

export interface RunOptions {
  mode: 'fast' | 'full';
  seed: number;
  resume?: boolean;
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(',')}}`;
}

function sha256(input: string): string {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function loadManifest(): TraceManifest {
  if (!fs.existsSync(MANIFEST_PATH)) {
    throw new Error(
      `No trace manifest at ${MANIFEST_PATH}. Run "npm run eval:gen" first.`,
    );
  }
  return JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8')) as TraceManifest;
}

function selectTraces(manifest: TraceManifest, mode: 'fast' | 'full', seed: number): TraceManifest['traces'] {
  const heldout = manifest.traces.filter((t) => t.split === 'heldout');
  if (mode === 'full') return heldout;
  const selected: TraceManifest['traces'] = [];
  for (const family of FAMILIES) {
    const members = heldout
      .filter((t) => t.family === family)
      .sort((a, b) => hashString(`${a.traceId}:${seed}`) - hashString(`${b.traceId}:${seed}`));
    selected.push(...members.slice(0, FAST_TRACES_PER_FAMILY));
  }
  return selected;
}

function loadLiveContainmentLatency(): { latencyMs: number; source: string } {
  try {
    if (fs.existsSync(LIVE_VALIDATION_PATH)) {
      const parsed = JSON.parse(fs.readFileSync(LIVE_VALIDATION_PATH, 'utf8')) as {
        mttcMedianMs?: number;
        summary?: { mttcMedianMs?: number };
        runs?: unknown[];
      };
      const value = parsed.mttcMedianMs ?? parsed.summary?.mttcMedianMs;
      if (typeof value === 'number' && Number.isFinite(value) && value >= 0) {
        const runs = Array.isArray(parsed.runs) ? parsed.runs.length : 0;
        return {
          latencyMs: Math.round(value),
          source: `live simulator MTTC median (${runs} runs)`,
        };
      }
    }
  } catch {
    // Fall through to the fixed value.
  }
  return {
    latencyMs: DEFAULT_CONTAINMENT_LATENCY_MS,
    source: 'fixed default; no live MTTC recording available',
  };
}

function runDetector(
  detectorId: string,
  trace: TraceRecord,
  params: Record<string, unknown>,
  seed: number,
): DetectorOutput {
  const detector = DETECTORS.find((d) => d.id === detectorId);
  if (!detector) throw new Error(`Unknown detector ${detectorId}`);
  return detector.run({
    events: trace.events,
    params,
    seed,
    bucket: trace.groundTruth.bucket,
  });
}

function recoveryFor(
  detectorId: string,
  params: Record<string, unknown>,
  trace: TraceRecord,
): ReturnType<(typeof DETECTORS)[number]['recovery']> {
  const detector = DETECTORS.find((d) => d.id === detectorId);
  if (!detector) throw new Error(`Unknown detector ${detectorId}`);
  return detector.recovery(params, trace.events);
}

function tuneDetectors(
  tuningTraces: TraceRecord[],
  fprBudget: number,
  seed: number,
): TuningResult[] {
  const results: TuningResult[] = [];
  for (const detector of DETECTORS) {
    if (detector.id.startsWith('D9')) {
      results.push({
        detectorId: detector.id,
        grid: [],
        selected: {},
        fprBudget,
        notes: detector.id === 'D9' ? 'Shipped policies.yaml; not tuned.' : 'Ablation; not tuned.',
      });
      continue;
    }
    const grid = tuningGridFor(detector.id);
    const points = grid.map((params) => {
      let detections = 0;
      let attackTraces = 0;
      let falsePositives = 0;
      let ttdSum = 0;
      let ttdCount = 0;
      for (const trace of tuningTraces) {
        const output = runDetector(detector.id, trace, params, seed);
        const evaluation = evaluateTrace(trace, detector.id as DetectorId, output, {
          containmentLatencyMs: 0,
          recovery: recoveryFor(detector.id, params, trace),
          seed,
        });
        if (trace.groundTruth.attackStartMs !== null) {
          attackTraces++;
          if (evaluation.detected) {
            detections++;
            ttdSum += evaluation.timeToDetectMs ?? 0;
            ttdCount++;
          }
        }
        if (evaluation.falsePositive) falsePositives++;
      }
      return {
        params,
        detectionRate: attackTraces > 0 ? detections / attackTraces : 0,
        falsePositiveRate: tuningTraces.length > 0 ? falsePositives / tuningTraces.length : 0,
        traces: tuningTraces.length,
        selected: false,
        medianTimeToDetectMs: ttdCount > 0 ? ttdSum / ttdCount : null,
      };
    });

    const eligible = points.filter((p) => p.falsePositiveRate <= fprBudget);
    const pool = eligible.length > 0 ? eligible : points;
    const best = [...pool].sort((a, b) => {
      if (b.detectionRate !== a.detectionRate) return b.detectionRate - a.detectionRate;
      if (a.falsePositiveRate !== b.falsePositiveRate) return a.falsePositiveRate - b.falsePositiveRate;
      const aTtd = a.medianTimeToDetectMs ?? Number.POSITIVE_INFINITY;
      const bTtd = b.medianTimeToDetectMs ?? Number.POSITIVE_INFINITY;
      return aTtd - bTtd;
    })[0];
    if (best) best.selected = true;

    results.push({
      detectorId: detector.id,
      grid: points.map(({ medianTimeToDetectMs: _medianTimeToDetectMs, ...rest }) => rest),
      selected: best?.params ?? {},
      fprBudget,
      notes:
        eligible.length === 0
          ? 'No grid point met the FP budget; selected the lowest-FP point and report the miss.'
          : undefined,
    });
  }
  return results;
}

function computeD9TuningFpr(tuningTraces: TraceRecord[], seed: number): number {
  let falsePositives = 0;
  for (const trace of tuningTraces) {
    const output = runDetector('D9', trace, {}, seed);
    const evaluation = evaluateTrace(trace, 'D9', output, {
      containmentLatencyMs: 0,
      recovery: recoveryFor('D9', {}, trace),
      seed,
    });
    if (evaluation.falsePositive) falsePositives++;
  }
  return tuningTraces.length > 0 ? falsePositives / tuningTraces.length : 0;
}

function buildDoseResponse(
  perTrace: TraceEvaluation[],
  traces: TraceRecord[],
  tuning: TuningResult[],
): DoseResponse {
  const traceById = new Map(traces.map((t) => [t.groundTruth.traceId, t]));
  const attackEvals = perTrace.filter(
    (e) => traceById.get(e.traceId)?.groundTruth.attackStartMs !== null,
  );
  const detectorIds = Array.from(new Set(perTrace.map((e) => e.detectorId)));

  const filesLostVsSpeed: DoseResponse['filesLostVsSpeed'] = [];
  for (const detectorId of detectorIds) {
    for (const speed of ['slow', 'medium', 'fast'] as const) {
      const values = attackEvals
        .filter(
          (e) =>
            e.detectorId === detectorId &&
            traceById.get(e.traceId)?.groundTruth.scenario.speed === speed,
        )
        .map((e) => e.filesLost);
      if (values.length > 0) {
        filesLostVsSpeed.push({ speed, detectorId, medianFilesLost: median(values) });
      }
    }
  }

  const detectionVsPrincipals: DoseResponse['detectionVsPrincipals'] = [];
  for (const detectorId of detectorIds) {
    for (const principals of [1, 2, 4, 8]) {
      const subset = attackEvals.filter(
        (e) =>
          e.detectorId === detectorId &&
          traceById.get(e.traceId)?.groundTruth.scenario.principals === principals,
      );
      if (subset.length > 0) {
        detectionVsPrincipals.push({
          principals,
          detectorId,
          detectionRate: subset.filter((e) => e.detected).length / subset.length,
          traces: subset.length,
        });
      }
    }
  }

  const detectionVsAttackToNoise: DoseResponse['detectionVsAttackToNoise'] = [];
  for (const detectorId of detectorIds) {
    for (const ratio of [5, 20, 100]) {
      const subset = attackEvals.filter(
        (e) =>
          e.detectorId === detectorId &&
          traceById.get(e.traceId)?.groundTruth.scenario.attackToNoiseRatio === ratio,
      );
      if (subset.length > 0) {
        detectionVsAttackToNoise.push({
          ratio,
          detectorId,
          detectionRate: subset.filter((e) => e.detected).length / subset.length,
          traces: subset.length,
        });
      }
    }
  }

  const fprVsThreshold: DoseResponse['fprVsThreshold'] = [];
  for (const tuningResult of tuning) {
    if (tuningResult.grid.length <= 1) continue;
    const thresholdName = thresholdNameFor(tuningResult.detectorId);
    for (const point of tuningResult.grid) {
      const raw = point.params[thresholdName];
      const threshold =
        typeof raw === 'number'
          ? raw
          : Array.isArray(raw)
            ? raw.length
            : typeof raw === 'string'
              ? 0
              : 0;
      fprVsThreshold.push({
        detectorId: tuningResult.detectorId,
        thresholdName,
        threshold,
        falsePositiveRate: point.falsePositiveRate,
      });
    }
  }

  return { filesLostVsSpeed, detectionVsPrincipals, detectionVsAttackToNoise, fprVsThreshold };
}

function thresholdNameFor(detectorId: string): string {
  switch (detectorId) {
    case 'D1':
      return 'intervalHours';
    case 'D2':
      return 'z';
    case 'D3':
      return 'batchMinutes';
    case 'D4':
    case 'D8':
      return 'entropyThreshold';
    case 'D5':
      return 'entropyDeltaThreshold';
    case 'D6':
      return 'extensions';
    case 'D7':
      return 'names';
    default:
      return 'threshold';
  }
}

function buildAblations(overall: DetectorSummary[]): AblationRow[] {
  const d9 = overall.find((s) => s.detectorId === 'D9');
  if (!d9) return [];
  return overall
    .filter((s) => s.detectorId.startsWith('D9') && s.detectorId !== 'D9')
    .map((s) => ({
      detectorId: s.detectorId,
      component: s.detectorName.replace('DefySwarm minus ', ''),
      detectionRate: s.detectionRate,
      falsePositiveRate: s.falsePositiveRate,
      medianFilesLost: s.medianFilesLost,
      deltaDetectionVsD9: s.detectionRate - d9.detectionRate,
      deltaFalsePositiveVsD9: s.falsePositiveRate - d9.falsePositiveRate,
    }));
}

function buildSensitivity(
  outputsByDetector: Map<string, Map<string, DetectorOutput>>,
  traces: TraceRecord[],
  latencies: number[],
  seed: number,
): SensitivityRow[] {
  const rows: SensitivityRow[] = [];
  for (const latencyMs of latencies) {
    for (const [detectorId, outputs] of outputsByDetector) {
      const evaluations: TraceEvaluation[] = [];
      for (const trace of traces) {
        const output = outputs.get(trace.groundTruth.traceId);
        if (!output) continue;
        evaluations.push(
          evaluateTrace(trace, detectorId as DetectorId, output, {
            containmentLatencyMs: latencyMs,
            recovery: recoveryFor(detectorId, {}, trace),
            seed,
          }),
        );
      }
      const attackEvals = evaluations.filter(
        (e) => traces.find((t) => t.groundTruth.traceId === e.traceId)?.groundTruth.attackStartMs !== null,
      );
      rows.push({
        latencyMs,
        detectorId: detectorId as DetectorId,
        medianFilesLost: attackEvals.length > 0 ? median(attackEvals.map((e) => e.filesLost)) : 0,
        detectionRate:
          attackEvals.length > 0
            ? attackEvals.filter((e) => e.detected).length / attackEvals.length
            : 0,
      });
    }
  }
  return rows;
}

function writeCsv(filePath: string, rows: Array<Record<string, unknown>>, columns: string[]): void {
  const lines = [columns.join(',')];
  for (const row of rows) {
    lines.push(
      columns
        .map((column) => {
          const value = row[column];
          if (value === null || value === undefined) return '';
          const text = String(value);
          return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
        })
        .join(','),
    );
  }
  fs.writeFileSync(filePath, `${lines.join('\n')}\n`, 'utf8');
}

function readPartialOutputs(
  partialDir: string,
  detectorId: string,
): Map<string, DetectorOutput> {
  const file = path.join(partialDir, 'outputs', `${detectorId}.jsonl`);
  const map = new Map<string, DetectorOutput>();
  if (!fs.existsSync(file)) return map;
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    try {
      const parsed = JSON.parse(line) as { traceId: string; output: DetectorOutput };
      map.set(parsed.traceId, parsed.output);
    } catch {
      // Ignore a torn final line from an interrupted run.
    }
  }
  return map;
}

function appendPartialOutput(
  partialDir: string,
  detectorId: string,
  traceId: string,
  output: DetectorOutput,
): void {
  fs.mkdirSync(path.join(partialDir, 'outputs'), { recursive: true });
  fs.appendFileSync(
    path.join(partialDir, 'outputs', `${detectorId}.jsonl`),
    `${JSON.stringify({ traceId, output })}\n`,
    'utf8',
  );
}

export function runEvaluation(options: RunOptions): EvalResults {
  const seed = options.seed ?? DEFAULT_RUN_SEED;
  const manifest = loadManifest();
  const heldoutEntries = selectTraces(manifest, options.mode, seed);
  const tuningEntries = manifest.traces.filter((t) => t.split === 'tuning');

  const heldoutTraces = heldoutEntries.map(readTrace);
  const tuningTraces = tuningEntries.map(readTrace);

  const d9TuningFpr = computeD9TuningFpr(tuningTraces, seed);
  const fprBudget = Math.max(DEFAULT_FPR_BUDGET, d9TuningFpr);
  const tuning = tuneDetectors(tuningTraces, fprBudget, seed);
  const selectedParams = new Map(tuning.map((t) => [t.detectorId, t.selected]));

  const latency = loadLiveContainmentLatency();

  const manifestHash = sha256(
    stableStringify(manifest.traces.map((t) => ({ traceId: t.traceId, sha256: t.sha256 }))),
  );
  const configHash = sha256(
    stableStringify({
      mode: options.mode,
      seed,
      generationSeed: manifest.generationSeed,
      manifestHash,
      selectedParams: Object.fromEntries(selectedParams),
      latency: latency.latencyMs,
    }),
  );
  const runId = `eval-${options.mode}-${seed}-${configHash.slice(0, 10)}`;
  const resultsDir = path.join(RESULTS_DIR, runId);
  const partialDir = path.join(resultsDir, 'partial');
  fs.mkdirSync(partialDir, { recursive: true });

  const completedPath = path.join(partialDir, 'completed.json');
  let completed: Record<string, string[]> = {};
  if (fs.existsSync(completedPath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(completedPath, 'utf8')) as {
        configHash: string;
        completed: Record<string, string[]>;
      };
      if (parsed.configHash === configHash) completed = parsed.completed ?? {};
    } catch {
      completed = {};
    }
  }

  const outputsByDetector = new Map<string, Map<string, DetectorOutput>>();
  for (const detector of DETECTORS) {
    const partial = readPartialOutputs(partialDir, detector.id);
    const completedSet = new Set(completed[detector.id] ?? []);
    for (const traceId of completedSet) {
      const output = partial.get(traceId);
      if (output) {
        if (!outputsByDetector.has(detector.id)) outputsByDetector.set(detector.id, new Map());
        outputsByDetector.get(detector.id)!.set(traceId, output);
      }
    }
  }

  for (const detector of DETECTORS) {
    const params = selectedParams.get(detector.id) ?? {};
    if (!outputsByDetector.has(detector.id)) outputsByDetector.set(detector.id, new Map());
    const store = outputsByDetector.get(detector.id)!;
    const completedSet = new Set(completed[detector.id] ?? []);
    for (const trace of heldoutTraces) {
      const traceId = trace.groundTruth.traceId;
      if (completedSet.has(traceId) && store.has(traceId)) continue;
      const output = runDetector(detector.id, trace, params, seed);
      store.set(traceId, output);
      appendPartialOutput(partialDir, detector.id, traceId, output);
      completedSet.add(traceId);
      if (completedSet.size % 4 === 0) {
        completed[detector.id] = Array.from(completedSet);
        fs.writeFileSync(
          completedPath,
          JSON.stringify({ configHash, completed }, null, 2),
          'utf8',
        );
      }
    }
    completed[detector.id] = Array.from(completedSet);
    fs.writeFileSync(completedPath, JSON.stringify({ configHash, completed }, null, 2), 'utf8');
  }

  const perTrace: TraceEvaluation[] = [];
  const evaluationsByDetector = new Map<string, TraceEvaluation[]>();
  for (const detector of DETECTORS) {
    const params = selectedParams.get(detector.id) ?? {};
    const outputs = outputsByDetector.get(detector.id) ?? new Map();
    const evaluations: TraceEvaluation[] = [];
    for (const trace of heldoutTraces) {
      const output = outputs.get(trace.groundTruth.traceId);
      if (!output) continue;
      const evaluation = evaluateTrace(trace, detector.id as DetectorId, output, {
        containmentLatencyMs: latency.latencyMs,
        recovery: recoveryFor(detector.id, params, trace),
        seed,
      });
      evaluations.push(evaluation);
      perTrace.push(evaluation);
    }
    evaluationsByDetector.set(detector.id, evaluations);
  }

  const d9Evaluations = evaluationsByDetector.get('D9') ?? [];
  const scorecard: FamilyScorecard[] = FAMILIES.map((family) => {
    const familyTraces = heldoutTraces.filter((t) => t.groundTruth.family === family);
    const summaries = DETECTORS.map((detector) => {
      const evaluations = (evaluationsByDetector.get(detector.id) ?? []).filter(
        (e) => e.family === family,
      );
      return summarize({
        evaluations,
        traces: familyTraces,
        detectorId: detector.id as DetectorId,
        detectorName: detector.name,
        family,
        seed,
        d9Evaluations: d9Evaluations.filter((e) => e.family === family),
      });
    });
    return { family, summaries };
  });

  const overall = DETECTORS.map((detector) =>
    summarize({
      evaluations: evaluationsByDetector.get(detector.id) ?? [],
      traces: heldoutTraces,
      detectorId: detector.id as DetectorId,
      detectorName: detector.name,
      family: 'overall',
      seed,
      d9Evaluations,
    }),
  );

  const ablations = buildAblations(overall);
  const sensitivity = buildSensitivity(
    outputsByDetector,
    heldoutTraces,
    [0, 1000, 5000, 30_000, 300_000],
    seed,
  );
  const doseResponse = buildDoseResponse(perTrace, heldoutTraces, tuning);

  const calibration = loadCalibrationProfile();
  const environment: EvalEnvironment = {
    platform: `${os.platform()} ${os.release()}`,
    node: process.version,
    cpus: os.cpus().length,
    totalMemoryMb: Math.round(os.totalmem() / (1024 * 1024)),
    productVersion: readProductVersion(),
    detectorImplementation:
      'D9: shipped server/detectionEngine.ts + server/storageAdapter.ts (fresh in-memory instance); D0-D8: eval/detectors/baselines.ts reference implementations',
    path: 'replay',
  };

  const limitations = [
    'Traces are generated by the seeded synthetic generator in eval/generator. They are not production telemetry.',
    calibration.recordings === 0
      ? 'No recorded traces exist yet. Generator calibration is uncalibrated synthetic; see calibration.json.'
      : `Generator calibration was fitted to ${calibration.recordings} recorded trace(s); recorded traces come from the local simulator unless labelled otherwise.`,
    'D0-D8 are our own reference implementations of common approaches, not vendor products.',
    'D5 (sync client) cannot see direct API-key attacks by construction; that is a threat-model difference, not a product failure.',
    'D9 uses the shipped data/policies.yaml unchanged. Baselines were tuned on the 30% tuning seed split to maximise detection subject to the same FP budget.',
    'The containment model blocks attacker events at detection + L. L is a post-detection latency, not a network round-trip measurement.',
    'Files lost counts distinct real files touched by labelled attack events before the block. Recoverable reports whether the detector has a recovery mechanism, not whether a specific restore was executed.',
    'Mixed-trace alert precision treats any alert before the labelled attack start as a false positive.',
    'Some D9 ablations are emulated at the event or policy boundary because policies.yaml cannot switch every component off independently. See docs/eval/BASELINES.md.',
    'No live external S3 endpoint, vendor product, or production data was used in the replay scorecard.',
  ];

  const partialResults: Omit<EvalResults, 'determinismHash'> = {
    runId,
    generatedAt: new Date().toISOString(),
    mode: options.mode,
    seed,
    generationSeed: manifest.generationSeed,
    tracesTotal: manifest.totalTraces,
    tracesUsed: heldoutTraces.length,
    tuningTraces: tuningTraces.length,
    heldoutTraces: heldoutEntries.length,
    containmentLatencyMs: latency.latencyMs,
    containmentLatencySource: latency.source,
    environment,
    scorecard,
    overall,
    ablations,
    sensitivity,
    doseResponse,
    tuning,
    perTrace,
    limitations,
  };
  const { generatedAt: _generatedAt, ...hashableResults } = partialResults;
  const determinismHash = sha256(stableStringify(hashableResults));
  const results: EvalResults = { ...partialResults, determinismHash };

  fs.writeFileSync(path.join(resultsDir, 'results.json'), JSON.stringify(results, null, 2), 'utf8');
  fs.writeFileSync(path.join(resultsDir, 'tuning.json'), JSON.stringify(tuning, null, 2), 'utf8');
  fs.writeFileSync(
    path.join(resultsDir, 'determinism.json'),
    JSON.stringify(
      {
        algorithm: 'sha256(stableStringify(results without generatedAt))',
        hash: determinismHash,
        mode: options.mode,
        seed,
        generationSeed: manifest.generationSeed,
      },
      null,
      2,
    ),
    'utf8',
  );
  fs.writeFileSync(
    path.join(resultsDir, 'charts.json'),
    JSON.stringify(doseResponse, null, 2),
    'utf8',
  );
  fs.writeFileSync(
    path.join(resultsDir, 'scorecard.md'),
    renderScorecard(results, {
      calibrationNotes:
        calibration.recordings === 0
          ? [
              'No recorded traces exist yet. The scorecard is a synthetic-replay result and must be labelled that way when presented.',
              'Run "npm run eval:record" against a live simulator run, then "npm run eval:calibrate" to fit the generator.',
            ]
          : calibration.notes,
    }),
    'utf8',
  );

  writeCsv(
    path.join(resultsDir, 'per-trace.csv'),
    perTrace.map((e) => ({
      runId,
      traceId: e.traceId,
      family: e.family,
      detectorId: e.detectorId,
      detected: e.detected,
      timeToDetectMs: e.timeToDetectMs,
      timeToContainMs: e.timeToContainMs,
      filesLost: e.filesLost,
      filesLostPct: e.filesLostPct,
      recoverable: e.recoverable,
      recoveryPointLossMs: e.recoveryPointLossMs,
      falsePositive: e.falsePositive,
      alertPrecision: e.alertPrecision,
      alertCount: e.alerts.length,
      attackStartMs: e.attackStartMs,
    })),
    [
      'runId',
      'traceId',
      'family',
      'detectorId',
      'detected',
      'timeToDetectMs',
      'timeToContainMs',
      'filesLost',
      'filesLostPct',
      'recoverable',
      'recoveryPointLossMs',
      'falsePositive',
      'alertPrecision',
      'alertCount',
      'attackStartMs',
    ],
  );

  writeCsv(
    path.join(resultsDir, 'ablations.csv'),
    ablations as unknown as Array<Record<string, unknown>>,
    [
      'detectorId',
      'component',
      'detectionRate',
      'falsePositiveRate',
      'medianFilesLost',
      'deltaDetectionVsD9',
      'deltaFalsePositiveVsD9',
    ],
  );
  writeCsv(
    path.join(resultsDir, 'sensitivity.csv'),
    sensitivity as unknown as Array<Record<string, unknown>>,
    ['latencyMs', 'detectorId', 'medianFilesLost', 'detectionRate'],
  );

  fs.mkdirSync(RESULTS_DIR, { recursive: true });
  fs.writeFileSync(
    path.join(RESULTS_DIR, 'latest.json'),
    JSON.stringify({ runId, directory: path.relative(EVAL_DATA_DIR, resultsDir) }, null, 2),
    'utf8',
  );

  return results;
}

function readProductVersion(): string {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'package.json'), 'utf8')) as {
      version?: string;
    };
    return pkg.version ?? 'unknown';
  } catch {
    return 'unknown';
  }
}

export function formatRunSummary(results: EvalResults): string {
  const d9 = results.overall.find((s) => s.detectorId === 'D9');
  const lines = [
    `Run ${results.runId} (${results.mode}, seed ${results.seed})`,
    `Traces: ${results.tracesUsed} held-out; tuning: ${results.tuningTraces}`,
    `Containment latency: ${results.containmentLatencyMs} ms (${results.containmentLatencySource})`,
    `Determinism hash: ${results.determinismHash}`,
  ];
  if (d9) {
    const [lo, hi] = d9.detectionCi;
    lines.push(
      `D9 detection: ${(d9.detectionRate * 100).toFixed(1)}% [${(lo * 100).toFixed(1)}%, ${(
        hi * 100
      ).toFixed(1)}%], FP trace rate ${(d9.falsePositiveRate * 100).toFixed(1)}%, median files lost ${
        d9.medianFilesLost
      }`,
    );
  }
  lines.push(`Scorecard: eval-data/results/${results.runId}/scorecard.md`);
  return lines.join('\n');
}
