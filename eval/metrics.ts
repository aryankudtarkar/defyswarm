import type {
  Alert,
  DetectorOutput,
  DetectorSummary,
  RecoveryModel,
  TraceEvaluation,
  TraceRecord,
} from './types.ts';
import type { DetectorId, Family } from './config.ts';
import {
  bootstrapInterval,
  mcnemarExact,
  median,
  pairedBootstrapDiff,
  p95,
  wilsonInterval,
} from './stats.ts';

export interface ScoreOptions {
  containmentLatencyMs: number;
  recovery: RecoveryModel;
  seed?: number;
}

/**
 * Score one detector output against ground truth. This is the only place that
 * reads GroundTruth. Detectors never see this function's inputs.
 */
export function evaluateTrace(
  trace: TraceRecord,
  detectorId: DetectorId,
  output: DetectorOutput,
  options: ScoreOptions,
): TraceEvaluation {
  const gt = trace.groundTruth;
  const alerts = [...output.alerts].sort((a, b) => a.timeMs - b.timeMs || a.seq - b.seq);
  const isAttackTrace = gt.attackStartMs !== null;

  const detectionAlerts = isAttackTrace
    ? alerts.filter((a) => a.timeMs >= (gt.attackStartMs as number))
    : [];
  const firstDetection = detectionAlerts.length > 0 ? detectionAlerts[0].timeMs : null;
  const detected = isAttackTrace && firstDetection !== null;
  const attackStart = gt.attackStartMs ?? 0;

  const timeToDetectMs = detected && firstDetection !== null ? Math.max(0, firstDetection - attackStart) : null;
  const timeToContainMs =
    timeToDetectMs !== null ? timeToDetectMs + options.containmentLatencyMs : null;
  const blockTimeMs =
    detected && firstDetection !== null ? firstDetection + options.containmentLatencyMs : Number.POSITIVE_INFINITY;

  const attackFileEvents: TraceEvaluation['attackFileEvents'] = [];
  const lostFiles = new Set<string>();
  for (const event of trace.events) {
    if (!gt.eventAttackFlags[event.seq]) continue;
    const fileId = gt.eventFileIds[event.seq];
    if (!fileId) continue;
    attackFileEvents.push({
      timeMs: event.timeMs,
      fileId,
      operation: event.operation,
      key: event.key,
    });
    if (event.timeMs <= blockTimeMs) {
      lostFiles.add(fileId);
    }
  }

  const falsePositiveAlerts = alerts.filter((a) => {
    if (!isAttackTrace) return true;
    if (a.timeMs < attackStart) return true;
    return !gt.attackerPrincipals.includes(a.principal);
  });
  const truePositiveAlerts = alerts.filter(
    (a) => isAttackTrace && a.timeMs >= attackStart && gt.attackerPrincipals.includes(a.principal),
  );
  const alertPrecision =
    isAttackTrace && alerts.length > 0
      ? truePositiveAlerts.length / Math.max(1, truePositiveAlerts.length + falsePositiveAlerts.length)
      : null;

  const filesLost = lostFiles.size;
  const filesLostPct = gt.totalRealFiles > 0 ? (filesLost / gt.totalRealFiles) * 100 : 0;

  return {
    traceId: gt.traceId,
    family: gt.family,
    detectorId,
    detected,
    timeToDetectMs,
    timeToContainMs,
    filesLost,
    filesLostPct: Number(filesLostPct.toFixed(2)),
    recoverable: options.recovery.capable,
    recoveryPointLossMs: options.recovery.recoveryPointLossMs,
    falsePositive: falsePositiveAlerts.length > 0,
    alertPrecision,
    alerts,
    attackStartMs: gt.attackStartMs,
    attackFileEvents,
  };
}

export interface SummaryInput {
  evaluations: TraceEvaluation[];
  traces: TraceRecord[];
  detectorId: DetectorId;
  detectorName: string;
  family: Family | 'overall';
  seed: number;
  d9Evaluations?: TraceEvaluation[];
}

export function summarize(input: SummaryInput): DetectorSummary {
  const { evaluations, traces, detectorId, detectorName, seed } = input;
  const traceById = new Map(traces.map((t) => [t.groundTruth.traceId, t]));
  const attackEvals = evaluations.filter((e) => traceById.get(e.traceId)?.groundTruth.attackStartMs !== null);
  const benignEvals = evaluations.filter((e) => traceById.get(e.traceId)?.groundTruth.attackStartMs === null);

  const detectionSuccesses = attackEvals.filter((e) => e.detected).length;
  const fpSuccesses = evaluations.filter((e) => e.falsePositive).length;
  const detectionCi =
    attackEvals.length > 0 ? wilsonInterval(detectionSuccesses, attackEvals.length) : ([0, 0] as [number, number]);
  const fpCi =
    evaluations.length > 0 ? wilsonInterval(fpSuccesses, evaluations.length) : ([0, 0] as [number, number]);

  const ttds = attackEvals
    .map((e) => e.timeToDetectMs)
    .filter((v): v is number => v !== null);
  const ttcs = attackEvals
    .map((e) => e.timeToContainMs)
    .filter((v): v is number => v !== null);
  const filesLost = attackEvals.map((e) => e.filesLost);
  const precisions = attackEvals
    .map((e) => e.alertPrecision)
    .filter((v): v is number => v !== null);

  let mcnemarPValueVsD9: number | null = null;
  let filesLostDiffVsD9: { medianDiff: number; ci: [number, number] } | null = null;
  if (input.d9Evaluations && input.d9Evaluations.length === evaluations.length) {
    const d9ById = new Map(input.d9Evaluations.map((e) => [e.traceId, e]));
    if (attackEvals.length > 0) {
      let b = 0;
      let c = 0;
      const arm: number[] = [];
      const d9Arm: number[] = [];
      for (const e of attackEvals) {
        const d9 = d9ById.get(e.traceId);
        if (!d9) continue;
        if (e.detected && !d9.detected) b++;
        if (!e.detected && d9.detected) c++;
        arm.push(e.filesLost);
        d9Arm.push(d9.filesLost);
      }
      mcnemarPValueVsD9 = mcnemarExact(b, c);
      if (arm.length > 0) {
        const diff = pairedBootstrapDiff(arm, d9Arm, median, { seed: seed + 17 });
        filesLostDiffVsD9 = { medianDiff: diff.diff, ci: diff.ci };
      }
    } else if (evaluations.length > 0) {
      // Benign family: compare false-positive decisions.
      let b = 0;
      let c = 0;
      for (const e of evaluations) {
        const d9 = d9ById.get(e.traceId);
        if (!d9) continue;
        if (e.falsePositive && !d9.falsePositive) b++;
        if (!e.falsePositive && d9.falsePositive) c++;
      }
      mcnemarPValueVsD9 = mcnemarExact(b, c);
    }
  }

  const recoveryLosses = attackEvals
    .map((e) => e.recoveryPointLossMs)
    .filter((v): v is number => v !== null);

  return {
    detectorId,
    detectorName,
    traces: evaluations.length,
    attackTraces: attackEvals.length,
    benignTraces: benignEvals.length,
    detectionRate: attackEvals.length > 0 ? detectionSuccesses / attackEvals.length : 0,
    detectionCi,
    falsePositiveRate: evaluations.length > 0 ? fpSuccesses / evaluations.length : 0,
    falsePositiveCi: fpCi,
    medianTimeToDetectMs: ttds.length > 0 ? median(ttds) : null,
    p95TimeToDetectMs: ttds.length > 0 ? p95(ttds) : null,
    medianTimeToContainMs: ttcs.length > 0 ? median(ttcs) : null,
    medianFilesLost: filesLost.length > 0 ? median(filesLost) : 0,
    worstFilesLost: filesLost.length > 0 ? Math.max(...filesLost) : 0,
    recoverablePct:
      attackEvals.length > 0
        ? (attackEvals.filter((e) => e.recoverable).length / attackEvals.length) * 100
        : 100,
    medianRecoveryPointLossMs: recoveryLosses.length > 0 ? median(recoveryLosses) : null,
    alertPrecision:
      precisions.length > 0 ? precisions.reduce((a, b) => a + b, 0) / precisions.length : null,
    mcnemarPValueVsD9,
    filesLostDiffVsD9,
  };
}

export function detectionRateForSubset(
  evaluations: TraceEvaluation[],
  predicate: (e: TraceEvaluation) => boolean,
): { rate: number; traces: number } {
  const subset = evaluations.filter(predicate);
  if (subset.length === 0) return { rate: 0, traces: 0 };
  return { rate: subset.filter((e) => e.detected).length / subset.length, traces: subset.length };
}

export function alertsForTimeline(alerts: Alert[]): Alert[] {
  return [...alerts].sort((a, b) => a.timeMs - b.timeMs || a.seq - b.seq);
}

export function recoveryFor(
  capable: boolean,
  mechanism: string,
  recoveryPointLossMs: number | null,
): RecoveryModel {
  return { capable, mechanism, recoveryPointLossMs };
}
