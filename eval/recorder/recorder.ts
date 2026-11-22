/**
 * Records live product telemetry from the shipped simulator.
 *
 * Known stream gap: /ws/live emits TelemetryEvent objects without a scenario
 * tag, object version id, size, or source address. The recorder labels runs
 * from CLI metadata (the scenario it just started) instead of pretending the
 * stream carries labels. See docs/eval/TRACE_PROTOCOL.md for the smallest
 * additive change that would close this gap.
 */
import fs from 'node:fs';
import path from 'node:path';
import WebSocket from 'ws';
import type { TelemetryEvent } from '../../src/shared/types.ts';
import { RECORDED_TRACES_DIR } from '../config.ts';
import type { Event, GroundTruth, TraceRecord } from '../types.ts';
import { ADAPTIVE_CANARY_KEYS, OBVIOUS_CANARY_KEYS } from '../generator/baseline.ts';
import { api, startProductServer } from '../live/productServer.ts';

const SCENARIOS = [
  'benign_bulk',
  'benign_compressed',
  'benign_rename',
  'benign_backup_sync',
  'standard_ransomware',
  'stealth_ai_swarm',
] as const;

type Scenario = (typeof SCENARIOS)[number];

function toEvalEvent(event: TelemetryEvent, seq: number, startMs: number): Event {
  return {
    seq,
    timeMs: Math.max(0, event.serverTimestampMs - startMs),
    principal: event.principalId,
    operation: event.apiOp as Event['operation'],
    plane: event.plane,
    bucket: event.bucket,
    key: event.key,
    sizeBytes: undefined,
    magicValid: event.magicValid,
    magicDetected: event.magicDetected,
    entropy: event.entropy,
    prevEntropy: event.prevEntropy,
    sseAlgorithm: event.sseAlgorithm,
    kmsKeyId: event.kmsKeyId,
    channel: 'api',
    isCanary: event.isCanary,
    httpStatus: event.httpStatus,
  };
}

async function waitForCompletion(baseUrl: string, timeoutMs = 90_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let sawRunning = false;
  while (Date.now() < deadline) {
    const state = await api<{ simulator: { running: boolean; completedAt?: string } }>(
      baseUrl,
      '/api/bootstrap',
    );
    if (state.simulator.running) sawRunning = true;
    if (sawRunning && !state.simulator.running) return;
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  throw new Error('Timed out waiting for the simulator to finish.');
}

export interface RecordOptions {
  scenarios?: string[];
}

export async function recordTraces(options: RecordOptions = {}): Promise<number> {
  const scenarios = (options.scenarios?.length ? options.scenarios : SCENARIOS).filter((s): s is Scenario =>
    (SCENARIOS as readonly string[]).includes(s),
  );
  if (scenarios.length === 0) throw new Error('No valid scenarios requested.');

  fs.mkdirSync(RECORDED_TRACES_DIR, { recursive: true });
  const server = await startProductServer();
  let recorded = 0;
  try {
    for (const scenario of scenarios) {
      await api(server.baseUrl, '/api/simulator/reset', { method: 'POST', body: '{}' });
      const captured: TelemetryEvent[] = [];
      const socket = new WebSocket(`ws://127.0.0.1:${server.port}/ws/live`);
      await new Promise<void>((resolve, reject) => {
        socket.once('open', () => resolve());
        socket.once('error', reject);
      });
      socket.on('message', (raw) => {
        try {
          const message = JSON.parse(String(raw)) as { type: string; payload: unknown };
          if (message.type === 'event:ingested') captured.push(message.payload as TelemetryEvent);
        } catch {
          // Ignore non-JSON frames.
        }
      });

      const startedAt = Date.now();
      await api(server.baseUrl, '/api/simulator/run', {
        method: 'POST',
        body: JSON.stringify({ scenario, bucket: 'finance-prod' }),
      });
      await waitForCompletion(server.baseUrl);
      await new Promise((resolve) => setTimeout(resolve, 250));
      socket.close();

      const startMs = captured.length > 0 ? captured[0].serverTimestampMs : startedAt;
      const events = captured.map((event, index) => toEvalEvent(event, index, startMs));
      if (events.length === 0) {
        console.warn(`Scenario ${scenario} produced no telemetry; skipped.`);
        continue;
      }

      const isAttack = !scenario.startsWith('benign_');
      const attackStartMs = isAttack
        ? Math.min(
            ...events
              .filter(
                (event) =>
                  event.principal.startsWith('swarm-node') ||
                  event.principal === 'svc-billing-etl' ||
                  event.isCanary === true,
              )
              .map((event) => event.timeMs),
          )
        : null;
      const attackStart = Number.isFinite(attackStartMs) ? attackStartMs : isAttack ? 0 : null;
      const attackerPrincipals = isAttack
        ? Array.from(
            new Set(
              events
                .filter(
                  (event) =>
                    event.principal.startsWith('swarm-node') ||
                    event.principal === 'svc-billing-etl',
                )
                .map((event) => event.principal),
            ),
          )
        : [];
      const attackEvents = isAttack
        ? events.filter(
            (event) =>
              attackStart !== null &&
              event.timeMs >= attackStart &&
              (attackerPrincipals.includes(event.principal) || event.isCanary === true),
          )
        : [];
      const attackSet = new Set(attackEvents);
      const eventAttackFlags = events.map((event) => attackSet.has(event));
      const eventFileIds = events.map((event, index) =>
        eventAttackFlags[index] ? event.key ?? null : null,
      );
      const attackFiles = Array.from(
        new Set(eventFileIds.filter((v): v is string => Boolean(v))),
      ).sort();
      const realKeys = new Set(events.map((e) => e.key).filter((v): v is string => Boolean(v)));

      const groundTruth: GroundTruth = {
        traceId: `rec-${scenario}-${startedAt}`,
        family: isAttack ? (scenario === 'stealth_ai_swarm' ? 'swarm' : 'ransomware') : 'benign',
        kind: `recorded_${scenario}`,
        seed: startedAt,
        split: 'heldout',
        bucket: 'finance-prod',
        durationMs: Math.max(1000, ...events.map((e) => e.timeMs)) + 1000,
        attackStartMs: attackStart,
        attackerPrincipals,
        eventAttackFlags,
        eventFileIds,
        attackFiles,
        totalRealFiles: Math.max(1, realKeys.size),
        benignEventCount: events.length - attackEvents.length,
        scenario: { benignKind: isAttack ? undefined : scenario, channel: 'api' },
        obviousCanaryKeys: OBVIOUS_CANARY_KEYS,
        adaptiveCanaryKeys: ADAPTIVE_CANARY_KEYS,
        notes: `Recorded from the shipped simulator scenario ${scenario}. Labels come from CLI metadata because the live stream carries no scenario tag.`,
      };
      const record: TraceRecord = { groundTruth, events };
      const file = path.join(RECORDED_TRACES_DIR, `${groundTruth.traceId}.jsonl`);
      const lines = [
        JSON.stringify({ type: 'meta', groundTruth, recordedFrom: 'shipped-simulator' }),
        ...events.map((event) => JSON.stringify({ type: 'event', event })),
      ];
      fs.writeFileSync(file, `${lines.join('\n')}\n`, 'utf8');
      recorded++;
      console.log(`Recorded ${scenario}: ${events.length} events -> ${path.basename(file)}`);
    }

    fs.writeFileSync(
      path.join(RECORDED_TRACES_DIR, 'manifest.json'),
      JSON.stringify(
        {
          recordedAt: new Date().toISOString(),
          source: 'shipped-simulator',
          scenarios,
          recordings: recorded,
        },
        null,
        2,
      ),
      'utf8',
    );
  } finally {
    await server.stop();
  }
  return recorded;
}

export function readRecordedTraces(): TraceRecord[] {
  if (!fs.existsSync(RECORDED_TRACES_DIR)) return [];
  const records: TraceRecord[] = [];
  for (const entry of fs.readdirSync(RECORDED_TRACES_DIR)) {
    if (!entry.endsWith('.jsonl')) continue;
    const lines = fs
      .readFileSync(path.join(RECORDED_TRACES_DIR, entry), 'utf8')
      .split('\n')
      .filter(Boolean);
    const meta = JSON.parse(lines[0]) as { groundTruth: GroundTruth };
    const events = lines.slice(1).map((line) => (JSON.parse(line) as { event: Event }).event);
    records.push({ groundTruth: meta.groundTruth, events });
  }
  return records;
}
