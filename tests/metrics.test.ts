import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluateTrace, summarize } from '../eval/metrics.ts';
import type { Alert, Event, GroundTruth, TraceRecord } from '../eval/types.ts';

function event(seq: number, timeMs: number, key: string, principal = 'attacker'): Event {
  return {
    seq,
    timeMs,
    principal,
    operation: 'PutObject',
    plane: 'data',
    bucket: 'finance-prod',
    key,
    channel: 'api',
    httpStatus: 200,
  };
}

function trace(): TraceRecord {
  const events = [event(0, 1000, 'a'), event(1, 1200, 'b'), event(2, 1600, 'c')];
  const groundTruth: GroundTruth = {
    traceId: 'tr-test',
    family: 'ransomware',
    kind: 'test',
    seed: 1,
    split: 'heldout',
    bucket: 'finance-prod',
    durationMs: 2600,
    attackStartMs: 1000,
    attackerPrincipals: ['attacker'],
    eventAttackFlags: [true, true, true],
    eventFileIds: ['a', 'b', 'c'],
    attackFiles: ['a', 'b', 'c'],
    totalRealFiles: 3,
    benignEventCount: 0,
    scenario: {},
    obviousCanaryKeys: [],
    adaptiveCanaryKeys: [],
  };
  return { groundTruth, events };
}

const detectionAlert: Alert = {
  seq: 1,
  timeMs: 1300,
  detectorId: 'D9',
  principal: 'attacker',
  reason: 'test',
  containmentRequested: true,
};

test('files lost counts distinct files touched before detection + latency', () => {
  const evaluation = evaluateTrace(
    trace(),
    'D9',
    { alerts: [detectionAlert] },
    {
      containmentLatencyMs: 500,
      recovery: { capable: true, mechanism: 'vault', recoveryPointLossMs: 42 },
    },
  );
  // Detection at 1300 + 500 = 1800. Files a (1000) and b (1200) are lost, c (1600) too.
  assert.equal(evaluation.detected, true);
  assert.equal(evaluation.timeToDetectMs, 300);
  assert.equal(evaluation.timeToContainMs, 800);
  assert.equal(evaluation.filesLost, 3);
  assert.equal(evaluation.filesLostPct, 100);
  assert.equal(evaluation.falsePositive, false);
  assert.equal(evaluation.alertPrecision, 1);
});

test('a later block preserves files', () => {
  const late = { ...detectionAlert, timeMs: 1000 };
  const evaluation = evaluateTrace(trace(), 'D9', { alerts: [late] }, {
    containmentLatencyMs: 0,
    recovery: { capable: true, mechanism: 'vault', recoveryPointLossMs: 42 },
  });
  // Block at 1000; only a is at or before the block.
  assert.equal(evaluation.filesLost, 1);
});

test('benign trace alerts are false positives', () => {
  const record = trace();
  record.groundTruth = {
    ...record.groundTruth,
    traceId: 'tr-benign',
    family: 'benign',
    attackStartMs: null,
    attackerPrincipals: [],
    eventAttackFlags: [false, false, false],
    eventFileIds: [null, null, null],
    attackFiles: [],
  };
  const evaluation = evaluateTrace(
    record,
    'D9',
    { alerts: [{ ...detectionAlert, timeMs: 500 }] },
    { containmentLatencyMs: 0, recovery: { capable: false, mechanism: 'none', recoveryPointLossMs: null } },
  );
  assert.equal(evaluation.detected, false);
  assert.equal(evaluation.falsePositive, true);
  assert.equal(evaluation.filesLost, 0);
});

test('summarize reports detection and FP rates with Wilson intervals', () => {
  const record = trace();
  const detection = evaluateTrace(record, 'D9', { alerts: [detectionAlert] }, {
    containmentLatencyMs: 500,
    recovery: { capable: true, mechanism: 'vault', recoveryPointLossMs: 42 },
  });
  const summary = summarize({
    evaluations: [detection],
    traces: [record],
    detectorId: 'D9',
    detectorName: 'DefySwarm full',
    family: 'ransomware',
    seed: 1,
  });
  assert.equal(summary.detectionRate, 1);
  assert.equal(summary.falsePositiveRate, 0);
  assert.equal(summary.traces, 1);
  assert.equal(summary.attackTraces, 1);
  assert.equal(summary.medianFilesLost, 3);
});
