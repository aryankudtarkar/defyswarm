import assert from 'node:assert/strict';
import test from 'node:test';
import { buildSpecs, generateTrace } from '../eval/generator/generate.ts';
import { ADAPTIVE_CANARY_KEYS, BASELINE_FILES } from '../eval/generator/baseline.ts';

test('the same spec produces byte-identical traces', () => {
  const spec = buildSpecs(20261122).find((s) => s.kind.startsWith('ransomware_aes_overwrite_medium'));
  assert.ok(spec);
  const first = generateTrace(spec);
  const second = generateTrace(spec);
  assert.deepEqual(first, second);
});

test('ground truth stays aligned with events and never leaks labels onto events', () => {
  for (const spec of buildSpecs(20261122).slice(0, 30)) {
    const trace = generateTrace(spec);
    assert.equal(trace.groundTruth.eventAttackFlags.length, trace.events.length);
    assert.equal(trace.groundTruth.eventFileIds.length, trace.events.length);
    for (const event of trace.events) {
      assert.equal('attack' in event, false);
      assert.equal('groundTruth' in event, false);
    }
    assert.ok(trace.groundTruth.totalRealFiles >= BASELINE_FILES.length);
  }
});

test('attack traces have an attack start and attacker principals', () => {
  const spec = buildSpecs(20261122).find((s) => s.family === 'swarm');
  assert.ok(spec);
  const trace = generateTrace(spec);
  assert.notEqual(trace.groundTruth.attackStartMs, null);
  assert.ok(trace.groundTruth.attackerPrincipals.length > 0);
  assert.ok(trace.groundTruth.attackFiles.length > 0);
});

test('benign traces have no attack start and no attacker principals', () => {
  const spec = buildSpecs(20261122).find((s) => s.family === 'benign');
  assert.ok(spec);
  const trace = generateTrace(spec);
  assert.equal(trace.groundTruth.attackStartMs, null);
  assert.deepEqual(trace.groundTruth.attackerPrincipals, []);
  assert.equal(trace.groundTruth.attackFiles.length, 0);
});

test('every trace id is unique and split assignment is deterministic', () => {
  const specs = buildSpecs(20261122);
  const traces = specs.map((spec) => generateTrace(spec));
  const ids = traces.map((t) => t.groundTruth.traceId);
  assert.equal(new Set(ids).size, ids.length);
  const second = specs.map((spec) => generateTrace(spec));
  assert.deepEqual(
    traces.map((t) => t.groundTruth.split),
    second.map((t) => t.groundTruth.split),
  );
});

test('adaptive canaries are realistic keys, obvious canaries are not', () => {
  for (const key of ADAPTIVE_CANARY_KEYS) {
    assert.equal(key.toLowerCase().includes('canary'), false, key);
    assert.ok(key.includes('/'), key);
  }
});
