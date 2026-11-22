import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { DETECTORS } from '../eval/detectors/index.ts';
import { buildSpecs, generateTrace } from '../eval/generator/generate.ts';

function hashDir(dir: string): string {
  const hash = crypto.createHash('sha256');
  if (!fs.existsSync(dir)) return hash.digest('hex');
  const files = fs.readdirSync(dir).sort();
  for (const file of files) {
    const full = path.join(dir, file);
    if (fs.statSync(full).isFile()) {
      hash.update(file);
      hash.update(fs.readFileSync(full));
    }
  }
  return hash.digest('hex');
}

test('running every detector never mutates the repository data/ folder', () => {
  const dataDir = path.join(process.cwd(), 'data');
  const before = hashDir(dataDir);
  const trace = generateTrace(
    buildSpecs(20261122).find((s) => s.family === 'ransomware')!,
  );
  for (const detector of DETECTORS) {
    detector.run({ events: trace.events, params: {}, seed: 1, bucket: 'finance-prod' });
    detector.recovery({}, trace.events);
  }
  const after = hashDir(dataDir);
  assert.equal(after, before, 'data/ changed during a detector run');
});

test('detectors receive no ground-truth fields in their context', () => {
  const trace = generateTrace(
    buildSpecs(20261122).find((s) => s.family === 'swarm')!,
  );
  const context = {
    events: trace.events,
    params: {},
    seed: 1,
    bucket: 'finance-prod',
  };
  assert.equal('groundTruth' in context, false);
  for (const event of context.events) {
    assert.equal('attack' in event, false);
    assert.equal('fileId' in event, false);
  }
});
