import assert from 'node:assert/strict';
import test from 'node:test';
import {
  bootstrapInterval,
  cliffsDelta,
  effectSizeLabel,
  mcnemarExact,
  median,
  p95,
  pairedBootstrapDiff,
  percentile,
  ruleOfThree,
  wilsonInterval,
} from '../eval/stats.ts';

test('percentile and median use the documented nearest-rank convention', () => {
  assert.equal(percentile([4, 1, 3, 2], 50), 2);
  assert.equal(percentile([1, 2, 3, 4, 5], 50), 3);
  assert.equal(p95(Array.from({ length: 100 }, (_, i) => i + 1)), 95);
  assert.equal(median([]), 0);
});

test('Wilson interval matches a hand-computed value', () => {
  const [lo, hi] = wilsonInterval(8, 10);
  assert.ok(Math.abs(lo - 0.4902) < 0.0002, `lower ${lo}`);
  assert.ok(Math.abs(hi - 0.9433) < 0.0002, `upper ${hi}`);
});

test('Wilson interval is [0,1] for no observations', () => {
  assert.deepEqual(wilsonInterval(0, 0), [0, 1]);
});

test('rule of three gives 3/n upper bound', () => {
  const [lo, hi] = ruleOfThree(300);
  assert.equal(lo, 0);
  assert.ok(Math.abs(hi - 0.01) < 1e-12);
});

test('exact McNemar matches a hand-computed binomial tail', () => {
  // b=10, c=2, n=12: 2 * (C(12,0)+C(12,1)+C(12,2)) / 2^12
  const expected = (2 * (1 + 12 + 66)) / 4096;
  assert.ok(Math.abs(mcnemarExact(10, 2) - expected) < 1e-12);
  assert.equal(mcnemarExact(0, 0), 1);
});

test('bootstrap intervals are deterministic for a fixed seed', () => {
  const values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
  const a = bootstrapInterval(values, median, { seed: 7, iterations: 300 });
  const b = bootstrapInterval(values, median, { seed: 7, iterations: 300 });
  assert.deepEqual(a, b);
});

test('paired bootstrap diff keeps pairing', () => {
  const result = pairedBootstrapDiff([3, 4, 5], [1, 2, 3], median, { seed: 2, iterations: 200 });
  assert.equal(result.diff, 2);
  assert.ok(result.ci[0] <= result.diff && result.diff <= result.ci[1]);
});

test('Cliffs delta and effect-size labels', () => {
  assert.equal(cliffsDelta([4, 5, 6], [1, 2, 3]), 1);
  assert.equal(cliffsDelta([1, 2, 3], [4, 5, 6]), -1);
  assert.equal(effectSizeLabel(0.05), 'negligible');
  assert.equal(effectSizeLabel(0.2), 'small');
  assert.equal(effectSizeLabel(0.4), 'medium');
  assert.equal(effectSizeLabel(0.6), 'large');
});
