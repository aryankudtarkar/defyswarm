import { Prng } from './prng.ts';

export function mean(values: number[]): number {
  if (values.length === 0) return 0;
  return values.reduce((a, b) => a + b, 0) / values.length;
}

export function percentile(values: number[], p: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx];
}

export function median(values: number[]): number {
  return percentile(values, 50);
}

export function p95(values: number[]): number {
  return percentile(values, 95);
}

/**
 * Wilson score interval for a binomial proportion at 95% confidence.
 * Hand-checked in tests/stats.test.ts.
 */
export function wilsonInterval(successes: number, n: number, z = 1.959963984540054): [number, number] {
  if (n <= 0) return [0, 1];
  const phat = successes / n;
  const denominator = 1 + (z * z) / n;
  const centre = (phat + (z * z) / (2 * n)) / denominator;
  const margin =
    (z * Math.sqrt((phat * (1 - phat)) / n + (z * z) / (4 * n * n))) / denominator;
  return [Math.max(0, centre - margin), Math.min(1, centre + margin)];
}

/**
 * Rule of three: with zero observed events in n trials, the 95% upper bound on
 * the true rate is approximately 3/n. Returns [0, upper].
 */
export function ruleOfThree(n: number): [number, number] {
  if (n <= 0) return [0, 1];
  return [0, Math.min(1, 3 / n)];
}

/** Percentile bootstrap interval for a statistic (default: median). */
export function bootstrapInterval(
  values: number[],
  statistic: (sample: number[]) => number = median,
  options: { seed?: number; iterations?: number; confidence?: number } = {},
): [number, number] {
  if (values.length === 0) return [0, 0];
  const seed = options.seed ?? 1;
  const iterations = options.iterations ?? 2000;
  const confidence = options.confidence ?? 0.95;
  const prng = new Prng(seed);
  const estimates: number[] = [];
  for (let i = 0; i < iterations; i++) {
    const sample: number[] = [];
    for (let j = 0; j < values.length; j++) {
      sample.push(values[Math.floor(prng.next() * values.length)]);
    }
    estimates.push(statistic(sample));
  }
  const alpha = (1 - confidence) / 2;
  return [percentile(estimates, alpha * 100), percentile(estimates, (1 - alpha) * 100)];
}

function binomialCoefficient(n: number, k: number): number {
  if (k < 0 || k > n) return 0;
  const m = Math.min(k, n - k);
  let result = 1;
  for (let i = 1; i <= m; i++) {
    result = (result * (n - m + i)) / i;
  }
  return result;
}

/**
 * Exact two-sided McNemar test for paired binary outcomes.
 * b = A positive / B negative; c = A negative / B positive.
 * Under H0, b ~ Binomial(b+c, 0.5).
 */
export function mcnemarExact(b: number, c: number): number {
  const n = b + c;
  if (n === 0) return 1;
  const k = Math.min(b, c);
  let tail = 0;
  for (let i = 0; i <= k; i++) {
    tail += binomialCoefficient(n, i) * Math.pow(0.5, n);
  }
  return Math.min(1, 2 * tail);
}

/** Paired bootstrap for the difference in a statistic between two paired arms. */
export function pairedBootstrapDiff(
  armA: number[],
  armB: number[],
  statistic: (sample: number[]) => number = median,
  options: { seed?: number; iterations?: number; confidence?: number } = {},
): { diff: number; ci: [number, number] } {
  if (armA.length !== armB.length) {
    throw new Error('Paired bootstrap requires equal-length arms.');
  }
  if (armA.length === 0) return { diff: 0, ci: [0, 0] };
  const seed = options.seed ?? 1;
  const iterations = options.iterations ?? 2000;
  const confidence = options.confidence ?? 0.95;
  const prng = new Prng(seed);
  const diffs: number[] = [];
  for (let i = 0; i < iterations; i++) {
    const sampleA: number[] = [];
    const sampleB: number[] = [];
    for (let j = 0; j < armA.length; j++) {
      const idx = Math.floor(prng.next() * armA.length);
      sampleA.push(armA[idx]);
      sampleB.push(armB[idx]);
    }
    diffs.push(statistic(sampleA) - statistic(sampleB));
  }
  const alpha = (1 - confidence) / 2;
  return {
    diff: statistic(armA) - statistic(armB),
    ci: [percentile(diffs, alpha * 100), percentile(diffs, (1 - alpha) * 100)],
  };
}

/**
 * Cliff's delta: P(X>Y) - P(X<Y). Range [-1, 1].
 * |d| < 0.147 negligible, < 0.33 small, < 0.474 medium, otherwise large.
 */
export function cliffsDelta(x: number[], y: number[]): number {
  if (x.length === 0 || y.length === 0) return 0;
  let greater = 0;
  let less = 0;
  for (const a of x) {
    for (const b of y) {
      if (a > b) greater++;
      else if (a < b) less++;
    }
  }
  return (greater - less) / (x.length * y.length);
}

export function effectSizeLabel(delta: number): 'negligible' | 'small' | 'medium' | 'large' {
  const abs = Math.abs(delta);
  if (abs < 0.147) return 'negligible';
  if (abs < 0.33) return 'small';
  if (abs < 0.474) return 'medium';
  return 'large';
}
