import assert from 'node:assert/strict';
import test from 'node:test';
import { Prng, hashString, seededShuffle } from '../eval/prng.ts';

test('same seed produces the same stream', () => {
  const a = new Prng(1234);
  const b = new Prng(1234);
  const first = Array.from({ length: 20 }, () => a.next());
  const second = Array.from({ length: 20 }, () => b.next());
  assert.deepEqual(first, second);
});

test('different seeds diverge', () => {
  const a = new Prng(1);
  const b = new Prng(2);
  assert.notEqual(a.next(), b.next());
});

test('values stay in [0,1)', () => {
  const prng = new Prng('eval');
  for (let i = 0; i < 5000; i++) {
    const value = prng.next();
    assert.ok(value >= 0 && value < 1, `out of range: ${value}`);
  }
});

test('string seeds hash deterministically', () => {
  assert.equal(hashString('abc'), hashString('abc'));
  assert.notEqual(hashString('abc'), hashString('abd'));
});

test('seeded shuffle is a permutation and is reproducible', () => {
  const input = [1, 2, 3, 4, 5, 6, 7, 8];
  const first = seededShuffle(input, 99);
  const second = seededShuffle(input, 99);
  assert.deepEqual(first, second);
  assert.deepEqual([...first].sort((a, b) => a - b), input);
});
