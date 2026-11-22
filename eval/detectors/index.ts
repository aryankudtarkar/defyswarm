import type { Detector } from '../types.ts';
import { ALLOWLISTED_PRINCIPALS, OBVIOUS_CANARY_KEYS } from '../generator/baseline.ts';
import { d0, d1, d2, d3, d4, d5, d6, d7, d8 } from './baselines.ts';
import { d9, d9a, d9b, d9c, d9d, d9e, d9f } from './d9.ts';

export const DETECTORS: Detector[] = [
  d0,
  d1,
  d2,
  d3,
  d4,
  d5,
  d6,
  d7,
  d8,
  d9,
  d9a,
  d9b,
  d9c,
  d9d,
  d9e,
  d9f,
];

export const BASELINE_DETECTORS: Detector[] = [d0, d1, d2, d3, d4, d5, d6, d7, d8];
export const D9_ABLATIONS: Detector[] = [d9a, d9b, d9c, d9d, d9e, d9f];

export function detectorById(id: string): Detector {
  const found = DETECTORS.find((d) => d.id === id);
  if (!found) throw new Error(`Unknown detector ${id}`);
  return found;
}

export interface TuningGrid {
  detectorId: string;
  points: Array<Record<string, unknown>>;
}

const allowlist = ALLOWLISTED_PRINCIPALS;

export const TUNING_GRIDS: TuningGrid[] = [
  { detectorId: 'D0', points: [{}] },
  {
    detectorId: 'D1',
    points: [0.25, 1, 4, 12, 24].map((intervalHours) => ({ intervalHours })),
  },
  {
    detectorId: 'D2',
    points: cross({
      z: [3, 3.5, 4],
      minHistory: [5, 10],
      windowSeconds: [15],
      minEntropyDelta: [1.0, 1.5],
      minRate: [25, 50],
      allowlist: [allowlist],
    }),
  },
  {
    detectorId: 'D3',
    points: cross({
      batchMinutes: [1, 5, 15],
      suspiciousThreshold: [3, 5, 10, 20],
      writeThreshold: [100, 500, 2000],
      allowlist: [allowlist],
    }),
  },
  {
    detectorId: 'D4',
    points: [7.0, 7.5, 7.8, 7.9, 7.95].map((entropyThreshold) => ({ entropyThreshold })),
  },
  {
    detectorId: 'D5',
    points: [0.5, 1.0, 1.5, 2.0].map((entropyDeltaThreshold) => ({
      entropyDeltaThreshold,
    })),
  },
  {
    detectorId: 'D6',
    points: [
      { extensions: ['.locked'] },
      { extensions: ['.locked', '.encrypted'] },
      { extensions: ['.locked', '.encrypted', '.crypt', '.enc'] },
    ],
  },
  {
    detectorId: 'D7',
    points: [{ names: OBVIOUS_CANARY_KEYS, allowlist }],
  },
  {
    detectorId: 'D8',
    points: [7.0, 7.2, 7.4, 7.6, 7.8, 7.9, 7.95].map((entropyThreshold) => ({
      entropyThreshold,
    })),
  },
  { detectorId: 'D9', points: [{}] },
  { detectorId: 'D9a', points: [{}] },
  { detectorId: 'D9b', points: [{}] },
  { detectorId: 'D9c', points: [{}] },
  { detectorId: 'D9d', points: [{}] },
  { detectorId: 'D9e', points: [{}] },
  { detectorId: 'D9f', points: [{}] },
];

function cross(grid: Record<string, unknown[]>): Array<Record<string, unknown>> {
  let combinations: Array<Record<string, unknown>> = [{}];
  for (const [key, values] of Object.entries(grid)) {
    const next: Array<Record<string, unknown>> = [];
    for (const combination of combinations) {
      for (const value of values) {
        next.push({ ...combination, [key]: value });
      }
    }
    combinations = next;
  }
  return combinations;
}

export function tuningGridFor(detectorId: string): Array<Record<string, unknown>> {
  return TUNING_GRIDS.find((g) => g.detectorId === detectorId)?.points ?? [{}];
}
