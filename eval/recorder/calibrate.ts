/**
 * Fits the synthetic generator to recorded benign telemetry.
 *
 * Calibration only shifts three knobs: object size, inter-arrival time, and
 * benign entropy. It never changes attack labels or detector parameters. When
 * there are no recordings the profile stays at defaults and the scorecard says
 * so instead of implying a fit that does not exist.
 */
import fs from 'node:fs';
import path from 'node:path';
import { CALIBRATION_PATH, RECORDED_TRACES_DIR } from '../config.ts';
import { baseEntropyFor, baseSizeFor } from '../generator/baseline.ts';
import { median } from '../stats.ts';
import { readRecordedTraces } from './recorder.ts';
import { DEFAULT_CALIBRATION, type CalibrationProfile } from '../generator/calibration.ts';

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

export function fitCalibration(): CalibrationProfile {
  const recordings = readRecordedTraces().filter((trace) => trace.groundTruth.attackStartMs === null);
  if (recordings.length === 0) {
    const profile: CalibrationProfile = {
      ...DEFAULT_CALIBRATION,
      generatedAt: new Date().toISOString(),
      recordings: 0,
      applied: false,
      notes: [
        'No recorded benign traces found in eval-data/traces/recorded.',
        'The generator uses its documented synthetic distributions; the scorecard is labelled synthetic.',
      ],
    };
    write(profile);
    return profile;
  }

  const sizeRatios: number[] = [];
  const entropyShifts: number[] = [];
  const gaps: number[] = [];

  for (const trace of recordings) {
    const events = trace.events;
    for (let i = 0; i < events.length; i++) {
      const event = events[i];
      if (event.key) {
        const baseSize = baseSizeFor(event.key);
        if (event.sizeBytes && baseSize > 0) sizeRatios.push(event.sizeBytes / baseSize);
        if (typeof event.entropy === 'number') {
          entropyShifts.push(event.entropy - baseEntropyFor(event.key));
        }
      }
      if (i > 0) gaps.push(Math.max(0, event.timeMs - events[i - 1].timeMs));
    }
  }

  const sizeScale = sizeRatios.length > 0 ? clamp(median(sizeRatios), 0.1, 10) : 1;
  const benignEntropyShift =
    entropyShifts.length > 0 ? clamp(entropyShifts.reduce((a, b) => a + b, 0) / entropyShifts.length, -2, 2) : 0;
  const medianGap = gaps.length > 0 ? median(gaps) : 500;
  // The generator's default spacing is roughly 500 ms; scale toward the recording.
  const interArrivalScale = clamp(medianGap / 500, 0.1, 10);

  const profile: CalibrationProfile = {
    version: 2,
    generatedAt: new Date().toISOString(),
    recordings: recordings.length,
    applied: true,
    sizeScale: Number(sizeScale.toFixed(3)),
    interArrivalScale: Number(interArrivalScale.toFixed(3)),
    benignEntropyShift: Number(benignEntropyShift.toFixed(3)),
    notes: [
      `Fitted to ${recordings.length} recorded benign trace(s) from the shipped simulator.`,
      `Size scale ${sizeScale.toFixed(3)} from ${sizeRatios.length} sized event(s); inter-arrival scale ${interArrivalScale.toFixed(
        3,
      )} from ${gaps.length} gap(s); benign entropy shift ${benignEntropyShift.toFixed(3)} from ${
        entropyShifts.length
      } entropy sample(s).`,
      'Recorded traces come from the local simulator, not production telemetry. They calibrate shape, not realism.',
      'Recorded events carry no object version id, size, or source address on the live stream; size calibration uses only events that include size.',
    ],
  };
  write(profile);
  return profile;
}

function write(profile: CalibrationProfile): void {
  fs.mkdirSync(path.dirname(CALIBRATION_PATH), { recursive: true });
  fs.writeFileSync(CALIBRATION_PATH, JSON.stringify(profile, null, 2), 'utf8');
  fs.mkdirSync(RECORDED_TRACES_DIR, { recursive: true });
}
