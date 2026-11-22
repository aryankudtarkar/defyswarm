import fs from 'node:fs';
import { CALIBRATION_PATH } from '../config.ts';

export interface CalibrationProfile {
  version: number;
  generatedAt: string;
  recordings: number;
  applied: boolean;
  sizeScale: number;
  interArrivalScale: number;
  benignEntropyShift: number;
  notes: string[];
}

export const DEFAULT_CALIBRATION: CalibrationProfile = {
  version: 1,
  generatedAt: '',
  recordings: 0,
  applied: false,
  sizeScale: 1,
  interArrivalScale: 1,
  benignEntropyShift: 0,
  notes: ['No recorded traces found; generator uses its documented synthetic distributions.'],
};

export function loadCalibrationProfile(): CalibrationProfile {
  try {
    if (!fs.existsSync(CALIBRATION_PATH)) return { ...DEFAULT_CALIBRATION };
    const parsed = JSON.parse(fs.readFileSync(CALIBRATION_PATH, 'utf8')) as Partial<CalibrationProfile>;
    return {
      ...DEFAULT_CALIBRATION,
      ...parsed,
      notes: Array.isArray(parsed.notes) ? parsed.notes : DEFAULT_CALIBRATION.notes,
    };
  } catch {
    return { ...DEFAULT_CALIBRATION };
  }
}
