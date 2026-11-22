/**
 * Evaluation Lab configuration.
 *
 * This module is intentionally free of product imports. The lab is off unless
 * EVAL_LAB=1. DEMO_LOCK=1 blocks every write path (live runs and the UI run
 * button) so a pitch demo can never be disturbed by an evaluation run.
 */
import path from 'node:path';

export const EVAL_LAB = process.env.EVAL_LAB === '1';
export const DEMO_LOCK = process.env.DEMO_LOCK === '1';

export const REPO_ROOT = path.resolve(process.cwd());
export const EVAL_DATA_DIR = path.join(REPO_ROOT, 'eval-data');
export const TRACES_DIR = path.join(EVAL_DATA_DIR, 'traces');
export const GENERATED_TRACES_DIR = path.join(TRACES_DIR, 'generated');
export const RECORDED_TRACES_DIR = path.join(TRACES_DIR, 'recorded');
export const RESULTS_DIR = path.join(EVAL_DATA_DIR, 'results');
export const MANIFEST_PATH = path.join(TRACES_DIR, 'manifest.json');
export const CALIBRATION_PATH = path.join(EVAL_DATA_DIR, 'calibration.json');
export const LIVE_VALIDATION_PATH = path.join(EVAL_DATA_DIR, 'live-validation.json');
export const LEDGER_PATH = path.join(EVAL_DATA_DIR, 'ledger.json');

export const DEFAULT_GENERATION_SEED = 20261122;
export const DEFAULT_RUN_SEED = 424242;
export const DEFAULT_FPR_BUDGET = 0.01;
export const DEFAULT_CONTAINMENT_LATENCY_MS = 1000;
export const FAST_TRACES_PER_FAMILY = 20;
export const FULL_TRACE_CHUNK_SIZE = 8;
export const FAST_TRACE_CHUNK_SIZE = 4;

export const FAMILIES = ['benign', 'ransomware', 'swarm', 'mixed'] as const;
export type Family = (typeof FAMILIES)[number];

export const DETECTOR_IDS = [
  'D0',
  'D1',
  'D2',
  'D3',
  'D4',
  'D5',
  'D6',
  'D7',
  'D8',
  'D9',
  'D9a',
  'D9b',
  'D9c',
  'D9d',
  'D9e',
  'D9f',
] as const;
export type DetectorId = (typeof DETECTOR_IDS)[number];

export const ATTACK_SPEEDS = ['slow', 'medium', 'fast'] as const;
export type AttackSpeed = (typeof ATTACK_SPEEDS)[number];

export const ATTACK_METHODS = [
  'aes_overwrite',
  'rename_locked',
  'delete_rewrite',
  'ssec_copy',
  'external_kms',
] as const;
export type AttackMethod = (typeof ATTACK_METHODS)[number];

export const SABOTAGE_MODES = ['none', 'suspend_versioning', 'purge_versions', 'lifecycle_1d'] as const;
export type SabotageMode = (typeof SABOTAGE_MODES)[number];

export const RECON_MODES = ['naive', 'canary_aware'] as const;
export type ReconMode = (typeof RECON_MODES)[number];
