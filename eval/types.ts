import type {
  AttackMethod,
  AttackSpeed,
  DetectorId,
  Family,
  ReconMode,
  SabotageMode,
} from './config.ts';

/**
 * Telemetry only. A detector may read every field on this interface. There is
 * deliberately no attack label, no ground-truth file list, and no scenario
 * parameter block here.
 */
export type Operation =
  | 'PutObject'
  | 'CopyObject'
  | 'GetObject'
  | 'DeleteObject'
  | 'DeleteObjectVersion'
  | 'CompleteMultipartUpload'
  | 'PutBucketVersioning'
  | 'PutBucketLifecycleConfiguration'
  | 'PutObjectLockConfiguration'
  | 'PutBucketLogging';

export type EventChannel = 'api' | 'sync' | 'console';

export interface Event {
  /** Monotonic sequence within the trace, starting at 0. */
  seq: number;
  /** Milliseconds since trace start. */
  timeMs: number;
  principal: string;
  operation: Operation;
  plane: 'data' | 'control';
  bucket: string;
  key?: string;
  sourceKey?: string;
  versionId?: string;
  sizeBytes?: number;
  magicValid?: boolean;
  magicDetected?: string;
  entropy?: number;
  prevEntropy?: number;
  sseAlgorithm?: string;
  kmsKeyId?: string;
  sourceAddress?: string;
  /** Ingestion path. Sync-client detectors only see `sync`. */
  channel: EventChannel;
  isCanary?: boolean;
  versioningTargetStatus?: 'Suspended' | 'Enabled';
  lifecycleExpiryDays?: number;
  versionIdPurged?: string;
  httpStatus: number;
}

/**
 * Ground truth is a separate object. It is never passed to a detector. The
 * runner keeps it beside the event stream and uses it only when scoring.
 */
export interface GroundTruth {
  traceId: string;
  family: Family;
  kind: string;
  seed: number;
  split: 'tuning' | 'heldout';
  bucket: string;
  durationMs: number;
  /** null for benign traces. */
  attackStartMs: number | null;
  attackerPrincipals: string[];
  /** One boolean per event, aligned by seq. */
  eventAttackFlags: boolean[];
  /** One file id (or null for control/recon events) per event, aligned by seq. */
  eventFileIds: Array<string | null>;
  /** Distinct real files that the attack would encrypt/destroy. */
  attackFiles: string[];
  totalRealFiles: number;
  benignEventCount: number;
  scenario: {
    speed?: AttackSpeed;
    principals?: number;
    method?: AttackMethod;
    recon?: ReconMode;
    sabotage?: SabotageMode;
    attackToNoiseRatio?: number;
    benignKind?: string;
    channel?: EventChannel;
  };
  obviousCanaryKeys: string[];
  adaptiveCanaryKeys: string[];
  notes?: string;
}

export interface TraceRecord {
  groundTruth: GroundTruth;
  events: Event[];
}

export interface TraceManifestEntry {
  traceId: string;
  family: Family;
  kind: string;
  seed: number;
  split: 'tuning' | 'heldout';
  path: string;
  eventCount: number;
  sha256: string;
}

export interface TraceManifest {
  generatedAt: string;
  generationSeed: number;
  generatorVersion: string;
  totalTraces: number;
  tuningTraces: number;
  heldoutTraces: number;
  families: Record<Family, number>;
  traces: TraceManifestEntry[];
}

export interface Alert {
  seq: number;
  timeMs: number;
  detectorId: DetectorId;
  principal: string;
  reason: string;
  /** True when the detector asks the containment layer to block the principal. */
  containmentRequested: boolean;
}

export interface DetectorOutput {
  alerts: Alert[];
  /** Extra diagnostics for the drill-down view. */
  notes?: string[];
}

export interface RecoveryModel {
  capable: boolean;
  /** Human-readable recovery mechanism. */
  mechanism: string;
  /** Recovery-point loss in ms, or null when not applicable. */
  recoveryPointLossMs: number | null;
}

export interface DetectorRunContext {
  /** Label-stripped events. This is the only trace data a detector receives. */
  events: Event[];
  /** Detector parameters chosen by tuning (or shipped defaults for D9). */
  params: Record<string, unknown>;
  /** Deterministic seed for any detector-side randomness. */
  seed: number;
  bucket: string;
}

export interface Detector {
  id: DetectorId;
  name: string;
  /** Real-world approach this reference implementation stands for. */
  models: string;
  run(context: DetectorRunContext): DetectorOutput;
  recovery(params: Record<string, unknown>, events: Event[]): RecoveryModel;
}

export interface TuningPoint {
  params: Record<string, unknown>;
  detectionRate: number;
  falsePositiveRate: number;
  traces: number;
  selected: boolean;
}

export interface TuningResult {
  detectorId: DetectorId;
  grid: TuningPoint[];
  selected: Record<string, unknown>;
  fprBudget: number;
  notes?: string;
}

export interface TraceEvaluation {
  traceId: string;
  family: Family;
  detectorId: DetectorId;
  detected: boolean;
  timeToDetectMs: number | null;
  timeToContainMs: number | null;
  filesLost: number;
  filesLostPct: number;
  recoverable: boolean;
  recoveryPointLossMs: number | null;
  falsePositive: boolean;
  alertPrecision: number | null;
  alerts: Alert[];
  /** For the drill-down timeline only. */
  attackStartMs: number | null;
  attackFileEvents: Array<{ timeMs: number; fileId: string; operation: string; key?: string }>;
}

export interface DetectorSummary {
  detectorId: DetectorId;
  detectorName: string;
  traces: number;
  attackTraces: number;
  benignTraces: number;
  detectionRate: number;
  detectionCi: [number, number];
  falsePositiveRate: number;
  falsePositiveCi: [number, number];
  medianTimeToDetectMs: number | null;
  p95TimeToDetectMs: number | null;
  medianTimeToContainMs: number | null;
  medianFilesLost: number;
  worstFilesLost: number;
  recoverablePct: number;
  medianRecoveryPointLossMs: number | null;
  alertPrecision: number | null;
  mcnemarPValueVsD9: number | null;
  filesLostDiffVsD9: { medianDiff: number; ci: [number, number] } | null;
}

export interface FamilyScorecard {
  family: Family;
  summaries: DetectorSummary[];
}

export interface AblationRow {
  detectorId: DetectorId;
  component: string;
  detectionRate: number;
  falsePositiveRate: number;
  medianFilesLost: number;
  deltaDetectionVsD9: number;
  deltaFalsePositiveVsD9: number;
}

export interface SensitivityRow {
  latencyMs: number;
  detectorId: DetectorId;
  medianFilesLost: number;
  detectionRate: number;
}

export interface DoseResponse {
  filesLostVsSpeed: Array<{ speed: AttackSpeed; detectorId: DetectorId; medianFilesLost: number }>;
  detectionVsPrincipals: Array<{
    principals: number;
    detectorId: DetectorId;
    detectionRate: number;
    traces: number;
  }>;
  detectionVsAttackToNoise: Array<{
    ratio: number;
    detectorId: DetectorId;
    detectionRate: number;
    traces: number;
  }>;
  fprVsThreshold: Array<{
    detectorId: DetectorId;
    thresholdName: string;
    threshold: number;
    falsePositiveRate: number;
  }>;
}

export interface EvalEnvironment {
  platform: string;
  node: string;
  cpus: number;
  totalMemoryMb: number;
  productVersion: string;
  detectorImplementation: string;
  path: 'replay' | 'live';
}

export interface EvalResults {
  runId: string;
  generatedAt: string;
  mode: 'fast' | 'full';
  seed: number;
  generationSeed: number;
  tracesTotal: number;
  tracesUsed: number;
  tuningTraces: number;
  heldoutTraces: number;
  containmentLatencyMs: number;
  containmentLatencySource: string;
  environment: EvalEnvironment;
  scorecard: FamilyScorecard[];
  overall: DetectorSummary[];
  ablations: AblationRow[];
  sensitivity: SensitivityRow[];
  doseResponse: DoseResponse;
  tuning: TuningResult[];
  perTrace: TraceEvaluation[];
  limitations: string[];
  determinismHash: string;
}
