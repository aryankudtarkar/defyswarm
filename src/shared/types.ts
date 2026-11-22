export type Role = 'viewer' | 'operator' | 'admin';

export type EnforcementMode = 'active' | 'dry-run';

export type SensitivityTier = 'critical' | 'sandbox';

export type PrincipalType = 'service_account' | 'assumed_role' | 'human_admin';

export type PrincipalStatus = 'ACTIVE' | 'WATCHLIST' | 'PENDING_APPROVAL' | 'REVOKED';

export type SignalType =
  | 'canary_read'
  | 'canary_write'
  | 'versioning_suspend'
  | 'version_purge'
  | 'lifecycle_expiry'
  | 'object_lock_tamper'
  | 'audit_log_tamper'
  | 'entropy_delta'
  | 'magic_header_lost'
  | 'rename_burst'
  | 'ssec_abuse'
  | 'untrusted_kms'
  | 'swarm_correlation';

export interface BucketConfig {
  name: string;
  tags: Record<string, string>;
  vault: string;
  versioningEnabled: boolean;
  objectLockEnabled: boolean;
  auditLoggingEnabled: boolean;
  adapter: 'local' | 'minio';
  objectCount: number;
  canaryCount: number;
  lastHardenedAt?: string;
}

export interface AutoHardenCheck {
  id: string;
  label: string;
  passed: boolean;
  detail: string;
}

export interface AutoHardenResult {
  bucket: string;
  timestamp: string;
  allPassed: boolean;
  checks: AutoHardenCheck[];
}

export interface PrincipalState {
  id: string;
  label: string;
  type: PrincipalType;
  status: PrincipalStatus;
  riskScore: number;
  allowlisted: boolean;
  quarantinePolicyAttached: boolean;
  revokedAt?: string;
  first403At?: string;
  lastSeenAt?: string;
  triggeredSignals: SignalType[];
}

export interface TelemetryEvent {
  id: string;
  timestamp: string;
  serverTimestampMs: number;
  plane: 'data' | 'control';
  apiOp: string;
  bucket: string;
  key?: string;
  principalId: string;
  httpStatus: number;
  entropy?: number;
  prevEntropy?: number;
  deltaEntropy?: number;
  magicValid?: boolean;
  magicDetected?: string;
  sseAlgorithm?: string;
  kmsKeyId?: string;
  isCanary?: boolean;
  allowlisted?: boolean;
  selfLoopIgnored?: boolean;
  riskDelta: number;
  bucketRiskScore: number;
  principalRiskScore: number;
  signals: SignalType[];
  source?: EventSource;
  note?: string;
}

export interface IncidentTimelineEntry {
  timestamp: string;
  label: string;
  detail: string;
  severity: 'info' | 'warning' | 'critical' | 'success';
}

export interface AffectedObjectRecord {
  key: string;
  bucket: string;
  artifactType: 'encrypted_overwrite' | 'locked_rename' | 'delete_marker' | 'ssec_copy' | 'canary_tamper';
  preAttackSha256?: string;
  cleanVersionId?: string;
  replicationLagMs: number;
  restored?: boolean;
  verifiedSha256Match?: boolean;
}

export interface RestorePreview {
  incidentId: string;
  bucket: string;
  allPrincipalsContained: boolean;
  artifactsToRemove: string[];
  objectsToRestore: Array<{
    key: string;
    cleanVersionId: string;
    preAttackSha256: string;
    dataLossWindowMs: number;
    recoverable: boolean;
  }>;
  unrecoverableCount: number;
  maxDataLossWindowMs: number;
}

export interface RestoreReport {
  restoredAt: string;
  durationMs: number;
  filesRestored: number;
  artifactsRemoved: number;
  filesUnrecoverable: number;
  verifiedMatchCount: number;
  restoreAccuracyPct: number;
  maxDataLossWindowMs: number;
  perObjectResults: Array<{
    key: string;
    expectedSha256: string;
    restoredSha256: string;
    matched: boolean;
    dataLossWindowMs: number;
  }>;
}

export interface IncidentRecord {
  id: string;
  title: string;
  bucket: string;
  scenario: string;
  mode: EnforcementMode;
  status: 'ACTIVE' | 'CONTAINED' | 'RESTORED' | 'DRY_RUN_LOGGED';
  severity: 'P0' | 'P1';
  createdAt: string;
  firstMaliciousAtMs: number;
  detectedAtMs: number;
  triggeredContainAtMs?: number;
  first403AtMs?: number;
  mttdMs: number;
  mttcMs?: number;
  totalFilesInBucket: number;
  filesImpacted: number;
  filesPreserved: number;
  filesPreservedPct: number;
  isSwarm: boolean;
  principals: string[];
  signals: SignalType[];
  pendingAdminApproval?: {
    principalId: string;
    reason: string;
    requestedAt: string;
    decision?: 'approved' | 'denied';
    decidedAt?: string;
    decidedByRole?: Role;
  };
  affectedObjects: AffectedObjectRecord[];
  riskHistory: Array<{ timestamp: string; score: number }>;
  timeline: IncidentTimelineEntry[];
  restoreReport?: RestoreReport;
}

export interface CanaryItem {
  id: string;
  bucket: string;
  key: string;
  folderDepth: number;
  fileType: string;
  sizeBytes: number;
  sha256: string;
  createdAt: string;
  lastRefreshedAt: string;
  readTrips: number;
  writeTrips: number;
  generatedBy: 'groq-gpt-oss-120b' | 'deterministic';
  previewSnippet: string;
}

export interface ClassifierFileVerdict {
  key: string;
  actualLabel: 'canary' | 'real';
  predictedLabel: 'canary' | 'real';
  correct: boolean;
  confidence: number;
  reasoning: string;
}

export interface ClassifierAuditResult {
  id: string;
  runAt: string;
  model: string;
  sampleSize: number;
  canaryCount: number;
  realCount: number;
  correctCount: number;
  accuracyPct: number;
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
  tokensUsed: number;
  verdicts: ClassifierFileVerdict[];
}

export interface VaultStatus {
  vaultBucket: string;
  retentionMode: 'GOVERNANCE' | 'COMPLIANCE';
  retentionDays: number;
  objectLockActive: boolean;
  productionCredentialsDenied: boolean;
  replicationPaused: boolean;
  avgReplicationLagMs: number;
  manifestCount: number;
  totalVaultBytes: number;
  lastVerifiedAt: string;
  manifestIntegrityPct: number;
}

export type SimScenarioId =
  | 'benign_bulk'
  | 'benign_compressed'
  | 'benign_rename'
  | 'benign_backup_sync'
  | 'standard_ransomware'
  | 'stealth_ai_swarm'
  | 'recovery_verification';

export interface SimAssertion {
  id: string;
  label: string;
  status: 'pending' | 'running' | 'pass' | 'fail';
  detail?: string;
}

export interface SimRunState {
  running: boolean;
  scenario?: SimScenarioId;
  bucket: string;
  startedAt?: string;
  completedAt?: string;
  incidentId?: string;
  summary?: string;
  assertions: SimAssertion[];
}

export interface BenchmarkScenarioMetrics {
  scenario: string;
  runs: number;
  mttdMedianMs: number;
  mttdP95Ms: number;
  mttcMedianMs: number;
  mttcP95Ms: number;
  filesPreservedMedianPct: number;
  filesPreservedMinPct: number;
  filesLostMedian: number;
  falseAlarms: number;
  falsePositiveRatePct: number;
  restoreAccuracyPct: number;
  restoreTimeMedianMs: number;
  replicationLagMedianMs: number;
  evasionOrLateRuns: number;
  lateRunDetails: Array<{ runIndex: number; mttdMs: number; caughtBy: SignalType[] }>;
}

export interface BenchmarkSuiteResult {
  id: string;
  runAt: string;
  adapter: 'local' | 'minio';
  iterationsPerScenario: number;
  durationMs: number;
  scenarios: BenchmarkScenarioMetrics[];
  detectionsBySignal: Record<string, number>;
  overallPass: boolean;
}

export interface PolicyConfig {
  version: number;
  mode: EnforcementMode;
  buckets: Array<{
    name: string;
    tags: Record<string, string>;
    vault: string;
  }>;
  tiers: {
    critical: { response: 'auto-revoke' | 'alert-only' };
    sandbox: { response: 'auto-revoke' | 'alert-only' };
  };
  allowlist: {
    principals: string[];
    kms_keys: string[];
  };
  detection: {
    entropy: { sample_bytes: number; delta_threshold: number };
    burst: { window_seconds: number; pairs: number };
    swarm: { window_seconds: number; min_principals: number; flagged_writes: number };
    score: { watchlist: number; contain: number };
  };
  canary: {
    count: number;
    refresh_hours: number;
  };
  hard_triggers: string[];
  actions: {
    on_p0: string[];
  };
}

export interface GroqQuotaSnapshot {
  model: string;
  rpmLimit: number;
  rpmUsed: number;
  tpmLimit: number;
  tpmUsed: number;
  rpdLimit: number;
  rpdUsed: number;
  tpdLimit: number;
  tpdUsed: number;
  cooldownSecondsRemaining: number;
  lastCallTokens?: number;
  lastCallAt?: string;
}

export interface GroqConfigStatus {
  configured: boolean;
  source: 'byok' | 'env' | 'none';
  maskedKey: string | null;
  model: string;
  reasoningEffort: 'low' | 'medium';
  canaryBatchSize: number;
  onboardingCompleted: boolean;
  lastTestedAt?: string;
  lastTestOk?: boolean;
  quota: GroqQuotaSnapshot;
}

export type EventSource = 'simulator' | 'live-api' | 'webhook' | 'poller';

export type StorageProviderPreset =
  | 'local'
  | 'backblaze-b2'
  | 'supabase-s3'
  | 'minio'
  | 'custom-s3';

export interface LiveObjectSummary {
  bucket: string;
  key: string;
  sizeBytes: number;
  versionId: string;
  etag?: string;
  sha256: string;
  entropy: number;
  magicValid: boolean;
  magicDetected: string;
  isCanary: boolean;
  vaultProtected: boolean;
  vaultSha256?: string;
  principalId: string;
  lastModified: string;
  source: 'local' | 'external-s3';
  previewSnippet?: string;
}

export interface StorageSettings {
  activeAdapter: 'local' | 'minio';
  provider: StorageProviderPreset;
  minioEndpoint: string;
  minioRegion: string;
  minioUseSSL: boolean;
  forcePathStyle: boolean;
  productionBucket: string;
  vaultBucket: string;
  minioMonitorConfigured: boolean;
  minioVaultConfigured: boolean;
  minioConnected: boolean;
  lastConnectionMessage?: string;
  pollingEnabled: boolean;
  pollingIntervalSec: number;
  lastPollAt?: string;
  lastPollDiffCount: number;
  apiCallsToday: number;
}

export interface IngestStatus {
  tokenMasked: string;
  webhookEventsReceived: number;
  polledDiffsDetected: number;
  directUploadsProcessed: number;
  lastIngestAt?: string;
  containmentWebhookUrl: string;
  containmentWebhookEnabled: boolean;
  containmentDeliveries: number;
  lastContainmentStatus?: 'ok' | 'error' | 'idle';
}

export interface AlertSettings {
  webhookUrl: string;
  slackWebhookUrl: string;
  discordWebhookUrl: string;
  ntfyTopic: string;
  enabled: boolean;
  lastDeliveryAt?: string;
  lastDeliveryStatus?: 'ok' | 'error' | 'idle';
  deliveredCount: number;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  role: Role;
  action: string;
  target: string;
  outcome: 'success' | 'denied' | 'error';
  detail: string;
}

export interface HealthMetrics {
  engineStatus: 'healthy' | 'degraded';
  apiStatus: 'healthy' | 'degraded';
  streamGapSimulated: boolean;
  eventsPerMinute: number;
  avgIngestionLatencyMs: number;
  monitoredBuckets: number;
  monitoredObjects: number;
  activeCanaries: number;
  vaultSizeBytes: number;
  lastHeartbeatAt: string;
  uptimeSeconds: number;
}

export interface ConsoleBootstrapState {
  policy: PolicyConfig;
  policyYaml: string;
  buckets: BucketConfig[];
  principals: PrincipalState[];
  events: TelemetryEvent[];
  incidents: IncidentRecord[];
  canaries: CanaryItem[];
  classifierAudits: ClassifierAuditResult[];
  vault: VaultStatus;
  simulator: SimRunState;
  benchmarks: BenchmarkSuiteResult[];
  groq: GroqConfigStatus;
  storage: StorageSettings;
  ingest: IngestStatus;
  alerts: AlertSettings;
  health: HealthMetrics;
  auditLog: AuditEntry[];
}
