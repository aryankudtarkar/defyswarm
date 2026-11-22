import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import type {
  AlertSettings,
  AuditEntry,
  AutoHardenResult,
  BenchmarkSuiteResult,
  ClassifierAuditResult,
  ConsoleBootstrapState,
  HealthMetrics,
  IncidentRecord,
  IngestStatus,
  LiveObjectSummary,
  PolicyConfig,
  Role,
  SignalType,
  StorageProviderPreset,
  StorageSettings,
  TelemetryEvent,
} from '../src/shared/types.ts';
import { encryptBufferAes256, sha256Hex } from './cryptoUtils.ts';
import { DetectionEngine } from './detectionEngine.ts';
import { GroqService } from './groqService.ts';
import {
  DEFAULT_POLICY,
  loadPersistedPolicy,
  savePersistedPolicy,
  serializePolicyYaml,
  validatePolicyYaml,
} from './policyEngine.ts';
import { ExternalS3Adapter } from './s3ExternalAdapter.ts';
import { SimulatorAndBenchmarkRunner } from './simulatorAndBenchmark.ts';
import {
  LocalObjectStoreAdapter,
  SERVICE_PRINCIPAL,
  validateSafeExternalUrl,
} from './storageAdapter.ts';

const DATA_DIR = path.resolve(process.cwd(), 'data');
const LEDGER_FILE = path.join(DATA_DIR, 'ledger.json');

interface PersistedLedger {
  incidents: IncidentRecord[];
  benchmarks: BenchmarkSuiteResult[];
  classifierAudits: ClassifierAuditResult[];
  auditLog: AuditEntry[];
  alerts: AlertSettings;
  storage: StorageSettings;
  containmentWebhookUrl?: string;
  containmentWebhookEnabled?: boolean;
  onboardingCompleted: boolean;
}

export type BroadcastFn = (type: string, payload: unknown) => void;

export function sanitizeObjectKey(rawKey: string): string {
  const cleaned = rawKey.trim().replace(/^\/+/, '').replace(/\\/g, '/');
  if (!cleaned || cleaned.length > 256) {
    throw new Error('Object key must be between 1 and 256 characters.');
  }
  if (cleaned.includes('..') || cleaned.includes('\0')) {
    throw new Error('Object key contains disallowed path-traversal or control characters.');
  }
  return cleaned;
}

export function sanitizeNtfyTopic(raw: string): string {
  const cleaned = raw.trim().replace(/^https?:\/\/ntfy\.sh\//i, '').replace(/[^a-zA-Z0-9_-]/g, '');
  return cleaned.slice(0, 64);
}

function maskToken(tok: string): string {
  if (tok.length <= 10) return '••••••••';
  return `${tok.slice(0, 6)}••••${tok.slice(-4)}`;
}

export class DefySwarmStateStore {
  public policy: PolicyConfig;
  public policyYaml: string;
  public store: LocalObjectStoreAdapter;
  public externalS3: ExternalS3Adapter;
  public groq: GroqService;
  public engine: DetectionEngine;
  public runner: SimulatorAndBenchmarkRunner;

  public benchmarks: BenchmarkSuiteResult[] = [];
  public classifierAudits: ClassifierAuditResult[] = [];
  public auditLog: AuditEntry[] = [];
  public storageSettings: StorageSettings = {
    activeAdapter: 'local',
    provider: 'local',
    minioEndpoint: 'https://s3.us-west-004.backblazeb2.com',
    minioRegion: 'us-west-004',
    minioUseSSL: true,
    forcePathStyle: true,
    productionBucket: 'finance-prod',
    vaultBucket: 'vault-finance',
    minioMonitorConfigured: false,
    minioVaultConfigured: false,
    minioConnected: false,
    lastConnectionMessage:
      'Local Sandbox active. Connect Backblaze B2, Supabase Storage, MinIO, or any S3-compatible bucket anytime.',
    pollingEnabled: false,
    pollingIntervalSec: 60,
    lastPollDiffCount: 0,
    apiCallsToday: 0,
  };

  public alertSettings: AlertSettings = {
    webhookUrl: '',
    slackWebhookUrl: '',
    discordWebhookUrl: '',
    ntfyTopic: '',
    enabled: false,
    lastDeliveryStatus: 'idle',
    deliveredCount: 0,
  };

  // In-memory ingest & containment signing secret (never persisted to disk or policies.yaml)
  private ingestToken: string;
  public ingestCounters = {
    webhookEventsReceived: 0,
    polledDiffsDetected: 0,
    directUploadsProcessed: 0,
    lastIngestAt: undefined as string | undefined,
    containmentWebhookUrl: '',
    containmentWebhookEnabled: false,
    containmentDeliveries: 0,
    lastContainmentStatus: 'idle' as 'ok' | 'error' | 'idle',
  };

  public streamGapSimulated = false;
  private startedAtMs = Date.now();
  private broadcast: BroadcastFn = () => {};
  private pollTimer: ReturnType<typeof setInterval> | null = null;

  constructor() {
    const loaded = loadPersistedPolicy();
    this.policy = loaded.policy;
    this.policyYaml = loaded.yamlText;

    this.ingestToken =
      process.env.DEFYSWARM_INGEST_TOKEN?.trim() || `dsw_${crypto.randomBytes(20).toString('hex')}`;

    this.store = new LocalObjectStoreAdapter();
    this.externalS3 = new ExternalS3Adapter();
    this.groq = new GroqService();

    this.engine = new DetectionEngine(this.store, () => this.policy, {
      onEvent: (evt) => {
        if (!this.streamGapSimulated) {
          this.broadcast('event:ingested', evt);
        }
      },
      onIncident: (inc) => {
        this.persistLedger();
        this.broadcast('incident:updated', inc);
        this.broadcast('state:sync', this.getBootstrapState());
      },
      onAlert: (inc, msg) => {
        void this.dispatchAlertNotifications(inc, msg);
      },
      onContainment: (payload) => {
        void this.dispatchContainmentWebhook(payload);
      },
    });

    this.runner = new SimulatorAndBenchmarkRunner(
      this.store,
      this.engine,
      () => this.policy,
      (simState) => this.broadcast('sim:update', simState),
      (progress) => this.broadcast('benchmark:progress', progress),
    );

    this.loadLedger();
    this.storageSettings.minioMonitorConfigured = this.externalS3.hasMonitorCreds();
    this.storageSettings.minioVaultConfigured = this.externalS3.hasVaultCreds();
    this.syncPolicyBucketsToStore();
    this.restartPollLoop();
  }

  public setBroadcaster(fn: BroadcastFn) {
    this.broadcast = fn;
  }

  public emitStateSync() {
    this.broadcast('state:sync', this.getBootstrapState());
  }

  public getIngestTokenForAdmin(): string {
    return this.ingestToken;
  }

  public rotateIngestToken(role: Role): string {
    this.ingestToken = `dsw_${crypto.randomBytes(20).toString('hex')}`;
    this.recordAudit(
      role,
      'ingest.token_rotated',
      'webhook-auth',
      'success',
      'Rotated server-side ingest & HMAC webhook signing token.',
    );
    this.emitStateSync();
    return this.ingestToken;
  }

  public verifyIngestAuth(params: {
    headerToken?: string;
    authHeader?: string;
    hmacSignature?: string;
    rawBody?: Buffer | string;
  }): boolean {
    const expected = Buffer.from(this.ingestToken, 'utf8');

    const candidate =
      params.headerToken?.trim() ||
      (params.authHeader?.startsWith('Bearer ') ? params.authHeader.slice(7).trim() : '');

    if (candidate) {
      const provided = Buffer.from(candidate, 'utf8');
      if (provided.length === expected.length && crypto.timingSafeEqual(provided, expected)) {
        return true;
      }
    }

    if (params.hmacSignature && params.rawBody !== undefined) {
      const cleanSig = params.hmacSignature.replace(/^sha256=/i, '').trim();
      const computed = crypto
        .createHmac('sha256', this.ingestToken)
        .update(params.rawBody)
        .digest('hex');
      const a = Buffer.from(cleanSig, 'utf8');
      const b = Buffer.from(computed, 'utf8');
      if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
        return true;
      }
    }

    return false;
  }

  public getIngestStatus(): IngestStatus {
    return {
      tokenMasked: maskToken(this.ingestToken),
      webhookEventsReceived: this.ingestCounters.webhookEventsReceived,
      polledDiffsDetected: this.ingestCounters.polledDiffsDetected,
      directUploadsProcessed: this.ingestCounters.directUploadsProcessed,
      lastIngestAt: this.ingestCounters.lastIngestAt,
      containmentWebhookUrl: this.ingestCounters.containmentWebhookUrl,
      containmentWebhookEnabled: this.ingestCounters.containmentWebhookEnabled,
      containmentDeliveries: this.ingestCounters.containmentDeliveries,
      lastContainmentStatus: this.ingestCounters.lastContainmentStatus,
    };
  }

  private loadLedger() {
    try {
      if (fs.existsSync(LEDGER_FILE)) {
        const raw = fs.readFileSync(LEDGER_FILE, 'utf8');
        const data = JSON.parse(raw) as Partial<PersistedLedger>;
        if (Array.isArray(data.incidents)) this.engine.incidents = data.incidents;
        if (Array.isArray(data.benchmarks)) this.benchmarks = data.benchmarks;
        if (Array.isArray(data.classifierAudits)) this.classifierAudits = data.classifierAudits;
        if (Array.isArray(data.auditLog)) this.auditLog = data.auditLog;
        if (data.alerts) this.alertSettings = { ...this.alertSettings, ...data.alerts };
        if (data.storage) {
          this.storageSettings = {
            ...this.storageSettings,
            ...data.storage,
            // Never assume an external S3 session is connected across restarts without in-memory creds
            minioConnected: false,
            activeAdapter: 'local',
          };
        }
        if (typeof data.containmentWebhookUrl === 'string') {
          this.ingestCounters.containmentWebhookUrl = data.containmentWebhookUrl;
        }
        if (typeof data.containmentWebhookEnabled === 'boolean') {
          this.ingestCounters.containmentWebhookEnabled = data.containmentWebhookEnabled;
        }
        if (typeof data.onboardingCompleted === 'boolean') {
          this.groq.updatePreferences({ onboardingCompleted: data.onboardingCompleted });
        }
      }
    } catch {
      // Fresh ledger if unreadable
    }

    if (this.auditLog.length === 0) {
      this.recordAudit(
        'admin',
        'system.initialized',
        'control-plane',
        'success',
        'Initialized DefySwarm out-of-band control plane, WORM vault, and S3 ingestion engine.',
      );
    }
  }

  public persistLedger() {
    try {
      fs.mkdirSync(DATA_DIR, { recursive: true });
      const payload: PersistedLedger = {
        incidents: this.engine.incidents.slice(0, 60),
        benchmarks: this.benchmarks.slice(0, 20),
        classifierAudits: this.classifierAudits.slice(0, 20),
        auditLog: this.auditLog.slice(0, 250),
        alerts: this.alertSettings,
        storage: {
          ...this.storageSettings,
          minioMonitorConfigured: false,
          minioVaultConfigured: false,
        },
        containmentWebhookUrl: this.ingestCounters.containmentWebhookUrl,
        containmentWebhookEnabled: this.ingestCounters.containmentWebhookEnabled,
        onboardingCompleted: this.groq.getStatus().onboardingCompleted,
      };
      fs.writeFileSync(LEDGER_FILE, JSON.stringify(payload, null, 2), 'utf8');
    } catch {
      // Ignore disk write failure in constrained environments
    }
  }

  public recordAudit(
    role: Role,
    action: string,
    target: string,
    outcome: AuditEntry['outcome'],
    detail: string,
  ) {
    const entry: AuditEntry = {
      id: `aud-${Date.now()}-${crypto.randomBytes(2).toString('hex')}`,
      timestamp: new Date().toISOString(),
      role,
      action,
      target,
      outcome,
      detail,
    };
    this.auditLog.unshift(entry);
    if (this.auditLog.length > 250) this.auditLog.length = 250;
    this.persistLedger();
  }

  public syncPolicyBucketsToStore() {
    for (const pb of this.policy.buckets) {
      const existing = this.store.buckets.get(pb.name);
      if (existing) {
        existing.tags = { ...pb.tags };
        existing.vault = pb.vault;
      } else {
        this.store.registerBucket({
          name: pb.name,
          tags: { ...pb.tags },
          vault: pb.vault,
          versioningEnabled: true,
          objectLockEnabled: pb.tags.sensitivity === 'critical',
          auditLoggingEnabled: true,
          adapter: this.storageSettings.activeAdapter,
          objectCount: 0,
          canaryCount: 0,
        });
      }
    }
    for (const p of this.store.principals.values()) {
      p.allowlisted = this.policy.allowlist.principals.includes(p.id);
    }
    this.store.refreshBucketCounts();
  }

  public updatePolicyFromYaml(rawYaml: string, role: Role): { valid: boolean; errors: string[] } {
    const result = validatePolicyYaml(rawYaml);
    if (!result.valid || !result.policy) {
      this.recordAudit(role, 'policy.update', 'policies.yaml', 'error', result.errors.join(' '));
      return { valid: false, errors: result.errors };
    }
    this.policy = result.policy;
    this.policyYaml = savePersistedPolicy(this.policy, rawYaml);
    this.syncPolicyBucketsToStore();
    this.recordAudit(
      role,
      'policy.update',
      'policies.yaml',
      'success',
      `Updated policies.yaml (mode=${this.policy.mode}, buckets=${this.policy.buckets.length}).`,
    );
    this.emitStateSync();
    return { valid: true, errors: [] };
  }

  public updateMode(mode: 'active' | 'dry-run', role: Role) {
    this.policy.mode = mode;
    this.policyYaml = savePersistedPolicy(this.policy);
    this.recordAudit(
      role,
      'policy.mode_switch',
      'policies.yaml',
      'success',
      `Switched enforcement mode to ${mode}.`,
    );
    this.emitStateSync();
  }

  public updateAllowlist(principals: string[], kmsKeys: string[], role: Role) {
    this.policy.allowlist.principals = principals.filter(Boolean);
    this.policy.allowlist.kms_keys = kmsKeys.filter(Boolean);
    this.policyYaml = savePersistedPolicy(this.policy);
    this.syncPolicyBucketsToStore();
    this.recordAudit(
      role,
      'allowlist.update',
      'policies.yaml',
      'success',
      `Updated allowlist (${this.policy.allowlist.principals.length} principals, ${this.policy.allowlist.kms_keys.length} KMS keys).`,
    );
    this.emitStateSync();
  }

  public registerOrUpdateBucket(
    params: { name: string; sensitivity: 'critical' | 'sandbox'; simOnly: boolean; vault: string },
    role: Role,
  ) {
    const cleanName = params.name.trim().toLowerCase().replace(/[^a-z0-9-]/g, '-');
    if (cleanName.length < 3) {
      throw new Error('Bucket name must be at least 3 characters.');
    }
    const tags: Record<string, string> = {
      sensitivity: params.sensitivity,
      env: params.simOnly ? 'ransomware-sim-only' : 'production',
    };
    const existingIdx = this.policy.buckets.findIndex((b) => b.name === cleanName);
    const entry = { name: cleanName, tags, vault: params.vault || 'vault-finance' };
    if (existingIdx >= 0) {
      this.policy.buckets[existingIdx] = entry;
    } else {
      this.policy.buckets.push(entry);
    }
    this.policyYaml = savePersistedPolicy(this.policy);
    this.syncPolicyBucketsToStore();
    this.recordAudit(
      role,
      'bucket.register',
      cleanName,
      'success',
      `Registered bucket ${cleanName} (sensitivity=${tags.sensitivity}, env=${tags.env}).`,
    );
    this.emitStateSync();
  }

  public runAutoHarden(bucketName: string, role: Role): AutoHardenResult {
    const bucket = this.store.buckets.get(bucketName);
    if (!bucket) throw new Error(`Bucket ${bucketName} not found.`);

    bucket.versioningEnabled = true;
    bucket.objectLockEnabled = true;
    bucket.auditLoggingEnabled = true;

    const existingCanaries = Array.from(this.store.canaries.values()).filter(
      (c) => c.bucket === bucketName,
    );
    if (existingCanaries.length === 0) {
      this.store.seedDeterministicCanaries(bucketName);
    }

    bucket.lastHardenedAt = new Date().toISOString();
    this.store.refreshBucketCounts();

    const vaultStatus = this.store.getVaultStatus();
    const checks = [
      {
        id: 'versioning',
        label: 'Bucket Versioning Enabled',
        passed: bucket.versioningEnabled,
        detail: 'Object versioning active; prior clean snapshots retained.',
      },
      {
        id: 'vault_isolation',
        label: 'Out-of-Band WORM Vault Isolated',
        passed: vaultStatus.objectLockActive && vaultStatus.productionCredentialsDenied,
        detail: `Vault "${bucket.vault}" locked (${vaultStatus.retentionMode}); tenant credentials denied.`,
      },
      {
        id: 'audit_webhook',
        label: 'Control-Plane Audit Stream Active',
        passed: bucket.auditLoggingEnabled && !this.streamGapSimulated,
        detail: 'Versioning, lifecycle, and Object Lock control calls monitored in real time.',
      },
      {
        id: 'canaries',
        label: 'Context-Matched Adaptive Canaries Live',
        passed: bucket.canaryCount > 0,
        detail: `${bucket.canaryCount} active decoy object(s) deployed across nested prefixes.`,
      },
    ];

    const result: AutoHardenResult = {
      bucket: bucketName,
      timestamp: bucket.lastHardenedAt,
      allPassed: checks.every((c) => c.passed),
      checks,
    };

    this.recordAudit(
      role,
      'bucket.auto_harden',
      bucketName,
      'success',
      `Auto-Harden completed on ${bucketName}: ${checks.filter((c) => c.passed).length}/${checks.length} checks passed.`,
    );
    this.emitStateSync();
    return result;
  }

  public refreshCanaries(bucketName: string, role: Role) {
    const nowIso = new Date().toISOString();
    const list = Array.from(this.store.canaries.values()).filter((c) => c.bucket === bucketName);
    for (const item of list) {
      const rotatedSnippet = `${item.previewSnippet} [Cycle refreshed ${nowIso.slice(0, 16)}]`;
      this.store.installCanaryObject(bucketName, item.key, rotatedSnippet, item.generatedBy);
      const latest = this.store.getLatestVersion(bucketName, item.key);
      if (this.isExternalBucketActive(bucketName) && latest) {
        void this.externalS3
          .putObject({ bucket: bucketName, key: item.key, buffer: latest.buffer })
          .catch(() => {});
      }
      this.engine.ingestEvent({
        serverTimestampMs: Date.now(),
        plane: 'data',
        apiOp: 'PutObject',
        bucket: bucketName,
        key: item.key,
        principalId: SERVICE_PRINCIPAL,
        httpStatus: 200,
        isCanary: true,
        source: 'live-api',
      });
    }
    this.recordAudit(
      role,
      'canaries.refresh',
      bucketName,
      'success',
      `Rotated ${list.length} canaries under defyswarm-service (0 self-loop alerts).`,
    );
    this.emitStateSync();
    return list.length;
  }

  public async generateCanariesWithGroq(bucketName: string, role: Role) {
    const sampleKeys = this.store.getLiveObjectKeys(bucketName, false);
    const { specs, tokensUsed } = await this.groq.generateAdaptiveCanaries(bucketName, sampleKeys);
    const installed = [];
    for (const spec of specs) {
      const item = this.store.installCanaryObject(
        bucketName,
        spec.key,
        spec.snippet,
        'groq-gpt-oss-120b',
      );
      const latest = this.store.getLatestVersion(bucketName, spec.key);
      if (this.isExternalBucketActive(bucketName) && latest) {
        try {
          await this.externalS3.putObject({
            bucket: bucketName,
            key: spec.key,
            buffer: latest.buffer,
          });
        } catch {
          // Keep local canary even if external bucket is read-only
        }
      }
      this.engine.ingestEvent({
        serverTimestampMs: Date.now(),
        plane: 'data',
        apiOp: 'PutObject',
        bucket: bucketName,
        key: spec.key,
        principalId: SERVICE_PRINCIPAL,
        httpStatus: 200,
        isCanary: true,
        source: 'live-api',
      });
      installed.push(item);
    }

    this.recordAudit(
      role,
      'canaries.generate_llm',
      bucketName,
      'success',
      `Generated ${installed.length} adaptive canaries via Groq openai/gpt-oss-120b (${tokensUsed} tokens).`,
    );
    this.emitStateSync();
    return { installed, tokensUsed };
  }

  public async runCanaryClassifierAudit(bucketName: string, role: Role): Promise<ClassifierAuditResult> {
    const canaries = Array.from(this.store.canaries.values())
      .filter((c) => c.bucket === bucketName)
      .slice(0, 5);
    const realKeys = this.store.getLiveObjectKeys(bucketName, false).slice(0, 5);

    const samples: Array<{
      key: string;
      sizeBytes: number;
      fileType: string;
      excerpt: string;
      actualLabel: 'canary' | 'real';
    }> = [];

    for (const c of canaries) {
      samples.push({
        key: c.key,
        sizeBytes: c.sizeBytes,
        fileType: c.fileType,
        excerpt: c.previewSnippet,
        actualLabel: 'canary',
      });
    }
    for (const rk of realKeys) {
      const v = this.store.getLatestVersion(bucketName, rk);
      if (!v) continue;
      samples.push({
        key: rk,
        sizeBytes: v.sizeBytes,
        fileType: rk.split('.').pop()?.toUpperCase() || 'FILE',
        excerpt: v.previewSnippet,
        actualLabel: 'real',
      });
    }

    const audit = await this.groq.runBlindClassifierAudit(samples);
    this.classifierAudits.unshift(audit);
    if (this.classifierAudits.length > 20) this.classifierAudits.length = 20;

    this.recordAudit(
      role,
      'canaries.classifier_test',
      bucketName,
      'success',
      `Groq openai/gpt-oss-120b blind classifier scored ${audit.accuracyPct}% accuracy on ${audit.sampleSize} files (${audit.tokensUsed} tokens).`,
    );
    this.persistLedger();
    this.emitStateSync();
    return audit;
  }

  public async triggerHumanAdminTestScenario(bucketName: string, role: Role) {
    const pid = 'admin-elena-chen';
    const p = this.store.principals.get(pid);
    if (p) {
      p.status = 'ACTIVE';
      p.quarantinePolicyAttached = false;
      p.riskScore = 70;
      p.triggeredSignals = [];
    }
    const targetKey =
      this.store.getLiveObjectKeys(bucketName, false)[0] ??
      'finance/2026/Q3/consolidated_balance_sheet.pdf';
    this.engine.ingestEvent({
      serverTimestampMs: Date.now(),
      plane: 'data',
      apiOp: 'CopyObject',
      bucket: bucketName,
      key: targetKey,
      principalId: pid,
      httpStatus: 200,
      kmsKeyId: 'arn:aws:kms:us-east-1:999988887777:key/unverified-admin-key',
      scenarioTag: 'human_admin_approval_test',
      source: 'simulator',
    });
    this.recordAudit(
      role,
      'incident.simulate_admin_gate',
      pid,
      'success',
      `Triggered human-admin approval gate test for ${pid} on ${bucketName}.`,
    );
    this.emitStateSync();
  }

  public isExternalBucketActive(bucket: string): boolean {
    return (
      this.storageSettings.activeAdapter === 'minio' &&
      this.storageSettings.minioConnected &&
      this.storageSettings.productionBucket === bucket
    );
  }

  /**
   * Lists live objects for the Live Storage Browser — pulls real external S3 objects when connected,
   * or returns real objects from the built-in versioned store.
   */
  public async listLiveObjects(bucket: string): Promise<LiveObjectSummary[]> {
    const results: LiveObjectSummary[] = [];

    if (this.isExternalBucketActive(bucket)) {
      const extItems = await this.externalS3.listObjects(bucket, 150);
      this.storageSettings.apiCallsToday = this.externalS3.getApiCallsToday();
      for (const item of extItems) {
        const localVer = this.store.getLatestVersion(bucket, item.key);
        const vaultEntry = this.store.getLatestCleanVersionFromVault(bucket, item.key);
        const isCanary = this.store.canaries.has(`${bucket}/${item.key}`);
        results.push({
          bucket,
          key: item.key,
          sizeBytes: item.sizeBytes,
          versionId: localVer?.versionId ?? item.etag ?? 'latest',
          etag: item.etag,
          sha256: localVer?.sha256 ?? item.etag ?? '',
          entropy: localVer?.entropy ?? 0,
          magicValid: localVer?.magicValid ?? true,
          magicDetected: localVer?.magicDetected ?? 'S3_OBJECT',
          isCanary,
          vaultProtected: Boolean(vaultEntry),
          vaultSha256: vaultEntry?.sha256,
          principalId: localVer?.principalId ?? 'external-s3',
          lastModified: item.lastModified,
          source: 'external-s3',
          previewSnippet: localVer?.previewSnippet,
        });
      }
      return results;
    }

    const bucketMap = this.store.objects.get(bucket);
    if (!bucketMap) return [];

    for (const [key, versions] of bucketMap.entries()) {
      const latest = versions[versions.length - 1];
      if (!latest || latest.isDeleteMarker) continue;
      const vaultEntry = this.store.getLatestCleanVersionFromVault(bucket, key);
      results.push({
        bucket,
        key,
        sizeBytes: latest.sizeBytes,
        versionId: latest.versionId,
        sha256: latest.sha256,
        entropy: latest.entropy,
        magicValid: latest.magicValid,
        magicDetected: latest.magicDetected,
        isCanary: latest.isCanary || this.store.canaries.has(`${bucket}/${key}`),
        vaultProtected: Boolean(vaultEntry),
        vaultSha256: vaultEntry?.sha256,
        principalId: latest.principalId,
        lastModified: new Date(latest.timestampMs).toISOString(),
        source: 'local',
        previewSnippet: latest.previewSnippet,
      });
    }

    return results.sort((a, b) => b.lastModified.localeCompare(a.lastModified));
  }

  /**
   * Real live file upload handler (browser drag-and-drop or external curl CLI).
   * Enforces real HTTP 403 principal containment, writes to external S3 if active + local store,
   * computes real 64 KB Shannon entropy & magic-byte verdict, and streams live to War Room.
   */
  public async handleLivePutObject(params: {
    bucket: string;
    key: string;
    buffer: Buffer;
    principalId: string;
    contentType?: string;
    sseAlgorithm?: string;
    kmsKeyId?: string;
  }): Promise<{
    httpStatus: number;
    error?: string;
    event: TelemetryEvent;
    object?: LiveObjectSummary;
  }> {
    const safeKey = sanitizeObjectKey(params.key);
    const principalId = params.principalId.trim() || 'live-upload-client';
    const bucket = params.bucket.trim();

    if (!this.store.buckets.has(bucket)) {
      throw new Error(`Bucket "${bucket}" is not registered in policies.yaml.`);
    }

    const res = this.store.putObject({
      bucket,
      key: safeKey,
      buffer: params.buffer,
      principalId,
      sseAlgorithm: params.sseAlgorithm,
      kmsKeyId: params.kmsKeyId,
      previewSnippet: `Real uploaded file (${params.buffer.length} bytes, ${params.contentType || 'binary'}).`,
    });

    if (res.httpStatus === 200 && this.isExternalBucketActive(bucket)) {
      await this.externalS3.putObject({
        bucket,
        key: safeKey,
        buffer: params.buffer,
        contentType: params.contentType,
      });
      // Replicate clean write to external vault bucket if configured & replication not paused
      if (
        !this.store.vaultReplicationPaused &&
        res.magicValid !== false &&
        this.storageSettings.vaultBucket
      ) {
        void this.externalS3
          .putObject({
            bucket: this.storageSettings.vaultBucket,
            key: safeKey,
            buffer: params.buffer,
            contentType: params.contentType,
            useVault: true,
          })
          .catch(() => {});
      }
      this.storageSettings.apiCallsToday = this.externalS3.getApiCallsToday();
    }

    const event = this.engine.ingestEvent({
      serverTimestampMs: Date.now(),
      plane: 'data',
      apiOp: 'PutObject',
      bucket,
      key: safeKey,
      principalId,
      httpStatus: res.httpStatus,
      entropy: res.entropy,
      prevEntropy: res.prevEntropy,
      magicValid: res.magicValid,
      magicDetected: res.magicDetected,
      sseAlgorithm: params.sseAlgorithm,
      kmsKeyId: params.kmsKeyId,
      source: 'live-api',
    });

    this.ingestCounters.directUploadsProcessed += 1;
    this.ingestCounters.lastIngestAt = new Date().toISOString();
    this.emitStateSync();

    if (res.httpStatus !== 200) {
      return { httpStatus: res.httpStatus, error: res.error, event };
    }

    const latest = this.store.getLatestVersion(bucket, safeKey);
    const vaultEntry = this.store.getLatestCleanVersionFromVault(bucket, safeKey);
    return {
      httpStatus: 200,
      event,
      object: latest
        ? {
            bucket,
            key: safeKey,
            sizeBytes: latest.sizeBytes,
            versionId: latest.versionId,
            sha256: latest.sha256,
            entropy: latest.entropy,
            magicValid: latest.magicValid,
            magicDetected: latest.magicDetected,
            isCanary: latest.isCanary,
            vaultProtected: Boolean(vaultEntry),
            vaultSha256: vaultEntry?.sha256,
            principalId: latest.principalId,
            lastModified: new Date(latest.timestampMs).toISOString(),
            source: this.isExternalBucketActive(bucket) ? 'external-s3' : 'local',
            previewSnippet: latest.previewSnippet,
          }
        : undefined,
    };
  }

  public async handleLiveDeleteObject(params: {
    bucket: string;
    key: string;
    principalId: string;
  }): Promise<{ httpStatus: number; error?: string; event: TelemetryEvent }> {
    const safeKey = sanitizeObjectKey(params.key);
    const principalId = params.principalId.trim() || 'live-upload-client';
    const res = this.store.deleteObject({
      bucket: params.bucket,
      key: safeKey,
      principalId,
    });

    if (res.httpStatus === 204 && this.isExternalBucketActive(params.bucket)) {
      await this.externalS3.deleteObject(params.bucket, safeKey);
      this.storageSettings.apiCallsToday = this.externalS3.getApiCallsToday();
    }

    const event = this.engine.ingestEvent({
      serverTimestampMs: Date.now(),
      plane: 'data',
      apiOp: 'DeleteObject',
      bucket: params.bucket,
      key: safeKey,
      principalId,
      httpStatus: res.httpStatus,
      source: 'live-api',
    });

    this.emitStateSync();
    return { httpStatus: res.httpStatus, error: res.error, event };
  }

  /**
   * Real AES-256-GCM encrypted overwrite test on an actual stored file (non-simulator live test).
   */
  public async handleRealEncryptedOverwriteTest(params: {
    bucket: string;
    key: string;
    principalId: string;
  }) {
    const safeKey = sanitizeObjectKey(params.key);
    const existing = this.store.getLatestVersion(params.bucket, safeKey);
    let sourceBuf = existing?.buffer;

    if (!sourceBuf && this.isExternalBucketActive(params.bucket)) {
      const ext = await this.externalS3.getObjectFull(params.bucket, safeKey, false);
      sourceBuf = ext.buffer;
      // Seed clean vault snapshot before test overwrite so recovery works cleanly
      this.store.putObject({
        bucket: params.bucket,
        key: safeKey,
        buffer: sourceBuf,
        principalId: SERVICE_PRINCIPAL,
      });
    }

    if (!sourceBuf) {
      throw new Error(`Object ${params.bucket}/${safeKey} not found.`);
    }

    const encrypted = encryptBufferAes256(sourceBuf);
    return this.handleLivePutObject({
      bucket: params.bucket,
      key: safeKey,
      buffer: encrypted,
      principalId: params.principalId,
      contentType: 'application/octet-stream',
    });
  }

  public async getObjectForDownload(
    bucket: string,
    key: string,
    fromVault: boolean,
  ): Promise<{ buffer: Buffer; filename: string; sha256: string }> {
    const safeKey = sanitizeObjectKey(key);
    const filename = path.basename(safeKey) || 'object.bin';

    if (fromVault) {
      const vaultEntry = this.store.getLatestCleanVersionFromVault(bucket, safeKey);
      if (vaultEntry) {
        return { buffer: vaultEntry.buffer, filename, sha256: vaultEntry.sha256 };
      }
      if (this.isExternalBucketActive(bucket) && this.storageSettings.vaultBucket) {
        const ext = await this.externalS3.getObjectFull(
          this.storageSettings.vaultBucket,
          safeKey,
          true,
        );
        return { buffer: ext.buffer, filename, sha256: ext.sha256 };
      }
      throw new Error('No verified clean vault snapshot available for this object.');
    }

    if (this.isExternalBucketActive(bucket)) {
      const ext = await this.externalS3.getObjectFull(bucket, safeKey, false);
      return { buffer: ext.buffer, filename, sha256: ext.sha256 };
    }

    const latest = this.store.getLatestVersion(bucket, safeKey);
    if (!latest || latest.isDeleteMarker) {
      throw new Error(`Object ${bucket}/${safeKey} not found.`);
    }
    return { buffer: latest.buffer, filename, sha256: latest.sha256 };
  }

  /**
   * Real AWS S3 / MinIO Webhook Receiver:
   * Parses standard S3/MinIO notification Records[], inspects 64 KB range when external S3 is connected,
   * and feeds directly into DetectionEngine.
   */
  public async processExternalS3Webhook(body: unknown): Promise<{ processed: number; events: TelemetryEvent[] }> {
    const payload = body as {
      Records?: Array<{
        eventName?: string;
        eventTime?: string;
        userIdentity?: { principalId?: string };
        s3?: {
          bucket?: { name?: string };
          object?: { key?: string; size?: number; eTag?: string };
        };
      }>;
    };

    const records = Array.isArray(payload?.Records) ? payload.Records : [];
    const emitted: TelemetryEvent[] = [];

    for (const rec of records.slice(0, 50)) {
      const rawEvent = String(rec.eventName || 's3:ObjectCreated:Put');
      const bucket = String(rec.s3?.bucket?.name || this.storageSettings.productionBucket || 'finance-prod');
      const rawKey = rec.s3?.object?.key ? decodeURIComponent(rec.s3.object.key.replace(/\+/g, ' ')) : undefined;
      const principalId = String(rec.userIdentity?.principalId || 'external-webhook-principal');

      if (!this.store.buckets.has(bucket)) {
        this.store.registerBucket({
          name: bucket,
          tags: { sensitivity: 'critical', env: 'production' },
          vault: this.storageSettings.vaultBucket || 'vault-finance',
          versioningEnabled: true,
          objectLockEnabled: true,
          auditLoggingEnabled: true,
          adapter: 'minio',
          objectCount: 0,
          canaryCount: 0,
        });
      }

      const apiOp = rawEvent.includes('ObjectRemoved')
        ? 'DeleteObject'
        : rawEvent.includes('ObjectAccessed')
          ? 'GetObject'
          : 'PutObject';

      let entropy: number | undefined;
      let prevEntropy: number | undefined;
      let magicValid: boolean | undefined;
      let magicDetected: string | undefined;

      if (rawKey && apiOp === 'PutObject' && this.isExternalBucketActive(bucket)) {
        try {
          const prev = this.store.getLatestVersion(bucket, rawKey);
          prevEntropy = prev?.entropy;
          const inspection = await this.externalS3.readObjectRange64KB(bucket, rawKey);
          entropy = inspection.entropy;
          magicValid = inspection.magicValid;
          magicDetected = inspection.magicDetected;
          this.storageSettings.apiCallsToday = this.externalS3.getApiCallsToday();
        } catch {
          // Proceed with metadata-only event if object was already deleted
        }
      }

      const evt = this.engine.ingestEvent({
        serverTimestampMs: Date.now(),
        plane: 'data',
        apiOp,
        bucket,
        key: rawKey,
        principalId,
        httpStatus: 200,
        entropy,
        prevEntropy,
        magicValid,
        magicDetected,
        source: 'webhook',
      });
      emitted.push(evt);
    }

    this.ingestCounters.webhookEventsReceived += emitted.length;
    this.ingestCounters.lastIngestAt = new Date().toISOString();
    this.emitStateSync();
    return { processed: emitted.length, events: emitted };
  }

  /**
   * Quota-safe S3 Change Poller (for Backblaze B2, Supabase Storage S3, or firewalled MinIO).
   */
  public async pollExternalBucketNow(triggeredBy: Role | 'scheduler' = 'scheduler'): Promise<{
    polled: boolean;
    totalObjects: number;
    diffsDetected: number;
    message: string;
  }> {
    if (!this.storageSettings.minioConnected || this.storageSettings.activeAdapter !== 'minio') {
      return {
        polled: false,
        totalObjects: 0,
        diffsDetected: 0,
        message: 'External S3 adapter is not connected. Using Built-in Real Object Store.',
      };
    }

    const bucket = this.storageSettings.productionBucket;
    const { diffs, totalObjects } = await this.externalS3.pollBucketChanges(bucket);
    this.storageSettings.lastPollAt = new Date().toISOString();
    this.storageSettings.lastPollDiffCount = diffs.length;
    this.storageSettings.apiCallsToday = this.externalS3.getApiCallsToday();

    for (const d of diffs) {
      this.engine.ingestEvent({
        serverTimestampMs: Date.now(),
        plane: 'data',
        apiOp: d.kind === 'deleted' ? 'DeleteObject' : 'PutObject',
        bucket: d.bucket,
        key: d.key,
        principalId: `s3-poller:${this.storageSettings.provider}`,
        httpStatus: 200,
        entropy: d.inspection?.entropy,
        prevEntropy: d.prevEntropy,
        magicValid: d.inspection?.magicValid,
        magicDetected: d.inspection?.magicDetected,
        source: 'poller',
      });
    }

    if (diffs.length > 0) {
      this.ingestCounters.polledDiffsDetected += diffs.length;
      this.ingestCounters.lastIngestAt = this.storageSettings.lastPollAt;
    }

    if (triggeredBy !== 'scheduler') {
      this.recordAudit(
        triggeredBy,
        'ingest.poll_now',
        bucket,
        'success',
        `Polled ${bucket} (${totalObjects} objects scanned, ${diffs.length} change(s) evaluated).`,
      );
    }

    this.emitStateSync();
    return {
      polled: true,
      totalObjects,
      diffsDetected: diffs.length,
      message: `Synced ${totalObjects} object(s) from ${bucket}; ${diffs.length} change(s) analyzed.`,
    };
  }

  public restartPollLoop() {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
    if (
      this.storageSettings.pollingEnabled &&
      this.storageSettings.minioConnected &&
      this.storageSettings.activeAdapter === 'minio'
    ) {
      const intervalMs = Math.max(30, this.storageSettings.pollingIntervalSec) * 1000;
      this.pollTimer = setInterval(() => {
        void this.pollExternalBucketNow('scheduler').catch(() => {});
      }, intervalMs);
    }
  }

  public async testAndSaveStorageSettings(
    params: {
      activeAdapter: 'local' | 'minio';
      provider?: StorageProviderPreset;
      minioEndpoint?: string;
      minioRegion?: string;
      forcePathStyle?: boolean;
      productionBucket?: string;
      vaultBucket?: string;
      monitorAccessKeyId?: string;
      monitorSecretAccessKey?: string;
      vaultAccessKeyId?: string;
      vaultSecretAccessKey?: string;
      clearMonitorCreds?: boolean;
      clearVaultCreds?: boolean;
      pollingEnabled?: boolean;
      pollingIntervalSec?: number;
    },
    role: Role,
  ) {
    if (params.provider) this.storageSettings.provider = params.provider;
    if (params.minioEndpoint && params.minioEndpoint.trim()) {
      const check = validateSafeExternalUrl(params.minioEndpoint.trim());
      if (!check.valid) throw new Error(check.reason || 'Invalid S3 endpoint URL.');
      this.storageSettings.minioEndpoint = params.minioEndpoint.trim();
      this.storageSettings.minioUseSSL = this.storageSettings.minioEndpoint.startsWith('https://');
    }
    if (params.minioRegion?.trim()) this.storageSettings.minioRegion = params.minioRegion.trim();
    if (typeof params.forcePathStyle === 'boolean') {
      this.storageSettings.forcePathStyle = params.forcePathStyle;
    }
    if (params.productionBucket?.trim()) {
      this.storageSettings.productionBucket = params.productionBucket.trim();
    }
    if (params.vaultBucket !== undefined) {
      this.storageSettings.vaultBucket = params.vaultBucket.trim();
    }
    if (typeof params.pollingEnabled === 'boolean') {
      this.storageSettings.pollingEnabled = params.pollingEnabled;
    }
    if (typeof params.pollingIntervalSec === 'number') {
      this.storageSettings.pollingIntervalSec = Math.min(600, Math.max(30, params.pollingIntervalSec));
    }

    this.externalS3.setCredentials({
      monitorAccessKeyId: params.monitorAccessKeyId,
      monitorSecretAccessKey: params.monitorSecretAccessKey,
      vaultAccessKeyId: params.vaultAccessKeyId,
      vaultSecretAccessKey: params.vaultSecretAccessKey,
      clearMonitor: params.clearMonitorCreds,
      clearVault: params.clearVaultCreds,
    });

    this.storageSettings.minioMonitorConfigured = this.externalS3.hasMonitorCreds();
    this.storageSettings.minioVaultConfigured = this.externalS3.hasVaultCreds();

    this.externalS3.setConfig({
      provider: this.storageSettings.provider,
      endpoint: this.storageSettings.minioEndpoint,
      region: this.storageSettings.minioRegion,
      forcePathStyle: this.storageSettings.forcePathStyle,
      productionBucket: this.storageSettings.productionBucket,
      vaultBucket: this.storageSettings.vaultBucket,
    });

    if (params.activeAdapter === 'minio' && this.storageSettings.provider !== 'local') {
      try {
        const posture = await this.externalS3.verifyConnection();
        this.storageSettings.minioConnected = posture.reachable;
        this.storageSettings.activeAdapter = 'minio';
        this.storageSettings.lastConnectionMessage = posture.message;
        this.storageSettings.apiCallsToday = this.externalS3.getApiCallsToday();
        this.externalS3.resetPollBaseline();

        // Ensure monitored external bucket exists in local policy registry
        if (!this.store.buckets.has(this.storageSettings.productionBucket)) {
          this.store.registerBucket({
            name: this.storageSettings.productionBucket,
            tags: { sensitivity: 'critical', env: 'production' },
            vault: this.storageSettings.vaultBucket || 'vault-finance',
            versioningEnabled: posture.versioningStatus === 'Enabled',
            objectLockEnabled: posture.objectLockEnabled,
            auditLoggingEnabled: true,
            adapter: 'minio',
            objectCount: 0,
            canaryCount: 0,
          });
        }
        // Establish initial polling baseline right away (1 ListObjectsV2 call)
        void this.pollExternalBucketNow('scheduler').catch(() => {});
      } catch (err) {
        this.storageSettings.minioConnected = false;
        this.storageSettings.activeAdapter = 'local';
        this.storageSettings.lastConnectionMessage = `Connection failed (${err instanceof Error ? err.message : 'S3 error'}). Local Sandbox remains active.`;
      }
    } else {
      this.storageSettings.activeAdapter = 'local';
      this.storageSettings.provider = 'local';
      this.storageSettings.minioConnected = false;
      this.storageSettings.lastConnectionMessage = 'Local Sandbox active.';
    }

    this.restartPollLoop();
    this.recordAudit(
      role,
      'storage.configure',
      this.storageSettings.provider,
      this.storageSettings.minioConnected || this.storageSettings.activeAdapter === 'local'
        ? 'success'
        : 'error',
      this.storageSettings.lastConnectionMessage || 'Updated storage adapter.',
    );
    this.persistLedger();
    this.emitStateSync();
    return this.storageSettings;
  }

  public updateContainmentWebhook(
    params: { containmentWebhookUrl?: string; containmentWebhookEnabled?: boolean },
    role: Role,
  ) {
    const url = (params.containmentWebhookUrl ?? this.ingestCounters.containmentWebhookUrl).trim();
    if (url) {
      const check = validateSafeExternalUrl(url);
      if (!check.valid) throw new Error(`Containment webhook rejected: ${check.reason}`);
    }
    this.ingestCounters.containmentWebhookUrl = url;
    if (typeof params.containmentWebhookEnabled === 'boolean') {
      this.ingestCounters.containmentWebhookEnabled = params.containmentWebhookEnabled;
    }
    this.recordAudit(
      role,
      'containment.webhook_configure',
      'containment-webhook',
      'success',
      `Updated signed containment webhook (enabled=${this.ingestCounters.containmentWebhookEnabled}).`,
    );
    this.persistLedger();
    this.emitStateSync();
    return this.getIngestStatus();
  }

  private async dispatchContainmentWebhook(payload: {
    incident: IncidentRecord;
    principalId: string;
    bucket: string;
    signals: SignalType[];
  }) {
    if (
      !this.ingestCounters.containmentWebhookEnabled ||
      !this.ingestCounters.containmentWebhookUrl
    ) {
      return;
    }
    const check = validateSafeExternalUrl(this.ingestCounters.containmentWebhookUrl);
    if (!check.valid) return;

    const bodyText = JSON.stringify({
      action: 'REVOKE_PRINCIPAL',
      product: 'DefySwarm',
      timestamp: new Date().toISOString(),
      incidentId: payload.incident.id,
      bucket: payload.bucket,
      principalId: payload.principalId,
      signals: payload.signals,
    });
    const sig = crypto.createHmac('sha256', this.ingestToken).update(bodyText).digest('hex');

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 3500);
      const res = await fetch(this.ingestCounters.containmentWebhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-DefySwarm-Signature': `sha256=${sig}`,
        },
        body: bodyText,
        signal: controller.signal,
      });
      clearTimeout(timer);
      this.ingestCounters.lastContainmentStatus = res.ok ? 'ok' : 'error';
      if (res.ok) this.ingestCounters.containmentDeliveries += 1;
    } catch {
      this.ingestCounters.lastContainmentStatus = 'error';
    }
    this.emitStateSync();
  }

  public updateAlertSettings(
    params: {
      webhookUrl?: string;
      slackWebhookUrl?: string;
      discordWebhookUrl?: string;
      ntfyTopic?: string;
      enabled?: boolean;
    },
    role: Role,
  ) {
    const urlsToCheck = [
      { label: 'Alert webhook', val: params.webhookUrl?.trim() },
      { label: 'Slack webhook', val: params.slackWebhookUrl?.trim() },
      { label: 'Discord webhook', val: params.discordWebhookUrl?.trim() },
    ];
    for (const item of urlsToCheck) {
      if (item.val) {
        const check = validateSafeExternalUrl(item.val);
        if (!check.valid) throw new Error(`${item.label} rejected: ${check.reason}`);
      }
    }

    if (params.webhookUrl !== undefined) this.alertSettings.webhookUrl = params.webhookUrl.trim();
    if (params.slackWebhookUrl !== undefined) {
      this.alertSettings.slackWebhookUrl = params.slackWebhookUrl.trim();
    }
    if (params.discordWebhookUrl !== undefined) {
      this.alertSettings.discordWebhookUrl = params.discordWebhookUrl.trim();
    }
    if (params.ntfyTopic !== undefined) {
      this.alertSettings.ntfyTopic = sanitizeNtfyTopic(params.ntfyTopic);
    }
    if (typeof params.enabled === 'boolean') this.alertSettings.enabled = params.enabled;

    this.recordAudit(
      role,
      'alerts.configure',
      'alert-channels',
      'success',
      `Updated alert delivery (enabled=${this.alertSettings.enabled}, ntfy=${this.alertSettings.ntfyTopic || 'off'}).`,
    );
    this.persistLedger();
    this.emitStateSync();
    return this.alertSettings;
  }

  public async sendTestAlert(role: Role): Promise<{ delivered: number; channels: string[] }> {
    const channels: string[] = [];
    let delivered = 0;

    if (this.alertSettings.ntfyTopic) {
      const ok = await this.postWithTimeout(`https://ntfy.sh/${this.alertSettings.ntfyTopic}`, {
        headers: {
          Title: 'DefySwarm Test Alert',
          Priority: 'high',
          Tags: 'shield',
        },
        body: 'DefySwarm push notification channel verified.',
      });
      if (ok) {
        delivered++;
        channels.push(`ntfy.sh/${this.alertSettings.ntfyTopic}`);
      }
    }

    if (this.alertSettings.discordWebhookUrl) {
      const ok = await this.postWithTimeout(this.alertSettings.discordWebhookUrl, {
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: '**[DefySwarm]** Discord alert channel verified.',
        }),
      });
      if (ok) {
        delivered++;
        channels.push('Discord');
      }
    }

    if (this.alertSettings.slackWebhookUrl) {
      const ok = await this.postWithTimeout(this.alertSettings.slackWebhookUrl, {
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: '[DefySwarm] Slack alert channel verified.' }),
      });
      if (ok) {
        delivered++;
        channels.push('Slack');
      }
    }

    if (this.alertSettings.webhookUrl) {
      const ok = await this.postWithTimeout(this.alertSettings.webhookUrl, {
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ event: 'defyswarm.test', timestamp: new Date().toISOString() }),
      });
      if (ok) {
        delivered++;
        channels.push('Custom Webhook');
      }
    }

    if (channels.length === 0) {
      throw new Error(
        'No alert destination succeeded. Enter an ntfy.sh topic (free, no signup) or Discord/Slack webhook first.',
      );
    }

    this.alertSettings.deliveredCount += delivered;
    this.alertSettings.lastDeliveryAt = new Date().toISOString();
    this.alertSettings.lastDeliveryStatus = 'ok';
    this.recordAudit(
      role,
      'alerts.test',
      channels.join(', '),
      'success',
      `Delivered test alert to ${channels.join(', ')}.`,
    );
    this.persistLedger();
    this.emitStateSync();
    return { delivered, channels };
  }

  private async postWithTimeout(
    url: string,
    init: { headers: Record<string, string>; body: string },
  ): Promise<boolean> {
    const check = validateSafeExternalUrl(url);
    if (!check.valid) return false;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 3500);
      const res = await fetch(url, {
        method: 'POST',
        headers: init.headers,
        body: init.body,
        signal: controller.signal,
      });
      clearTimeout(timer);
      return res.ok;
    } catch {
      return false;
    }
  }

  private async dispatchAlertNotifications(incident: IncidentRecord, summary: string) {
    if (!this.alertSettings.enabled) return;
    let anyOk = false;
    let anyAttempted = false;

    if (this.alertSettings.ntfyTopic) {
      anyAttempted = true;
      const ok = await this.postWithTimeout(`https://ntfy.sh/${this.alertSettings.ntfyTopic}`, {
        headers: {
          Title: `DefySwarm ${incident.severity}: ${incident.bucket}`,
          Priority: 'urgent',
          Tags: 'rotating_light,shield',
        },
        body: `${summary} | Principals: ${incident.principals.join(', ')} | Signals: ${incident.signals.join(', ')}`,
      });
      if (ok) {
        anyOk = true;
        this.alertSettings.deliveredCount += 1;
      }
    }

    if (this.alertSettings.discordWebhookUrl) {
      anyAttempted = true;
      const ok = await this.postWithTimeout(this.alertSettings.discordWebhookUrl, {
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: `**[DefySwarm ${incident.severity}]** ${summary}\nBucket: \`${incident.bucket}\` · Principals: \`${incident.principals.join(', ')}\` · Signals: \`${incident.signals.join(', ')}\``,
        }),
      });
      if (ok) {
        anyOk = true;
        this.alertSettings.deliveredCount += 1;
      }
    }

    if (this.alertSettings.slackWebhookUrl) {
      anyAttempted = true;
      const ok = await this.postWithTimeout(this.alertSettings.slackWebhookUrl, {
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: `[DefySwarm ${incident.severity}] ${summary} (Bucket: ${incident.bucket}, Principals: ${incident.principals.join(', ')})`,
        }),
      });
      if (ok) {
        anyOk = true;
        this.alertSettings.deliveredCount += 1;
      }
    }

    if (this.alertSettings.webhookUrl) {
      anyAttempted = true;
      const ok = await this.postWithTimeout(this.alertSettings.webhookUrl, {
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: `[DefySwarm ${incident.severity}] ${summary}`,
          incidentId: incident.id,
          bucket: incident.bucket,
          principals: incident.principals,
          signals: incident.signals,
          mttdMs: incident.mttdMs,
        }),
      });
      if (ok) {
        anyOk = true;
        this.alertSettings.deliveredCount += 1;
      }
    }

    if (anyAttempted) {
      this.alertSettings.lastDeliveryAt = new Date().toISOString();
      this.alertSettings.lastDeliveryStatus = anyOk ? 'ok' : 'error';
      this.persistLedger();
    }
  }

  public setPrincipalStatus(principalId: string, status: 'ACTIVE' | 'REVOKED', role: Role) {
    const p = this.store.principals.get(principalId);
    if (!p) throw new Error(`Principal ${principalId} not found.`);
    p.status = status;
    if (status === 'ACTIVE') {
      p.quarantinePolicyAttached = false;
      p.riskScore = 0;
      p.triggeredSignals = [];
    } else {
      p.quarantinePolicyAttached = true;
      p.revokedAt = new Date().toISOString();
    }
    this.recordAudit(
      role,
      status === 'REVOKED' ? 'principal.revoke' : 'principal.restore_access',
      principalId,
      'success',
      `Manually set principal ${principalId} status to ${status}.`,
    );
    this.emitStateSync();
    return p;
  }

  public async executeOneClickRestoreWithExternalSync(incidentId: string, role: Role) {
    const { incident, report } = this.engine.executeOneClickRestore(incidentId);

    // If connected to a real external S3 bucket, push verified restored clean files back to external S3 too!
    if (this.isExternalBucketActive(incident.bucket)) {
      for (const obj of incident.affectedObjects) {
        const clean = this.store.getLatestCleanVersionFromVault(incident.bucket, obj.key);
        if (clean) {
          try {
            await this.externalS3.putObject({
              bucket: incident.bucket,
              key: obj.key,
              buffer: clean.buffer,
            });
          } catch {
            // Best-effort sync to external bucket
          }
        }
      }
      this.storageSettings.apiCallsToday = this.externalS3.getApiCallsToday();
    }

    this.recordAudit(
      role,
      'incident.restore',
      incident.id,
      'success',
      `1-Click Restore completed: ${report.filesRestored} files restored (${report.restoreAccuracyPct}% SHA-256 match).`,
    );
    this.persistLedger();
    this.emitStateSync();
    return { incident, report };
  }

  public resetDemo(role: Role) {
    this.policy = structuredClone(DEFAULT_POLICY);
    this.policyYaml = savePersistedPolicy(this.policy, serializePolicyYaml(this.policy));
    this.store.seedDefaults();
    this.engine.resetRuntimeWindows();
    this.engine.events = [];
    this.engine.incidents = [];
    this.runner.simState = {
      running: false,
      bucket: 'finance-prod',
      assertions: [],
    };
    this.streamGapSimulated = false;
    this.recordAudit(
      role,
      'demo.reset',
      'all-buckets',
      'success',
      'Reset object store, WORM vault, credentials, incidents, and policies to clean baseline.',
    );
    this.persistLedger();
    this.emitStateSync();
  }

  public getHealthMetrics(): HealthMetrics {
    const nowMs = Date.now();
    const oneMinAgo = nowMs - 60000;
    const eventsLastMin = this.engine.events.filter((e) => e.serverTimestampMs >= oneMinAgo).length;
    const latencies = this.engine.ingestionLatenciesMs;
    const avgLatency =
      latencies.length > 0
        ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length)
        : 4;

    let monitoredObjects = 0;
    for (const b of this.store.buckets.values()) {
      monitoredObjects += b.objectCount;
    }

    const vault = this.store.getVaultStatus();
    return {
      engineStatus: this.streamGapSimulated ? 'degraded' : 'healthy',
      apiStatus: 'healthy',
      streamGapSimulated: this.streamGapSimulated,
      eventsPerMinute: eventsLastMin,
      avgIngestionLatencyMs: avgLatency,
      monitoredBuckets: this.store.buckets.size,
      monitoredObjects,
      activeCanaries: this.store.canaries.size,
      vaultSizeBytes: vault.totalVaultBytes,
      lastHeartbeatAt: new Date().toISOString(),
      uptimeSeconds: Math.round((nowMs - this.startedAtMs) / 1000),
    };
  }

  public getBootstrapState(): ConsoleBootstrapState {
    this.storageSettings.apiCallsToday = this.externalS3.getApiCallsToday();
    return {
      policy: this.policy,
      policyYaml: this.policyYaml,
      buckets: Array.from(this.store.buckets.values()),
      principals: Array.from(this.store.principals.values()),
      events: this.engine.events.slice(0, 140),
      incidents: this.engine.incidents,
      canaries: Array.from(this.store.canaries.values()),
      classifierAudits: this.classifierAudits,
      vault: this.store.getVaultStatus(),
      simulator: this.runner.simState,
      benchmarks: this.benchmarks,
      groq: this.groq.getStatus(),
      storage: this.storageSettings,
      ingest: this.getIngestStatus(),
      alerts: this.alertSettings,
      health: this.getHealthMetrics(),
      auditLog: this.auditLog.slice(0, 120),
    };
  }
}
