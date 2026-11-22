import crypto from 'crypto';
import type {
  AffectedObjectRecord,
  EventSource,
  IncidentRecord,
  PolicyConfig,
  RestorePreview,
  RestoreReport,
  Role,
  SignalType,
  TelemetryEvent,
} from '../src/shared/types.ts';
import { LocalObjectStoreAdapter, SERVICE_PRINCIPAL } from './storageAdapter.ts';

interface BurstRecord {
  atMs: number;
  principalId: string;
  key: string;
  kind: 'delete' | 'suspicious_write';
}

interface SwarmFlagRecord {
  atMs: number;
  principalId: string;
  key: string;
  signals: SignalType[];
}

export interface IncomingStorageEvent {
  serverTimestampMs: number;
  plane: 'data' | 'control';
  apiOp: string;
  bucket: string;
  key?: string;
  principalId: string;
  httpStatus: number;
  entropy?: number;
  prevEntropy?: number;
  magicValid?: boolean;
  magicDetected?: string;
  sseAlgorithm?: string;
  kmsKeyId?: string;
  isCanary?: boolean;
  lifecycleExpiryDays?: number;
  versioningTargetStatus?: 'Suspended' | 'Enabled';
  versionIdPurged?: string;
  scenarioTag?: string;
  source?: EventSource;
}

export class DetectionEngine {
  private burstWindows = new Map<string, BurstRecord[]>();
  private swarmWindows = new Map<string, SwarmFlagRecord[]>();
  private bucketRiskScores = new Map<string, { score: number; updatedAtMs: number }>();

  public events: TelemetryEvent[] = [];
  public incidents: IncidentRecord[] = [];
  public ingestionLatenciesMs: number[] = [];

  private onEventCallback?: (evt: TelemetryEvent) => void;
  private onIncidentCallback?: (inc: IncidentRecord) => void;
  private onAlertCallback?: (inc: IncidentRecord, message: string) => void;
  private onContainmentCallback?: (payload: {
    incident: IncidentRecord;
    principalId: string;
    bucket: string;
    signals: SignalType[];
  }) => void;

  constructor(
    private store: LocalObjectStoreAdapter,
    private getPolicy: () => PolicyConfig,
    hooks?: {
      onEvent?: (evt: TelemetryEvent) => void;
      onIncident?: (inc: IncidentRecord) => void;
      onAlert?: (inc: IncidentRecord, message: string) => void;
      onContainment?: (payload: {
        incident: IncidentRecord;
        principalId: string;
        bucket: string;
        signals: SignalType[];
      }) => void;
    },
  ) {
    this.onEventCallback = hooks?.onEvent;
    this.onIncidentCallback = hooks?.onIncident;
    this.onAlertCallback = hooks?.onAlert;
    this.onContainmentCallback = hooks?.onContainment;
  }

  public resetRuntimeWindows() {
    this.burstWindows.clear();
    this.swarmWindows.clear();
    this.bucketRiskScores.clear();
  }

  public getBucketRiskScore(bucket: string): number {
    const entry = this.bucketRiskScores.get(bucket);
    if (!entry) return 0;
    // Gentle exponential decay (half-life ~120s) when quiet
    const elapsedSec = (Date.now() - entry.updatedAtMs) / 1000;
    const decayed = entry.score * Math.pow(0.5, elapsedSec / 120);
    return Math.round(decayed);
  }

  public ingestEvent(input: IncomingStorageEvent): TelemetryEvent {
    const ingestStartMs = Date.now();
    const policy = this.getPolicy();

    // 1. Self-loop protection: ignore internal defyswarm-service principal
    if (input.principalId === SERVICE_PRINCIPAL) {
      const ignored: TelemetryEvent = {
        id: `evt-${ingestStartMs}-${crypto.randomBytes(3).toString('hex')}`,
        timestamp: new Date(input.serverTimestampMs).toISOString(),
        serverTimestampMs: input.serverTimestampMs,
        plane: input.plane,
        apiOp: input.apiOp,
        bucket: input.bucket,
        key: input.key,
        principalId: input.principalId,
        httpStatus: input.httpStatus,
        entropy: input.entropy,
        prevEntropy: input.prevEntropy,
        magicValid: input.magicValid,
        magicDetected: input.magicDetected,
        isCanary: input.isCanary,
        selfLoopIgnored: true,
        riskDelta: 0,
        bucketRiskScore: this.getBucketRiskScore(input.bucket),
        principalRiskScore: 0,
        signals: [],
        note: 'Self-loop protection: ignored out-of-band service principal.',
      };
      this.recordEvent(ignored, ingestStartMs - input.serverTimestampMs);
      return ignored;
    }

    // Ensure principal exists in registry
    if (!this.store.principals.has(input.principalId)) {
      this.store.registerPrincipal(input.principalId, input.principalId, 'service_account', false);
    }
    const principal = this.store.principals.get(input.principalId)!;
    const isAllowlistedPrincipal =
      principal.allowlisted || policy.allowlist.principals.includes(input.principalId);
    principal.allowlisted = isAllowlistedPrincipal;
    principal.lastSeenAt = new Date(input.serverTimestampMs).toISOString();

    // If this request was ALREADY rejected with 403 because of containment, measure exact MTTC!
    if (input.httpStatus === 403) {
      if (!principal.first403At) {
        principal.first403At = new Date(input.serverTimestampMs).toISOString();
      }
      const openInc = this.findActiveIncidentForBucket(input.bucket);
      if (openInc && !openInc.first403AtMs && openInc.triggeredContainAtMs) {
        openInc.first403AtMs = input.serverTimestampMs;
        openInc.mttcMs = Math.max(1, input.serverTimestampMs - openInc.triggeredContainAtMs);
        openInc.timeline.push({
          timestamp: new Date(input.serverTimestampMs).toISOString(),
          label: 'Containment Verified (HTTP 403)',
          detail: `Principal ${input.principalId} blocked with 403 AccessDenied on ${input.apiOp}. Measured MTTC: ${openInc.mttcMs} ms.`,
          severity: 'success',
        });
        this.onIncidentCallback?.(openInc);
      }

      const blockedEvt: TelemetryEvent = {
        id: `evt-${ingestStartMs}-${crypto.randomBytes(3).toString('hex')}`,
        timestamp: new Date(input.serverTimestampMs).toISOString(),
        serverTimestampMs: input.serverTimestampMs,
        plane: input.plane,
        apiOp: input.apiOp,
        bucket: input.bucket,
        key: input.key,
        principalId: input.principalId,
        httpStatus: 403,
        riskDelta: 0,
        bucketRiskScore: this.getBucketRiskScore(input.bucket),
        principalRiskScore: principal.riskScore,
        signals: [],
        source: input.source ?? 'simulator',
        note: 'Blocked by DefySwarm containment (HTTP 403).',
      };
      this.recordEvent(blockedEvt, ingestStartMs - input.serverTimestampMs);
      return blockedEvt;
    }

    const signals: SignalType[] = [];
    let riskDelta = 0;
    let hardTriggerFired = false;
    let deltaEntropy: number | undefined;

    const canaryItem = input.key ? this.store.canaries.get(`${input.bucket}/${input.key}`) : undefined;
    const isCanary = Boolean(input.isCanary || canaryItem);

    // 2. Control-plane sabotage triggers (instant P0)
    if (input.plane === 'control') {
      if (
        input.apiOp === 'PutBucketVersioning' &&
        input.versioningTargetStatus === 'Suspended' &&
        policy.hard_triggers.includes('versioning_suspend')
      ) {
        signals.push('versioning_suspend');
        riskDelta += 100;
        hardTriggerFired = true;
      }
      if (
        (input.apiOp === 'DeleteObjectVersion' ||
          (input.apiOp === 'DeleteObjects' && Boolean(input.versionIdPurged))) &&
        policy.hard_triggers.includes('version_purge')
      ) {
        signals.push('version_purge');
        riskDelta += 100;
        hardTriggerFired = true;
      }
      if (
        input.apiOp === 'PutBucketLifecycleConfiguration' &&
        typeof input.lifecycleExpiryDays === 'number' &&
        input.lifecycleExpiryDays <= 1 &&
        policy.hard_triggers.includes('lifecycle_expiry_1d_or_less')
      ) {
        signals.push('lifecycle_expiry');
        riskDelta += 100;
        hardTriggerFired = true;
      }
      if (
        (input.apiOp === 'PutObjectLockConfiguration' || input.apiOp === 'PutObjectRetention') &&
        policy.hard_triggers.includes('object_lock_tamper')
      ) {
        signals.push('object_lock_tamper');
        riskDelta += 100;
        hardTriggerFired = true;
      }
      if (
        input.apiOp === 'PutBucketLogging' &&
        policy.hard_triggers.includes('audit_log_tamper')
      ) {
        signals.push('audit_log_tamper');
        riskDelta += 100;
        hardTriggerFired = true;
      }
    }

    // 3. Canary triggers (allowlist respected on reads)
    if (isCanary && input.plane === 'data') {
      if (input.apiOp === 'GetObject') {
        if (canaryItem) canaryItem.readTrips += 1;
        if (!isAllowlistedPrincipal) {
          signals.push('canary_read');
          riskDelta += 45;
        }
      } else if (
        input.apiOp === 'PutObject' ||
        input.apiOp === 'CopyObject' ||
        input.apiOp === 'DeleteObject' ||
        input.apiOp === 'CompleteMultipartUpload'
      ) {
        if (canaryItem) canaryItem.writeTrips += 1;
        if (policy.hard_triggers.includes('canary_write')) {
          signals.push('canary_write');
          riskDelta += 100;
          hardTriggerFired = true;
        }
      }
    }

    // 4. Native Cloud Crypto-Abuse (SSE-C or untrusted KMS ARN)
    if (
      (input.apiOp === 'CopyObject' ||
        input.apiOp === 'CompleteMultipartUpload' ||
        input.apiOp === 'PutObject') &&
      !isAllowlistedPrincipal
    ) {
      if (input.sseAlgorithm === 'AES256-SSE-C') {
        signals.push('ssec_abuse');
        riskDelta += 100;
        hardTriggerFired = true;
      } else if (input.kmsKeyId && !policy.allowlist.kms_keys.includes(input.kmsKeyId)) {
        signals.push('untrusted_kms');
        riskDelta += 65;
      }
    }

    // 5. Entropy delta & magic-byte validation (avoids false alarms on new valid compressed files!)
    let isSuspiciousWrite = false;
    if (
      (input.apiOp === 'PutObject' ||
        input.apiOp === 'CopyObject' ||
        input.apiOp === 'CompleteMultipartUpload') &&
      typeof input.entropy === 'number'
    ) {
      if (typeof input.prevEntropy === 'number' && input.prevEntropy > 0) {
        deltaEntropy = Number((input.entropy - input.prevEntropy).toFixed(3));
        if (deltaEntropy >= policy.detection.entropy.delta_threshold) {
          signals.push('entropy_delta');
          riskDelta += 32;
          isSuspiciousWrite = true;
        }
      }
      if (input.magicValid === false) {
        signals.push('magic_header_lost');
        riskDelta += 35;
        isSuspiciousWrite = true;
      }
      if (input.key?.endsWith('.locked')) {
        isSuspiciousWrite = true;
      }
    }

    // 6. Rename & Delete-Rewrite Burst (10-second sliding window)
    if (input.plane === 'data' && input.key) {
      const nowMs = input.serverTimestampMs;
      const winMs = policy.detection.burst.window_seconds * 1000;
      const bucketBurst = (this.burstWindows.get(input.bucket) ?? []).filter(
        (r) => nowMs - r.atMs <= winMs,
      );

      if (input.apiOp === 'DeleteObject') {
        bucketBurst.push({ atMs: nowMs, principalId: input.principalId, key: input.key, kind: 'delete' });
      } else if (isSuspiciousWrite) {
        bucketBurst.push({
          atMs: nowMs,
          principalId: input.principalId,
          key: input.key,
          kind: 'suspicious_write',
        });
      }
      this.burstWindows.set(input.bucket, bucketBurst);

      // Count paired deletes + suspicious writes by this principal
      const byPrincipal = bucketBurst.filter((r) => r.principalId === input.principalId);
      const deletes = byPrincipal.filter((r) => r.kind === 'delete').length;
      const suspWrites = byPrincipal.filter((r) => r.kind === 'suspicious_write').length;
      const pairs = Math.min(deletes, suspWrites);
      if (pairs >= policy.detection.burst.pairs && !isAllowlistedPrincipal) {
        signals.push('rename_burst');
        riskDelta += 45;
      }
    }

    // 7. Cross-Principal Swarm Correlation (60s bucket-wide window across >= min_principals)
    let swarmPrincipals: string[] = [];
    if ((isSuspiciousWrite || signals.length > 0) && !isAllowlistedPrincipal && input.key) {
      const nowMs = input.serverTimestampMs;
      const swarmWinMs = policy.detection.swarm.window_seconds * 1000;
      const bucketSwarm = (this.swarmWindows.get(input.bucket) ?? []).filter(
        (r) => nowMs - r.atMs <= swarmWinMs,
      );
      bucketSwarm.push({
        atMs: nowMs,
        principalId: input.principalId,
        key: input.key,
        signals: [...signals],
      });
      this.swarmWindows.set(input.bucket, bucketSwarm);

      const distinctPrincipals = Array.from(new Set(bucketSwarm.map((r) => r.principalId)));
      if (
        distinctPrincipals.length >= policy.detection.swarm.min_principals &&
        bucketSwarm.length >= policy.detection.swarm.flagged_writes
      ) {
        if (!signals.includes('swarm_correlation')) {
          signals.push('swarm_correlation');
        }
        riskDelta = Math.max(riskDelta, 100);
        swarmPrincipals = distinctPrincipals;
      }
    }

    // Update risk scores (principal & bucket)
    if (riskDelta > 0) {
      principal.riskScore = Math.min(200, principal.riskScore + riskDelta);
      for (const s of signals) {
        if (!principal.triggeredSignals.includes(s)) {
          principal.triggeredSignals.push(s);
        }
      }
      const prevBucket = this.getBucketRiskScore(input.bucket);
      this.bucketRiskScores.set(input.bucket, {
        score: Math.min(200, prevBucket + riskDelta),
        updatedAtMs: input.serverTimestampMs,
      });
    }

    const bucketScore = this.getBucketRiskScore(input.bucket);
    const event: TelemetryEvent = {
      id: `evt-${ingestStartMs}-${crypto.randomBytes(3).toString('hex')}`,
      timestamp: new Date(input.serverTimestampMs).toISOString(),
      serverTimestampMs: input.serverTimestampMs,
      plane: input.plane,
      apiOp: input.apiOp,
      bucket: input.bucket,
      key: input.key,
      principalId: input.principalId,
      httpStatus: input.httpStatus,
      entropy: input.entropy,
      prevEntropy: input.prevEntropy,
      deltaEntropy,
      magicValid: input.magicValid,
      magicDetected: input.magicDetected,
      sseAlgorithm: input.sseAlgorithm,
      kmsKeyId: input.kmsKeyId,
      isCanary,
      allowlisted: isAllowlistedPrincipal,
      riskDelta,
      bucketRiskScore: bucketScore,
      principalRiskScore: principal.riskScore,
      signals,
      source: input.source ?? 'simulator',
      note:
        isCanary && isAllowlistedPrincipal && input.apiOp === 'GetObject'
          ? 'Allowlisted scanner read canary: logged, not scored.'
          : undefined,
    };

    this.recordEvent(event, Date.now() - input.serverTimestampMs);

    // 8. Evaluate Watchlist (P1) vs Containment (P0)
    const shouldContain =
      hardTriggerFired ||
      signals.includes('swarm_correlation') ||
      principal.riskScore >= policy.detection.score.contain ||
      bucketScore >= policy.detection.score.contain;

    const shouldWatchlist =
      !shouldContain &&
      (principal.riskScore >= policy.detection.score.watchlist || signals.includes('canary_read'));

    if (shouldWatchlist && principal.status === 'ACTIVE') {
      principal.status = 'WATCHLIST';
    }

    // Track impacted files in any open incident
    const existingInc = this.findActiveIncidentForBucket(input.bucket);
    if (existingInc && input.key && (isSuspiciousWrite || input.apiOp === 'DeleteObject' || input.sseAlgorithm === 'AES256-SSE-C')) {
      this.appendAffectedObject(existingInc, input);
    }

    if (shouldContain) {
      this.triggerContainment({
        event,
        input,
        hardTriggerFired,
        swarmPrincipals,
        signals,
      });
    }

    return event;
  }

  private triggerContainment(ctx: {
    event: TelemetryEvent;
    input: IncomingStorageEvent;
    hardTriggerFired: boolean;
    swarmPrincipals: string[];
    signals: SignalType[];
  }) {
    const policy = this.getPolicy();
    const bucketCfg = this.store.buckets.get(ctx.input.bucket);
    const sensitivity = bucketCfg?.tags.sensitivity === 'sandbox' ? 'sandbox' : 'critical';
    const tierResponse = policy.tiers[sensitivity].response;
    const nowMs = Date.now();
    const isDryRun = policy.mode === 'dry-run';

    const targetPrincipals =
      ctx.swarmPrincipals.length > 0
        ? ctx.swarmPrincipals
        : [ctx.input.principalId];

    // Create or update active incident
    let incident = this.findActiveIncidentForBucket(ctx.input.bucket);
    const isNew = !incident;
    if (!incident) {
      const totalFiles = Math.max(1, this.store.getLiveObjectKeys(ctx.input.bucket, false).length);
      const isSwarm = ctx.swarmPrincipals.length >= 2;
      incident = {
        id: `INC-${new Date().toISOString().slice(11, 19).replace(/:/g, '')}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`,
        title: isSwarm
          ? `Distributed Swarm Containment on ${ctx.input.bucket}`
          : ctx.signals.includes('versioning_suspend') || ctx.signals.includes('version_purge')
            ? `Recovery Sabotage Blocked on ${ctx.input.bucket}`
            : ctx.signals.includes('canary_write')
              ? `Adaptive Canary Tamper on ${ctx.input.bucket}`
              : ctx.signals.includes('ssec_abuse')
                ? `Native SSE-C Crypto-Abuse on ${ctx.input.bucket}`
                : `Ransomware Encryption Activity on ${ctx.input.bucket}`,
        bucket: ctx.input.bucket,
        scenario: ctx.input.scenarioTag || (isSwarm ? 'stealth_ai_swarm' : 'standard_ransomware'),
        mode: policy.mode,
        status: isDryRun ? 'DRY_RUN_LOGGED' : 'CONTAINED',
        severity: 'P0',
        createdAt: new Date(nowMs).toISOString(),
        firstMaliciousAtMs: ctx.input.serverTimestampMs,
        detectedAtMs: nowMs,
        triggeredContainAtMs: nowMs,
        mttdMs: Math.max(1, nowMs - ctx.input.serverTimestampMs),
        totalFilesInBucket: totalFiles,
        filesImpacted: 0,
        filesPreserved: totalFiles,
        filesPreservedPct: 100,
        isSwarm,
        principals: [...targetPrincipals],
        signals: [...ctx.signals],
        affectedObjects: [],
        riskHistory: [
          { timestamp: new Date(ctx.input.serverTimestampMs).toISOString(), score: ctx.event.bucketRiskScore },
        ],
        timeline: [
          {
            timestamp: new Date(ctx.input.serverTimestampMs).toISOString(),
            label: 'Malicious Activity Detected',
            detail: `Triggered signals: ${ctx.signals.join(', ')} by ${ctx.input.principalId} on ${ctx.input.bucket}.`,
            severity: 'critical',
          },
        ],
      };
      this.incidents.unshift(incident);
    } else {
      for (const p of targetPrincipals) {
        if (!incident.principals.includes(p)) incident.principals.push(p);
      }
      for (const s of ctx.signals) {
        if (!incident.signals.includes(s)) incident.signals.push(s);
      }
      if (ctx.swarmPrincipals.length >= 2) incident.isSwarm = true;
      incident.riskHistory.push({
        timestamp: new Date(nowMs).toISOString(),
        score: ctx.event.bucketRiskScore,
      });
    }

    if (ctx.input.key && (ctx.input.apiOp !== 'GetObject' || ctx.signals.includes('canary_write'))) {
      this.appendAffectedObject(incident, ctx.input);
    }

    // Pause replication immediately (replication-poisoning guard) when active
    if (!isDryRun && policy.actions.on_p0.includes('pause_replication')) {
      this.store.vaultReplicationPaused = true;
    }

    // Enforce containment per principal type & bucket sensitivity tier
    for (const pid of targetPrincipals) {
      const pState = this.store.principals.get(pid);
      if (!pState) continue;

      if (isDryRun) {
        incident.timeline.push({
          timestamp: new Date(nowMs).toISOString(),
          label: 'Dry-Run Action Logged (No Revocation)',
          detail: `Would disable ${pid} and attach deny-all quarantine on ${ctx.input.bucket}.`,
          severity: 'warning',
        });
        continue;
      }

      if (tierResponse === 'alert-only') {
        pState.status = 'WATCHLIST';
        incident.timeline.push({
          timestamp: new Date(nowMs).toISOString(),
          label: 'Sandbox Tier Alert-Only',
          detail: `Bucket ${ctx.input.bucket} is tagged sensitivity=sandbox; escalated ${pid} to WATCHLIST without revocation.`,
          severity: 'warning',
        });
        continue;
      }

      // Human admin rule (PRD §8): quarantine + approval prompt unless hard trigger OR >= 2 signals agree
      const corroborated = pState.triggeredSignals.length >= 2;
      if (pState.type === 'human_admin' && !ctx.hardTriggerFired && !corroborated) {
        pState.status = 'PENDING_APPROVAL';
        pState.quarantinePolicyAttached = true;
        incident.pendingAdminApproval = {
          principalId: pid,
          reason: `Single non-hard signal (${ctx.signals.join(', ')}) on human admin ${pid}. Confirm permanent revocation or release quarantine.`,
          requestedAt: new Date(nowMs).toISOString(),
        };
        incident.timeline.push({
          timestamp: new Date(nowMs).toISOString(),
          label: 'Human Admin Approval Required',
          detail: `Temporary quarantine applied to ${pid}; awaiting operator approval in Incidents console.`,
          severity: 'warning',
        });
        continue;
      }

      if (pState.status !== 'REVOKED') {
        pState.status = 'REVOKED';
        pState.quarantinePolicyAttached = true;
        pState.revokedAt = new Date(nowMs).toISOString();
        incident.timeline.push({
          timestamp: pState.revokedAt,
          label:
            pState.type === 'assumed_role'
              ? 'Deny-All Session Quarantine Attached'
              : 'Credential Disabled & Sessions Revoked',
          detail: `Principal ${pid} revoked and isolated. Replication paused to protect WORM vault.`,
          severity: 'critical',
        });
        this.onContainmentCallback?.({
          incident,
          principalId: pid,
          bucket: ctx.input.bucket,
          signals: ctx.signals,
        });
      }
    }

    this.recomputeIncidentStats(incident);
    this.onIncidentCallback?.(incident);
    if (isNew) {
      this.onAlertCallback?.(incident, `${incident.title} (MTTD: ${incident.mttdMs} ms)`);
    }
  }

  private appendAffectedObject(incident: IncidentRecord, input: IncomingStorageEvent) {
    if (!input.key) return;
    const baseKey = input.key.endsWith('.locked') ? input.key.slice(0, -'.locked'.length) : input.key;
    const vaultEntry = this.store.getLatestCleanVersionFromVault(input.bucket, baseKey);
    const artifactType: AffectedObjectRecord['artifactType'] = input.key.endsWith('.locked')
      ? 'locked_rename'
      : input.apiOp === 'DeleteObject'
        ? 'delete_marker'
        : input.sseAlgorithm === 'AES256-SSE-C'
          ? 'ssec_copy'
          : input.isCanary
            ? 'canary_tamper'
            : 'encrypted_overwrite';

    const existing = incident.affectedObjects.find((a) => a.key === baseKey);
    if (!existing) {
      incident.affectedObjects.push({
        key: baseKey,
        bucket: input.bucket,
        artifactType,
        preAttackSha256: vaultEntry?.sha256,
        cleanVersionId: vaultEntry?.versionId,
        replicationLagMs: vaultEntry?.replicationLagMs ?? 0,
      });
    } else if (artifactType === 'locked_rename' || artifactType === 'ssec_copy') {
      existing.artifactType = artifactType;
    }

    this.recomputeIncidentStats(incident);
  }

  public recomputeIncidentStats(incident: IncidentRecord) {
    const impactedBusiness = incident.affectedObjects.filter(
      (a) => a.artifactType !== 'canary_tamper',
    ).length;
    incident.filesImpacted = impactedBusiness;
    incident.filesPreserved = Math.max(0, incident.totalFilesInBucket - impactedBusiness);
    incident.filesPreservedPct = Number(
      ((incident.filesPreserved / Math.max(1, incident.totalFilesInBucket)) * 100).toFixed(1),
    );
  }

  public findActiveIncidentForBucket(bucket: string): IncidentRecord | undefined {
    return this.incidents.find(
      (inc) => inc.bucket === bucket && (inc.status === 'ACTIVE' || inc.status === 'CONTAINED'),
    );
  }

  public approveOrDenyAdminQuarantine(
    incidentId: string,
    decision: 'approved' | 'denied',
    role: Role,
  ): IncidentRecord {
    const inc = this.incidents.find((i) => i.id === incidentId);
    if (!inc || !inc.pendingAdminApproval) {
      throw new Error('No pending human-admin approval found for this incident.');
    }
    const pid = inc.pendingAdminApproval.principalId;
    const pState = this.store.principals.get(pid);
    const nowIso = new Date().toISOString();

    inc.pendingAdminApproval.decision = decision;
    inc.pendingAdminApproval.decidedAt = nowIso;
    inc.pendingAdminApproval.decidedByRole = role;

    if (pState) {
      if (decision === 'approved') {
        pState.status = 'REVOKED';
        pState.quarantinePolicyAttached = true;
        pState.revokedAt = nowIso;
      } else {
        pState.status = 'ACTIVE';
        pState.quarantinePolicyAttached = false;
        pState.riskScore = 0;
      }
    }

    inc.timeline.push({
      timestamp: nowIso,
      label: decision === 'approved' ? 'Admin Quarantine Approved' : 'Admin Quarantine Released',
      detail: `Operator (${role}) ${decision} quarantine on ${pid}.`,
      severity: decision === 'approved' ? 'critical' : 'info',
    });

    this.onIncidentCallback?.(inc);
    return inc;
  }

  public buildRestorePreview(incidentId: string): RestorePreview {
    const inc = this.incidents.find((i) => i.id === incidentId);
    if (!inc) throw new Error(`Incident ${incidentId} not found.`);

    const allPrincipalsContained = inc.principals.every((pid) => {
      const p = this.store.principals.get(pid);
      return !p || p.status === 'REVOKED' || p.quarantinePolicyAttached;
    });

    const artifactsToRemove: string[] = [];
    const bucketMap = this.store.objects.get(inc.bucket);
    if (bucketMap) {
      for (const key of bucketMap.keys()) {
        if (key.endsWith('.locked')) {
          artifactsToRemove.push(key);
        }
      }
    }

    const objectsToRestore = inc.affectedObjects.map((obj) => {
      const manifest = this.store.getLatestCleanVersionFromVault(inc.bucket, obj.key);
      return {
        key: obj.key,
        cleanVersionId: manifest?.versionId ?? 'NONE',
        preAttackSha256: manifest?.sha256 ?? 'UNAVAILABLE',
        dataLossWindowMs: manifest?.replicationLagMs ?? 0,
        recoverable: Boolean(manifest),
      };
    });

    const unrecoverableCount = objectsToRestore.filter((o) => !o.recoverable).length;
    const maxDataLossWindowMs = objectsToRestore.reduce(
      (max, o) => Math.max(max, o.dataLossWindowMs),
      0,
    );

    return {
      incidentId: inc.id,
      bucket: inc.bucket,
      allPrincipalsContained,
      artifactsToRemove,
      objectsToRestore,
      unrecoverableCount,
      maxDataLossWindowMs,
    };
  }

  /**
   * Executes 1-Click Restore (PRD §8):
   * 1. Confirm every principal contained & hold replication
   * 2. Remove attacker artifacts (.locked, encrypted versions, delete markers)
   * 3. Restore latest clean version from WORM vault under defyswarm-service
   * 4. Verify SHA-256 of every restored file against clean-version manifest
   */
  public executeOneClickRestore(incidentId: string): { incident: IncidentRecord; report: RestoreReport } {
    const startMs = Date.now();
    const inc = this.incidents.find((i) => i.id === incidentId);
    if (!inc) throw new Error(`Incident ${incidentId} not found.`);

    // Step 1: Ensure every correlated principal is contained and hold replication
    this.store.vaultReplicationPaused = true;
    for (const pid of inc.principals) {
      const p = this.store.principals.get(pid);
      if (p && p.status !== 'REVOKED') {
        p.status = 'REVOKED';
        p.quarantinePolicyAttached = true;
        p.revokedAt = new Date().toISOString();
      }
    }

    // Step 2: Remove .locked attacker artifacts
    let artifactsRemoved = 0;
    const bucketMap = this.store.objects.get(inc.bucket);
    if (bucketMap) {
      for (const key of Array.from(bucketMap.keys())) {
        if (key.endsWith('.locked')) {
          this.store.removeAttackerArtifact(inc.bucket, key);
          artifactsRemoved++;
        }
      }
    }

    // Step 3 & 4: Restore each affected object from WORM vault and verify SHA-256
    const perObjectResults: RestoreReport['perObjectResults'] = [];
    let filesRestored = 0;
    let filesUnrecoverable = 0;
    let verifiedMatchCount = 0;
    let maxDataLossWindowMs = 0;

    for (const obj of inc.affectedObjects) {
      const res = this.store.restoreKeyFromVault(inc.bucket, obj.key);
      if (res.restored) {
        filesRestored++;
        obj.restored = true;
        obj.verifiedSha256Match = res.matched;
        if (res.matched) verifiedMatchCount++;
        maxDataLossWindowMs = Math.max(maxDataLossWindowMs, res.dataLossWindowMs);
        perObjectResults.push({
          key: obj.key,
          expectedSha256: res.expectedSha256,
          restoredSha256: res.restoredSha256,
          matched: res.matched,
          dataLossWindowMs: res.dataLossWindowMs,
        });
      } else {
        filesUnrecoverable++;
      }
    }

    // Emit self-loop-protected restore telemetry event
    this.ingestEvent({
      serverTimestampMs: Date.now(),
      plane: 'data',
      apiOp: 'VaultRestoreBatch',
      bucket: inc.bucket,
      principalId: SERVICE_PRINCIPAL,
      httpStatus: 200,
    });

    // Resume clean replication & decay bucket risk score
    this.store.vaultReplicationPaused = false;
    this.bucketRiskScores.set(inc.bucket, { score: 0, updatedAtMs: Date.now() });

    const durationMs = Math.max(1, Date.now() - startMs);
    const restoreAccuracyPct =
      filesRestored > 0 ? Number(((verifiedMatchCount / filesRestored) * 100).toFixed(1)) : 100;

    const report: RestoreReport = {
      restoredAt: new Date().toISOString(),
      durationMs,
      filesRestored,
      artifactsRemoved,
      filesUnrecoverable,
      verifiedMatchCount,
      restoreAccuracyPct,
      maxDataLossWindowMs,
      perObjectResults,
    };

    inc.status = 'RESTORED';
    inc.restoreReport = report;
    inc.timeline.push({
      timestamp: report.restoredAt,
      label: '1-Click Vault Restore Verified',
      detail: `Restored ${filesRestored} object(s), removed ${artifactsRemoved} artifact(s). SHA-256 verification: ${verifiedMatchCount}/${filesRestored} (${restoreAccuracyPct}%). Max recovery gap: ${maxDataLossWindowMs} ms.`,
      severity: 'success',
    });

    this.onIncidentCallback?.(inc);
    return { incident: inc, report };
  }

  private recordEvent(event: TelemetryEvent, latencyMs: number) {
    this.events.unshift(event);
    if (this.events.length > 350) {
      this.events.length = 350;
    }
    this.ingestionLatenciesMs.push(Math.max(1, latencyMs));
    if (this.ingestionLatenciesMs.length > 200) {
      this.ingestionLatenciesMs.shift();
    }
    this.onEventCallback?.(event);
  }
}
