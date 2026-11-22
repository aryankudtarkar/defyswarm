/**
 * D9 adapter. This imports the product's detection engine and in-memory store
 * read-only and instantiates a fresh pair per trace. It never touches the live
 * DefySwarm singleton, the live ledger, or data/.
 */
import fs from 'node:fs';
import path from 'node:path';
import type { CanaryItem, PolicyConfig } from '../../src/shared/types.ts';
import { DetectionEngine } from '../../server/detectionEngine.ts';
import { DEFAULT_POLICY, validatePolicyYaml } from '../../server/policyEngine.ts';
import { LocalObjectStoreAdapter } from '../../server/storageAdapter.ts';
import { ADAPTIVE_CANARY_KEYS, ALLOWLISTED_PRINCIPALS, BUCKET } from '../generator/baseline.ts';
import type { Detector, DetectorOutput, DetectorRunContext, RecoveryModel } from '../types.ts';
import type { DetectorId } from '../config.ts';
import type { Alert, Event } from '../types.ts';

export type D9Variant = 'D9' | 'D9a' | 'D9b' | 'D9c' | 'D9d' | 'D9e' | 'D9f';

const BASE_EPOCH_MS = Date.UTC(2026, 0, 1, 0, 0, 0);

class EvalStore extends LocalObjectStoreAdapter {
  /** Bare in-memory store: no seeded file buffers, no live state. */
  public override seedDefaults(): void {
    this.buckets.clear();
    this.objects.clear();
    this.vaultManifest.clear();
    this.principals.clear();
    this.canaries.clear();
    this.vaultReplicationPaused = false;

    this.registerBucket({
      name: BUCKET,
      tags: { sensitivity: 'critical', env: 'ransomware-sim-only' },
      vault: 'vault-finance',
      versioningEnabled: true,
      objectLockEnabled: true,
      auditLoggingEnabled: true,
      adapter: 'local',
      objectCount: 0,
      canaryCount: 0,
    });
  }
}

function loadShippedPolicy(): PolicyConfig {
  try {
    const file = path.join(process.cwd(), 'data', 'policies.yaml');
    if (fs.existsSync(file)) {
      const result = validatePolicyYaml(fs.readFileSync(file, 'utf8'));
      if (result.valid && result.policy) return structuredClone(result.policy);
    }
  } catch {
    // Fall through to the product default.
  }
  return structuredClone(DEFAULT_POLICY);
}

function applyVariant(policy: PolicyConfig, variant: D9Variant): {
  policy: PolicyConfig;
  installCanaries: boolean;
  neutralizeEntropyMagic: boolean;
  neutralizeCanaryReads: boolean;
  recoveryCapable: boolean;
  note: string;
} {
  const clone = structuredClone(policy);
  clone.mode = 'active';
  let installCanaries = true;
  let neutralizeEntropyMagic = false;
  let neutralizeCanaryReads = false;
  let recoveryCapable = true;
  let note = 'full DefySwarm';

  switch (variant) {
    case 'D9':
      break;
    case 'D9a':
      installCanaries = false;
      note = 'ablation: adaptive canaries removed';
      break;
    case 'D9b':
      clone.hard_triggers = clone.hard_triggers.filter((t) => t === 'canary_write');
      note = 'ablation: control-plane sabotage triggers removed';
      break;
    case 'D9c':
      neutralizeEntropyMagic = true;
      note = 'ablation: entropy delta and magic-byte signals neutralised';
      break;
    case 'D9d':
      clone.detection.swarm.min_principals = 99;
      clone.detection.swarm.flagged_writes = 9999;
      note = 'ablation: cross-principal swarm correlation disabled';
      break;
    case 'D9e':
      clone.detection.score.watchlist = 200;
      neutralizeCanaryReads = true;
      note = 'ablation: canary-read / honey-credential watchlist escalation disabled';
      break;
    case 'D9f':
      recoveryCapable = false;
      note = 'ablation: vault recovery disabled (detection unchanged)';
      break;
  }
  return {
    policy: clone,
    installCanaries,
    neutralizeEntropyMagic,
    neutralizeCanaryReads,
    recoveryCapable,
    note,
  };
}

function canaryItem(key: string, index: number): CanaryItem {
  const now = new Date(BASE_EPOCH_MS).toISOString();
  return {
    id: `cnr-eval-${index}`,
    bucket: BUCKET,
    key,
    folderDepth: key.split('/').length - 1,
    fileType: key.split('.').pop()?.toUpperCase() ?? 'UNKNOWN',
    sizeBytes: 12_000,
    sha256: `eval-${index}`,
    createdAt: now,
    lastRefreshedAt: now,
    readTrips: 0,
    writeTrips: 0,
    generatedBy: 'deterministic',
    previewSnippet: 'Evaluation Lab adaptive canary.',
  };
}

function mapEvent(
  event: Event,
  options: {
    installCanaries: boolean;
    neutralizeEntropyMagic: boolean;
    neutralizeCanaryReads: boolean;
  },
): import('../../server/detectionEngine.ts').IncomingStorageEvent {
  const neutral = options.neutralizeEntropyMagic;
  const canaryVisible =
    options.installCanaries && !(options.neutralizeCanaryReads && event.operation === 'GetObject');
  return {
    serverTimestampMs: BASE_EPOCH_MS + event.timeMs,
    plane: event.plane,
    apiOp: event.operation,
    bucket: event.bucket,
    key: event.key,
    principalId: event.principal,
    httpStatus: event.httpStatus,
    entropy: neutral ? undefined : event.entropy,
    prevEntropy: neutral ? undefined : event.prevEntropy,
    magicValid: neutral ? true : event.magicValid,
    magicDetected: event.magicDetected,
    sseAlgorithm: event.sseAlgorithm,
    kmsKeyId: event.kmsKeyId,
    isCanary: canaryVisible ? event.isCanary : false,
    versioningTargetStatus: event.versioningTargetStatus,
    lifecycleExpiryDays: event.lifecycleExpiryDays,
    versionIdPurged: event.versionIdPurged,
  };
}

export function runD9Variant(context: DetectorRunContext, variant: D9Variant): DetectorOutput {
  const { policy, installCanaries, neutralizeEntropyMagic, neutralizeCanaryReads, note } =
    applyVariant(loadShippedPolicy(), variant);
  const store = new EvalStore();
  const engine = new DetectionEngine(store, () => policy);
  const alerts: Alert[] = [];

  const principals = Array.from(new Set(context.events.map((e) => e.principal)));
  for (const principal of principals) {
    store.registerPrincipal(
      principal,
      principal,
      principal === 'human-admin' ? 'human_admin' : 'service_account',
      ALLOWLISTED_PRINCIPALS.includes(principal),
    );
  }

  if (installCanaries) {
    ADAPTIVE_CANARY_KEYS.forEach((key, index) => {
      store.canaries.set(`${BUCKET}/${key}`, canaryItem(key, index));
    });
  }

  const realNow = Date.now;
  try {
    for (const event of context.events) {
      const virtualNow = BASE_EPOCH_MS + event.timeMs;
      Date.now = () => virtualNow;
      const telemetry = engine.ingestEvent(
        mapEvent(event, {
          installCanaries,
          neutralizeEntropyMagic,
          neutralizeCanaryReads,
        }),
      );
      const principalState = store.principals.get(event.principal);
      const contained =
        principalState?.status === 'REVOKED' ||
        principalState?.status === 'PENDING_APPROVAL' ||
        engine.incidents.some((incident) => incident.status === 'CONTAINED');
      if (telemetry.signals.length > 0) {
        alerts.push({
          seq: event.seq,
          timeMs: event.timeMs,
          detectorId: variant,
          principal: event.principal,
          reason: `${telemetry.signals.join(', ')}${note === 'full DefySwarm' ? '' : ` (${note})`}`,
          containmentRequested: contained,
        });
      }
    }
  } finally {
    Date.now = realNow;
  }

  return { alerts, notes: [note] };
}

function d9Recovery(variant: D9Variant): RecoveryModel {
  if (variant === 'D9f') {
    return {
      capable: false,
      mechanism: 'vault recovery disabled by ablation',
      recoveryPointLossMs: null,
    };
  }
  return {
    capable: true,
    mechanism: 'isolated WORM vault (clean-only replication)',
    // Product store measures 18–65 ms replication lag; use the midpoint.
    recoveryPointLossMs: 42,
  };
}

export function makeD9Detector(variant: D9Variant, name: string, models: string): Detector {
  return {
    id: variant as DetectorId,
    name,
    models,
    run(context: DetectorRunContext): DetectorOutput {
      return runD9Variant(context, variant);
    },
    recovery(): RecoveryModel {
      return d9Recovery(variant);
    },
  };
}

export const d9 = makeD9Detector('D9', 'DefySwarm full', 'The shipped product detection engine with all four signals');
export const d9a = makeD9Detector('D9a', 'DefySwarm minus canaries', 'Ablation: no adaptive canaries');
export const d9b = makeD9Detector('D9b', 'DefySwarm minus sabotage triggers', 'Ablation: no control-plane sabotage hard triggers');
export const d9c = makeD9Detector('D9c', 'DefySwarm minus entropy/magic', 'Ablation: no entropy-delta or magic-byte signals');
export const d9d = makeD9Detector('D9d', 'DefySwarm minus swarm correlation', 'Ablation: no cross-principal swarm correlation');
export const d9e = makeD9Detector('D9e', 'DefySwarm minus honey credentials', 'Ablation: no canary-read watchlist escalation');
export const d9f = makeD9Detector('D9f', 'DefySwarm minus vault', 'Ablation: no vault recovery');
