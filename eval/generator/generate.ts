import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type {
  AttackMethod,
  AttackSpeed,
  Family,
  ReconMode,
  SabotageMode,
} from '../config.ts';
import { DEFAULT_GENERATION_SEED, GENERATED_TRACES_DIR, MANIFEST_PATH, TRACES_DIR } from '../config.ts';
import { Prng, hashString } from '../prng.ts';
import type { Event, GroundTruth, TraceManifest, TraceManifestEntry, TraceRecord } from '../types.ts';
import {
  ADAPTIVE_CANARY_KEYS,
  ALLOWLISTED_PRINCIPALS,
  ATTACKER_POOL,
  BASELINE_FILES,
  BUCKET,
  OBVIOUS_CANARY_KEYS,
  baseEntropyFor,
  baseSizeFor,
  magicFor,
  makeEvent,
  typeFromKey,
} from './baseline.ts';
import { loadCalibrationProfile, type CalibrationProfile } from './calibration.ts';

export const GENERATOR_VERSION = '1.0.0';

type PartialEvent = Omit<Event, 'seq' | 'timeMs' | 'bucket' | 'plane' | 'channel' | 'httpStatus'> & {
  channel?: Event['channel'];
  httpStatus?: number;
  plane?: Event['plane'];
  bucket?: string;
};

interface PendingEvent {
  timeMs: number;
  attack: boolean;
  fileId: string | null;
  event: Omit<Event, 'seq' | 'timeMs'>;
}

class TraceBuilder {
  private pending: PendingEvent[] = [];

  add(timeMs: number, attack: boolean, fileId: string | null, partial: PartialEvent): void {
    const full = makeEvent(0, Math.max(0, Math.round(timeMs)), partial);
    const { seq: _seq, timeMs: _timeMs, ...rest } = full;
    this.pending.push({ timeMs: Math.max(0, Math.round(timeMs)), attack, fileId, event: rest });
  }

  get length(): number {
    return this.pending.length;
  }

  finalize(meta: {
    traceId: string;
    family: Family;
    kind: string;
    seed: number;
    split: 'tuning' | 'heldout';
    totalRealFiles: number;
    scenario: GroundTruth['scenario'];
    notes?: string;
  }): TraceRecord {
    const ordered = this.pending
      .map((p, index) => ({ ...p, index }))
      .sort((a, b) => a.timeMs - b.timeMs || a.index - b.index);
    const events: Event[] = ordered.map((p, seq) => ({ ...p.event, seq, timeMs: p.timeMs }));
    const eventAttackFlags = ordered.map((p) => p.attack);
    const eventFileIds = ordered.map((p) => p.fileId);
    const attackEvents = ordered.filter((p) => p.attack);
    const attackFiles = Array.from(
      new Set(attackEvents.map((p) => p.fileId).filter((v): v is string => Boolean(v))),
    ).sort();
    const attackerPrincipals = Array.from(
      new Set(attackEvents.map((p) => p.event.principal)),
    ).sort();
    const attackStartMs = attackEvents.length > 0 ? Math.min(...attackEvents.map((p) => p.timeMs)) : null;
    const durationMs = Math.max(1000, ...ordered.map((p) => p.timeMs)) + 1000;
    const benignEventCount = ordered.filter((p) => !p.attack).length;

    const groundTruth: GroundTruth = {
      traceId: meta.traceId,
      family: meta.family,
      kind: meta.kind,
      seed: meta.seed,
      split: meta.split,
      bucket: BUCKET,
      durationMs,
      attackStartMs,
      attackerPrincipals,
      eventAttackFlags,
      eventFileIds,
      attackFiles,
      totalRealFiles: meta.totalRealFiles,
      benignEventCount,
      scenario: meta.scenario,
      obviousCanaryKeys: OBVIOUS_CANARY_KEYS,
      adaptiveCanaryKeys: ADAPTIVE_CANARY_KEYS,
      notes: meta.notes,
    };
    return { groundTruth, events };
  }
}

interface BenignResult {
  realFilesAdded: number;
}

function benignEntropy(type: ReturnType<typeof typeFromKey>, prng: Prng, calibration: CalibrationProfile): number {
  const base = {
    pdf: 5.2,
    docx: 5.6,
    xlsx: 5.4,
    csv: 4.8,
    txt: 4.5,
    png: 7.4,
    jpg: 7.3,
    zip: 7.6,
    gz: 7.7,
    log: 4.9,
  }[type];
  const value = base + prng.float(-0.25, 0.25) + calibration.benignEntropyShift;
  return Number(Math.max(0.4, Math.min(7.94, value)).toFixed(3));
}

function encryptedEntropy(prng: Prng): number {
  return Number((7.88 + prng.float(0, 0.1)).toFixed(3));
}

function scaledSize(key: string, prng: Prng, calibration: CalibrationProfile): number {
  return Math.max(512, Math.round(baseSizeFor(key) * calibration.sizeScale * prng.float(0.8, 1.2)));
}

function gap(ms: number, calibration: CalibrationProfile): number {
  return Math.max(10, Math.round(ms * calibration.interArrivalScale));
}

function addBenignUpload(
  builder: TraceBuilder,
  kind: string,
  count: number,
  durationMs: number,
  prng: Prng,
  calibration: CalibrationProfile,
  options: {
    types: Array<ReturnType<typeof typeFromKey>>;
    principal: string;
    channel?: Event['channel'];
    prefix: string;
  },
): BenignResult {
  const step = durationMs / Math.max(1, count);
  for (let i = 0; i < count; i++) {
    const type = options.types[i % options.types.length];
    const key = `${options.prefix}/${String(i + 1).padStart(5, '0')}.${type === 'log' ? 'txt' : type}`;
    const entropy = benignEntropy(type, prng, calibration);
    builder.add(i * step, false, null, {
      principal: options.principal,
      operation: 'PutObject',
      key,
      sizeBytes: scaledSize(key, prng, calibration),
      entropy,
      magicValid: true,
      magicDetected: magicFor(type),
      channel: options.channel ?? 'api',
    });
  }
  return { realFilesAdded: count };
}

function addBenignBackground(
  builder: TraceBuilder,
  count: number,
  durationMs: number,
  prng: Prng,
  calibration: CalibrationProfile,
): BenignResult {
  const step = durationMs / Math.max(1, count);
  let realFilesAdded = 0;
  const baselineKeys = BASELINE_FILES.map((f) => f.key);
  const compressedTypes: Array<ReturnType<typeof typeFromKey>> = ['jpg', 'png', 'zip', 'gz', 'docx'];
  for (let i = 0; i < count; i++) {
    const time = i * step;
    const roll = prng.next();
    if (roll < 0.4) {
      const key = `uploads/2026/mixed/batch_${String(i).padStart(5, '0')}.${prng.pick(['pdf', 'docx', 'csv', 'xlsx'])}`;
      const type = typeFromKey(key);
      builder.add(time, false, null, {
        principal: prng.pick(['ci-deployer', 'analyst-jdoe', 'finance-user']),
        operation: 'PutObject',
        key,
        sizeBytes: scaledSize(key, prng, calibration),
        entropy: benignEntropy(type, prng, calibration),
        magicValid: true,
        magicDetected: magicFor(type),
      });
      realFilesAdded++;
    } else if (roll < 0.6) {
      const key = `photos/import/2026/img_${String(i).padStart(5, '0')}.jpg`;
      builder.add(time, false, null, {
        principal: 'photo-sync',
        operation: 'PutObject',
        key,
        sizeBytes: scaledSize(key, prng, calibration),
        entropy: benignEntropy('jpg', prng, calibration),
        magicValid: true,
        magicDetected: 'JPEG',
        channel: 'sync',
      });
      realFilesAdded++;
    } else if (roll < 0.78) {
      const key = `logs/2026/app_${i % 4}.log.gz`;
      const prev = 7.5 + prng.float(-0.05, 0.05);
      builder.add(time, false, null, {
        principal: 'app-log-writer',
        operation: 'PutObject',
        key,
        sizeBytes: scaledSize(key, prng, calibration),
        entropy: Number((prev + prng.float(-0.03, 0.03)).toFixed(3)),
        prevEntropy: Number(prev.toFixed(3)),
        magicValid: true,
        magicDetected: 'GZIP',
      });
    } else if (roll < 0.9) {
      const key = prng.pick(baselineKeys);
      builder.add(time, false, null, {
        principal: 'backup-agent',
        operation: 'GetObject',
        key,
        isCanary: ADAPTIVE_CANARY_KEYS.includes(key) || OBVIOUS_CANARY_KEYS.includes(key),
        sizeBytes: baseSizeFor(key),
        channel: 'api',
      });
    } else {
      const key = `unzipped/2026/bundle_${String(i).padStart(5, '0')}.${prng.pick(['zip', 'gz'])}`;
      const type = typeFromKey(key);
      builder.add(time, false, null, {
        principal: 'dev-workstation',
        operation: 'PutObject',
        key,
        sizeBytes: scaledSize(key, prng, calibration),
        entropy: benignEntropy(type, prng, calibration),
        magicValid: true,
        magicDetected: magicFor(type),
      });
      realFilesAdded++;
    }
  }
  return { realFilesAdded };
}

function addBenignKind(
  builder: TraceBuilder,
  kind: string,
  prng: Prng,
  calibration: CalibrationProfile,
): BenignResult {
  switch (kind) {
    case 'benign_upload_50':
      return addBenignUpload(builder, kind, 50, 60_000, prng, calibration, {
        types: ['pdf', 'jpg', 'docx', 'csv', 'txt'],
        principal: 'ci-deployer',
        prefix: 'uploads/2026/q3/batch',
      });
    case 'benign_upload_5000_compressed_media':
      return addBenignUpload(builder, kind, 5000, 600_000, prng, calibration, {
        types: ['jpg', 'png', 'zip', 'docx', 'gz'],
        principal: 'photo-sync',
        prefix: 'uploads/2026/bulk/media',
        channel: 'sync',
      });
    case 'benign_bulk_rename_move': {
      const keys = BASELINE_FILES.map((f) => f.key).slice(0, 80);
      for (let i = 0; i < keys.length; i++) {
        const key = keys[i];
        const newKey = key.replace(/(\.[^.]+)$/, '_archived$1');
        builder.add(i * gap(600, calibration), false, null, {
          principal: 'ci-deployer',
          operation: 'CopyObject',
          key: newKey,
          sourceKey: key,
          sizeBytes: baseSizeFor(key),
          entropy: baseEntropyFor(key),
          magicValid: true,
          magicDetected: magicFor(typeFromKey(key)),
        });
        builder.add(i * gap(600, calibration) + 30, false, null, {
          principal: 'ci-deployer',
          operation: 'DeleteObject',
          key,
        });
      }
      return { realFilesAdded: 0 };
    }
    case 'benign_nightly_backup': {
      const keys = [...BASELINE_FILES.map((f) => f.key), ...ADAPTIVE_CANARY_KEYS].slice(0, 60);
      for (let i = 0; i < keys.length; i++) {
        const key = keys[i];
        builder.add(i * gap(800, calibration), false, null, {
          principal: 'backup-agent',
          operation: 'GetObject',
          key,
          isCanary: ADAPTIVE_CANARY_KEYS.includes(key),
          sizeBytes: baseSizeFor(key),
        });
      }
      return { realFilesAdded: 0 };
    }
    case 'benign_av_dlp_scan': {
      const keys = [
        ...BASELINE_FILES.map((f) => f.key),
        ...ADAPTIVE_CANARY_KEYS,
        ...OBVIOUS_CANARY_KEYS,
      ];
      for (let i = 0; i < 200; i++) {
        const key = keys[i % keys.length];
        builder.add(i * gap(250, calibration), false, null, {
          principal: 'dlp-scanner',
          operation: 'GetObject',
          key,
          isCanary: ADAPTIVE_CANARY_KEYS.includes(key) || OBVIOUS_CANARY_KEYS.includes(key),
          sizeBytes: baseSizeFor(key),
        });
      }
      return { realFilesAdded: 0 };
    }
    case 'benign_ci_deploy_overwrite': {
      for (let i = 0; i < 120; i++) {
        const key = BASELINE_FILES[i % BASELINE_FILES.length].key;
        const type = typeFromKey(key);
        builder.add(i * gap(400, calibration), false, null, {
          principal: 'ci-deployer',
          operation: 'PutObject',
          key,
          sizeBytes: scaledSize(key, prng, calibration),
          entropy: benignEntropy(type, prng, calibration),
          prevEntropy: baseEntropyFor(key),
          magicValid: true,
          magicDetected: magicFor(type),
        });
      }
      return { realFilesAdded: 0 };
    }
    case 'benign_photo_import': {
      return addBenignUpload(builder, kind, 150, 90_000, prng, calibration, {
        types: ['jpg', 'png', 'jpg', 'png'],
        principal: 'photo-sync',
        prefix: 'photos/import/2026',
        channel: 'sync',
      });
    }
    case 'benign_dev_unzip_archives': {
      return addBenignUpload(builder, kind, 80, 80_000, prng, calibration, {
        types: ['zip', 'gz', 'docx'],
        principal: 'dev-workstation',
        prefix: 'unzipped/2026/release',
      });
    }
    case 'benign_app_compressed_logs': {
      for (let i = 0; i < 200; i++) {
        const key = `logs/2026/app_${i % 4}.log.gz`;
        const prev = 7.5 + prng.float(-0.05, 0.05);
        builder.add(i * gap(250, calibration), false, null, {
          principal: 'app-log-writer',
          operation: 'PutObject',
          key,
          sizeBytes: scaledSize(key, prng, calibration),
          entropy: Number((prev + prng.float(-0.03, 0.03)).toFixed(3)),
          prevEntropy: Number(prev.toFixed(3)),
          magicValid: true,
          magicDetected: 'GZIP',
        });
      }
      return { realFilesAdded: 0 };
    }
    default:
      throw new Error(`Unknown benign kind: ${kind}`);
  }
}

interface AttackSpec {
  speed: AttackSpeed;
  principals: number;
  method: AttackMethod;
  recon: ReconMode;
  sabotage: SabotageMode;
  targetCount: number;
  startMs: number;
  channel?: Event['channel'];
}

function attackersFor(principals: number, family: Family): string[] {
  if (principals <= 1) return ['svc-billing-etl'];
  const pool = family === 'swarm' ? ATTACKER_POOL.slice(1) : ATTACKER_POOL.slice(1);
  return pool.slice(0, Math.max(1, Math.min(principals, pool.length)));
}

function attackGap(speed: AttackSpeed, calibration: CalibrationProfile): number {
  if (speed === 'fast') return gap(180, calibration);
  if (speed === 'medium') return gap(1500, calibration);
  return gap(8000, calibration);
}

function addAttack(
  builder: TraceBuilder,
  family: Family,
  spec: AttackSpec,
  times: number[],
  prng: Prng,
  calibration: CalibrationProfile,
): { attackFiles: string[] } {
  const attackers = attackersFor(spec.principals, family);
  const targets = prng.shuffle(BASELINE_FILES.map((f) => f.key)).slice(0, Math.max(1, spec.targetCount));
  const attackFiles: string[] = [];
  const startMs = times.length > 0 ? Math.min(...times) : spec.startMs;

  // Recon. Naive attackers touch obvious and adaptive canaries; canary-aware
  // attackers avoid every decoy. Recon is part of the attack timeline.
  if (spec.recon === 'naive') {
    const canaries = prng.sample([...ADAPTIVE_CANARY_KEYS, ...OBVIOUS_CANARY_KEYS], 3);
    canaries.forEach((key, i) => {
      builder.add(Math.max(0, startMs - 500 + i * 150), true, null, {
        principal: attackers[i % attackers.length],
        operation: 'GetObject',
        key,
        isCanary: true,
        sizeBytes: baseSizeFor(key),
      });
    });
  }

  // Recovery sabotage.
  if (spec.sabotage === 'suspend_versioning') {
    builder.add(startMs, true, null, {
      principal: attackers[0],
      operation: 'PutBucketVersioning',
      plane: 'control',
      versioningTargetStatus: 'Suspended',
    });
  } else if (spec.sabotage === 'purge_versions') {
    const purgeTargets = prng.sample(targets, Math.min(3, targets.length));
    purgeTargets.forEach((key, i) => {
      builder.add(startMs + i * 20, true, null, {
        principal: attackers[0],
        operation: 'DeleteObjectVersion',
        plane: 'control',
        key,
        versionIdPurged: `v-${i}-purged`,
      });
    });
  } else if (spec.sabotage === 'lifecycle_1d') {
    builder.add(startMs, true, null, {
      principal: attackers[0],
      operation: 'PutBucketLifecycleConfiguration',
      plane: 'control',
      lifecycleExpiryDays: 1,
    });
  }

  times.forEach((time, i) => {
    const key = targets[i % targets.length];
    const principal = attackers[i % attackers.length];
    const type = typeFromKey(key);
    const baseEntropy = baseEntropyFor(key);
    const size = scaledSize(key, prng, calibration);
    attackFiles.push(key);

    switch (spec.method) {
      case 'aes_overwrite':
        builder.add(time, true, key, {
          principal,
          operation: 'PutObject',
          key,
          sizeBytes: size,
          entropy: encryptedEntropy(prng),
          prevEntropy: baseEntropy,
          magicValid: false,
          magicDetected: 'UNKNOWN',
          channel: spec.channel ?? 'api',
        });
        break;
      case 'rename_locked':
        builder.add(time, true, key, {
          principal,
          operation: 'PutObject',
          key: `${key}.locked`,
          sizeBytes: size,
          entropy: encryptedEntropy(prng),
          prevEntropy: baseEntropy,
          magicValid: false,
          magicDetected: 'UNKNOWN',
          channel: spec.channel ?? 'api',
        });
        builder.add(time + 25, true, key, {
          principal,
          operation: 'DeleteObject',
          key,
          channel: spec.channel ?? 'api',
        });
        break;
      case 'delete_rewrite':
        builder.add(time, true, key, {
          principal,
          operation: 'DeleteObject',
          key,
          channel: spec.channel ?? 'api',
        });
        builder.add(time + 25, true, key, {
          principal,
          operation: 'PutObject',
          key,
          sizeBytes: size,
          entropy: encryptedEntropy(prng),
          prevEntropy: baseEntropy,
          magicValid: false,
          magicDetected: 'UNKNOWN',
          channel: spec.channel ?? 'api',
        });
        break;
      case 'ssec_copy':
        builder.add(time, true, key, {
          principal,
          operation: 'CopyObject',
          key,
          sourceKey: key,
          sizeBytes: size,
          entropy: baseEntropy,
          prevEntropy: baseEntropy,
          magicValid: true,
          magicDetected: magicFor(type),
          sseAlgorithm: 'AES256-SSE-C',
          channel: spec.channel ?? 'api',
        });
        break;
      case 'external_kms':
        builder.add(time, true, key, {
          principal,
          operation: 'CopyObject',
          key,
          sourceKey: key,
          sizeBytes: size,
          entropy: baseEntropy,
          prevEntropy: baseEntropy,
          magicValid: true,
          magicDetected: magicFor(type),
          kmsKeyId: 'arn:aws:kms:us-east-1:999988887777:key/untrusted-external-key',
          channel: spec.channel ?? 'api',
        });
        break;
      default:
        throw new Error(`Unknown method ${spec.method}`);
    }
  });

  return { attackFiles: Array.from(new Set(attackFiles)) };
}

export interface TraceSpec {
  family: Family;
  kind: string;
  seed: number;
  benignKind?: string;
  attack?: AttackSpec;
  mixed?: {
    attackCount: number;
    benignCount: number;
    ratio: number;
    durationMs: number;
  };
}

export function buildSpecs(generationSeed: number): TraceSpec[] {
  const specs: TraceSpec[] = [];
  const benignKinds = [
    'benign_upload_50',
    'benign_upload_5000_compressed_media',
    'benign_bulk_rename_move',
    'benign_nightly_backup',
    'benign_av_dlp_scan',
    'benign_ci_deploy_overwrite',
    'benign_photo_import',
    'benign_dev_unzip_archives',
    'benign_app_compressed_logs',
  ];
  let index = 0;
  for (const kind of benignKinds) {
    for (let i = 0; i < 7; i++) {
      specs.push({
        family: 'benign',
        kind,
        seed: generationSeed + index * 7919 + 11,
        benignKind: kind,
      });
      index++;
    }
  }

  const methods: AttackMethod[] = [
    'aes_overwrite',
    'rename_locked',
    'delete_rewrite',
    'ssec_copy',
    'external_kms',
  ];
  const speeds: AttackSpeed[] = ['slow', 'medium', 'fast'];
  const principalCounts = [1, 2, 4];
  for (const method of methods) {
    for (const speed of speeds) {
      for (const principals of principalCounts) {
        const targetCount = speed === 'fast' ? 24 : speed === 'medium' ? 18 : 12;
        specs.push({
          family: 'ransomware',
          kind: `ransomware_${method}_${speed}_p${principals}`,
          seed: generationSeed + index * 7919 + 11,
          attack: {
            speed,
            principals,
            method,
            recon: index % 2 === 0 ? 'naive' : 'canary_aware',
            sabotage: 'none',
            targetCount,
            startMs: 1200 + (index % 5) * 400,
            channel: index % 7 === 0 ? 'sync' : 'api',
          },
        });
        index++;
      }
    }
  }
  for (let i = 0; i < 25; i++) {
    const method = methods[i % methods.length];
    const speed = speeds[(i + 1) % speeds.length];
    const principals = [1, 2, 4, 8][i % 4];
    const sabotage = (['none', 'suspend_versioning', 'purge_versions', 'lifecycle_1d'] as SabotageMode[])[
      i % 4
    ];
    specs.push({
      family: 'ransomware',
      kind: `ransomware_variant_${method}_${speed}_p${principals}_${sabotage}`,
      seed: generationSeed + index * 7919 + 11,
      attack: {
        speed,
        principals,
        method,
        recon: i % 2 === 0 ? 'naive' : 'canary_aware',
        sabotage,
        targetCount: speed === 'fast' ? 24 : speed === 'medium' ? 18 : 12,
        startMs: 1500 + (i % 4) * 500,
        channel: i % 6 === 0 ? 'sync' : 'api',
      },
    });
    index++;
  }

  const swarmMethods: AttackMethod[] = ['external_kms', 'aes_overwrite', 'ssec_copy'];
  const swarmPrincipals = [2, 4, 8];
  for (const principals of swarmPrincipals) {
    for (const method of swarmMethods) {
      for (const speed of ['slow', 'medium'] as AttackSpeed[]) {
        for (const sabotage of ['none', 'suspend_versioning'] as SabotageMode[]) {
          specs.push({
            family: 'swarm',
            kind: `swarm_${method}_${speed}_p${principals}_${sabotage}`,
            seed: generationSeed + index * 7919 + 11,
            attack: {
              speed,
              principals,
              method,
              recon: 'canary_aware',
              sabotage,
              targetCount: principals === 8 ? 24 : principals === 4 ? 18 : 12,
              startMs: 2000 + (index % 3) * 700,
            },
          });
          index++;
        }
      }
    }
  }
  for (let i = 0; i < 6; i++) {
    specs.push({
      family: 'swarm',
      kind: `swarm_variant_external_kms_slow_p8_${i}`,
      seed: generationSeed + index * 7919 + 11,
      attack: {
        speed: 'slow',
        principals: 8,
        method: 'external_kms',
        recon: i % 2 === 0 ? 'naive' : 'canary_aware',
        sabotage: i % 3 === 0 ? 'suspend_versioning' : 'none',
        targetCount: 24,
        startMs: 2500 + i * 300,
      },
    });
    index++;
  }

  for (const ratio of [5, 20, 100]) {
    for (const method of ['aes_overwrite', 'rename_locked', 'external_kms'] as AttackMethod[]) {
      for (const speed of ['medium', 'fast'] as AttackSpeed[]) {
        for (const principals of [1, 2]) {
          const attackCount = 20;
          specs.push({
            family: 'mixed',
            kind: `mixed_${method}_${speed}_p${principals}_1to${ratio}`,
            seed: generationSeed + index * 7919 + 11,
            mixed: {
              attackCount,
              benignCount: attackCount * ratio,
              ratio,
              durationMs: Math.max(120_000, attackCount * ratio * 250),
            },
            attack: {
              speed,
              principals,
              method,
              recon: index % 3 === 0 ? 'naive' : 'canary_aware',
              sabotage: 'none',
              targetCount: attackCount,
              startMs: 0,
              channel: index % 5 === 0 ? 'sync' : 'api',
            },
          });
          index++;
        }
      }
    }
  }

  return specs.slice(0, 210);
}

function splitFor(traceId: string): 'tuning' | 'heldout' {
  return hashString(traceId) % 100 < 30 ? 'tuning' : 'heldout';
}

export function generateTrace(spec: TraceSpec, calibration = loadCalibrationProfile()): TraceRecord {
  const prng = new Prng(spec.seed);
  const builder = new TraceBuilder();
  let totalRealFiles = BASELINE_FILES.length;
  let scenario: GroundTruth['scenario'] = {};

  if (spec.family === 'benign' && spec.benignKind) {
    const result = addBenignKind(builder, spec.benignKind, prng, calibration);
    totalRealFiles += result.realFilesAdded;
    scenario = { benignKind: spec.benignKind };
  } else if (spec.family === 'mixed' && spec.mixed && spec.attack) {
    const mixed = spec.mixed;
    const benign = addBenignBackground(builder, mixed.benignCount, mixed.durationMs, prng, calibration);
    totalRealFiles += benign.realFilesAdded;
    const start = mixed.durationMs * 0.2;
    const end = mixed.durationMs * 0.9;
    const times = Array.from({ length: mixed.attackCount }, (_, i) =>
      Math.round(start + ((end - start) * i) / Math.max(1, mixed.attackCount - 1)),
    );
    addAttack(builder, spec.family, spec.attack, times, prng, calibration);
    scenario = {
      speed: spec.attack.speed,
      principals: spec.attack.principals,
      method: spec.attack.method,
      recon: spec.attack.recon,
      sabotage: spec.attack.sabotage,
      attackToNoiseRatio: spec.mixed.ratio,
      channel: spec.attack.channel,
    };
  } else if (spec.attack) {
    const attackStart = spec.attack.startMs;
    const gapMs = attackGap(spec.attack.speed, calibration);
    const times = Array.from({ length: spec.attack.targetCount }, (_, i) => attackStart + 250 + i * gapMs);
    addAttack(builder, spec.family, spec.attack, times, prng, calibration);
    scenario = {
      speed: spec.attack.speed,
      principals: spec.attack.principals,
      method: spec.attack.method,
      recon: spec.attack.recon,
      sabotage: spec.attack.sabotage,
      channel: spec.attack.channel,
    };
  }

  const traceId = `tr-${spec.family}-${String(spec.seed).slice(-8)}-${hashString(spec.kind).toString(16).slice(0, 6)}`;
  return builder.finalize({
    traceId,
    family: spec.family,
    kind: spec.kind,
    seed: spec.seed,
    split: splitFor(traceId),
    totalRealFiles,
    scenario,
  });
}

export function writeGeneratedTraces(
  generationSeed = DEFAULT_GENERATION_SEED,
  options: { outDir?: string; manifestPath?: string } = {},
): TraceManifest {
  const outDir = options.outDir ?? GENERATED_TRACES_DIR;
  const manifestPath = options.manifestPath ?? MANIFEST_PATH;
  fs.mkdirSync(outDir, { recursive: true });
  fs.mkdirSync(path.dirname(manifestPath), { recursive: true });

  const calibration = loadCalibrationProfile();
  const specs = buildSpecs(generationSeed);
  const traces = specs.map((spec) => generateTrace(spec, calibration));

  // Guarantee both splits exist in every family without introducing overlap.
  const families: Family[] = ['benign', 'ransomware', 'swarm', 'mixed'];
  for (const family of families) {
    const members = traces.filter((t) => t.groundTruth.family === family);
    if (!members.some((t) => t.groundTruth.split === 'tuning') && members.length > 0) {
      members[0].groundTruth.split = 'tuning';
    }
    if (!members.some((t) => t.groundTruth.split === 'heldout') && members.length > 1) {
      members[1].groundTruth.split = 'heldout';
    }
  }

  const entries: TraceManifestEntry[] = [];
  for (const trace of traces) {
    const lines = [
      JSON.stringify({ type: 'meta', groundTruth: trace.groundTruth }),
      ...trace.events.map((event) => JSON.stringify({ type: 'event', event })),
    ];
    const content = `${lines.join('\n')}\n`;
    const fileName = `${trace.groundTruth.traceId}.jsonl`;
    const filePath = path.join(outDir, fileName);
    fs.writeFileSync(filePath, content, 'utf8');
    entries.push({
      traceId: trace.groundTruth.traceId,
      family: trace.groundTruth.family,
      kind: trace.groundTruth.kind,
      seed: trace.groundTruth.seed,
      split: trace.groundTruth.split,
      path: path.relative(TRACES_DIR, filePath),
      eventCount: trace.events.length,
      sha256: crypto.createHash('sha256').update(content).digest('hex'),
    });
  }

  const familyCounts = families.reduce(
    (acc, family) => {
      acc[family] = entries.filter((e) => e.family === family).length;
      return acc;
    },
    {} as Record<Family, number>,
  );

  const manifest: TraceManifest = {
    generatedAt: new Date().toISOString(),
    generationSeed,
    generatorVersion: GENERATOR_VERSION,
    totalTraces: entries.length,
    tuningTraces: entries.filter((e) => e.split === 'tuning').length,
    heldoutTraces: entries.filter((e) => e.split === 'heldout').length,
    families: familyCounts,
    traces: entries,
  };
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');
  return manifest;
}

export function readTrace(manifestEntry: TraceManifestEntry): TraceRecord {
  const filePath = path.join(TRACES_DIR, manifestEntry.path);
  const lines = fs.readFileSync(filePath, 'utf8').split('\n').filter(Boolean);
  const meta = JSON.parse(lines[0]) as { type: 'meta'; groundTruth: GroundTruth };
  const events = lines.slice(1).map((line) => (JSON.parse(line) as { event: Event }).event);
  return { groundTruth: meta.groundTruth, events };
}
