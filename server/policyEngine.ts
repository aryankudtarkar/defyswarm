import fs from 'fs';
import path from 'path';
import * as yaml from 'js-yaml';
import type { PolicyConfig } from '../src/shared/types.ts';

const DATA_DIR = path.resolve(process.cwd(), 'data');
const POLICY_FILE = path.join(DATA_DIR, 'policies.yaml');

export const DEFAULT_POLICY: PolicyConfig = {
  version: 1,
  mode: 'active',
  buckets: [
    {
      name: 'finance-prod',
      tags: { sensitivity: 'critical', env: 'ransomware-sim-only' },
      vault: 'vault-finance',
    },
    {
      name: 'analytics-sandbox',
      tags: { sensitivity: 'sandbox', env: 'ransomware-sim-only' },
      vault: 'vault-finance',
    },
    {
      name: 'legal-archives-prod',
      tags: { sensitivity: 'critical', env: 'production' },
      vault: 'vault-finance',
    },
  ],
  tiers: {
    critical: { response: 'auto-revoke' },
    sandbox: { response: 'alert-only' },
  },
  allowlist: {
    principals: ['ci-deployer', 'backup-agent', 'dlp-scanner'],
    kms_keys: ['arn:aws:kms:us-east-1:111122223333:key/trusted-kms-key-id', 'trusted-kms-key-id'],
  },
  detection: {
    entropy: { sample_bytes: 65536, delta_threshold: 1.5 },
    burst: { window_seconds: 10, pairs: 5 },
    swarm: { window_seconds: 60, min_principals: 2, flagged_writes: 12 },
    score: { watchlist: 45, contain: 100 },
  },
  canary: {
    count: 10,
    refresh_hours: 24,
  },
  hard_triggers: [
    'canary_write',
    'versioning_suspend',
    'version_purge',
    'lifecycle_expiry_1d_or_less',
    'object_lock_tamper',
  ],
  actions: {
    on_p0: ['disable_key', 'attach_deny_all', 'alert', 'pause_replication'],
  },
};

const ALLOWED_TOP_KEYS = new Set([
  'version',
  'mode',
  'buckets',
  'tiers',
  'allowlist',
  'detection',
  'canary',
  'hard_triggers',
  'actions',
]);

const ALLOWED_HARD_TRIGGERS = new Set([
  'canary_write',
  'versioning_suspend',
  'version_purge',
  'lifecycle_expiry_1d_or_less',
  'object_lock_tamper',
  'audit_log_tamper',
]);

const ALLOWED_ACTIONS = new Set([
  'disable_key',
  'attach_deny_all',
  'alert',
  'pause_replication',
]);

function checkAllowedKeys(obj: Record<string, unknown>, allowed: Set<string>, prefix: string, errors: string[]) {
  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) {
      errors.push(`Unknown key "${prefix ? `${prefix}.` : ''}${key}" rejected by strict policy schema.`);
    }
  }
}

export interface PolicyValidationResult {
  valid: boolean;
  policy?: PolicyConfig;
  errors: string[];
}

export function validatePolicyYaml(rawYaml: string): PolicyValidationResult {
  const errors: string[] = [];
  let parsed: unknown;
  try {
    parsed = yaml.load(rawYaml, { schema: yaml.JSON_SCHEMA });
  } catch (err) {
    return {
      valid: false,
      errors: [`YAML syntax error: ${err instanceof Error ? err.message : String(err)}`],
    };
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { valid: false, errors: ['Root policy document must be a YAML mapping object.'] };
  }

  const doc = parsed as Record<string, unknown>;
  checkAllowedKeys(doc, ALLOWED_TOP_KEYS, '', errors);

  if (doc.version !== 1) {
    errors.push('Field "version" must be integer 1.');
  }
  if (doc.mode !== 'active' && doc.mode !== 'dry-run') {
    errors.push('Field "mode" must be either "active" or "dry-run".');
  }

  // buckets
  if (!Array.isArray(doc.buckets) || doc.buckets.length === 0) {
    errors.push('Field "buckets" must be a non-empty array.');
  } else {
    doc.buckets.forEach((b, idx) => {
      if (!b || typeof b !== 'object' || Array.isArray(b)) {
        errors.push(`buckets[${idx}] must be an object.`);
        return;
      }
      const bObj = b as Record<string, unknown>;
      checkAllowedKeys(bObj, new Set(['name', 'tags', 'vault']), `buckets[${idx}]`, errors);
      if (typeof bObj.name !== 'string' || !bObj.name.trim()) {
        errors.push(`buckets[${idx}].name must be a non-empty string.`);
      }
      if (typeof bObj.vault !== 'string' || !bObj.vault.trim()) {
        errors.push(`buckets[${idx}].vault must be a non-empty string.`);
      }
      if (!bObj.tags || typeof bObj.tags !== 'object' || Array.isArray(bObj.tags)) {
        errors.push(`buckets[${idx}].tags must be a key/value map.`);
      }
    });
  }

  // tiers
  if (!doc.tiers || typeof doc.tiers !== 'object' || Array.isArray(doc.tiers)) {
    errors.push('Field "tiers" is required.');
  } else {
    const tiers = doc.tiers as Record<string, unknown>;
    checkAllowedKeys(tiers, new Set(['critical', 'sandbox']), 'tiers', errors);
    for (const tierName of ['critical', 'sandbox']) {
      const t = tiers[tierName] as Record<string, unknown> | undefined;
      if (!t || typeof t !== 'object') {
        errors.push(`tiers.${tierName} is required.`);
      } else {
        checkAllowedKeys(t, new Set(['response']), `tiers.${tierName}`, errors);
        if (t.response !== 'auto-revoke' && t.response !== 'alert-only') {
          errors.push(`tiers.${tierName}.response must be "auto-revoke" or "alert-only".`);
        }
      }
    }
  }

  // allowlist
  if (!doc.allowlist || typeof doc.allowlist !== 'object' || Array.isArray(doc.allowlist)) {
    errors.push('Field "allowlist" is required.');
  } else {
    const al = doc.allowlist as Record<string, unknown>;
    checkAllowedKeys(al, new Set(['principals', 'kms_keys']), 'allowlist', errors);
    if (!Array.isArray(al.principals) || !al.principals.every((p) => typeof p === 'string')) {
      errors.push('allowlist.principals must be an array of principal IDs.');
    }
    if (!Array.isArray(al.kms_keys) || !al.kms_keys.every((k) => typeof k === 'string')) {
      errors.push('allowlist.kms_keys must be an array of KMS key IDs.');
    }
  }

  // detection
  if (!doc.detection || typeof doc.detection !== 'object' || Array.isArray(doc.detection)) {
    errors.push('Field "detection" is required.');
  } else {
    const det = doc.detection as Record<string, unknown>;
    checkAllowedKeys(det, new Set(['entropy', 'burst', 'swarm', 'score']), 'detection', errors);

    const ent = det.entropy as Record<string, unknown> | undefined;
    if (!ent || typeof ent !== 'object') {
      errors.push('detection.entropy is required.');
    } else {
      checkAllowedKeys(ent, new Set(['sample_bytes', 'delta_threshold']), 'detection.entropy', errors);
      if (typeof ent.sample_bytes !== 'number' || ent.sample_bytes < 1024 || ent.sample_bytes > 1048576) {
        errors.push('detection.entropy.sample_bytes must be between 1024 and 1048576.');
      }
      if (typeof ent.delta_threshold !== 'number' || ent.delta_threshold <= 0 || ent.delta_threshold > 8) {
        errors.push('detection.entropy.delta_threshold must be between 0.1 and 8.0.');
      }
    }

    const burst = det.burst as Record<string, unknown> | undefined;
    if (!burst || typeof burst !== 'object') {
      errors.push('detection.burst is required.');
    } else {
      checkAllowedKeys(burst, new Set(['window_seconds', 'pairs']), 'detection.burst', errors);
      if (typeof burst.window_seconds !== 'number' || burst.window_seconds < 1) {
        errors.push('detection.burst.window_seconds must be >= 1.');
      }
      if (typeof burst.pairs !== 'number' || burst.pairs < 2) {
        errors.push('detection.burst.pairs must be >= 2.');
      }
    }

    const swarm = det.swarm as Record<string, unknown> | undefined;
    if (!swarm || typeof swarm !== 'object') {
      errors.push('detection.swarm is required.');
    } else {
      checkAllowedKeys(
        swarm,
        new Set(['window_seconds', 'min_principals', 'flagged_writes']),
        'detection.swarm',
        errors,
      );
      if (typeof swarm.window_seconds !== 'number' || swarm.window_seconds < 5) {
        errors.push('detection.swarm.window_seconds must be >= 5.');
      }
      if (typeof swarm.min_principals !== 'number' || swarm.min_principals < 2) {
        errors.push('detection.swarm.min_principals must be >= 2.');
      }
      if (typeof swarm.flagged_writes !== 'number' || swarm.flagged_writes < 2) {
        errors.push('detection.swarm.flagged_writes must be >= 2.');
      }
    }

    const score = det.score as Record<string, unknown> | undefined;
    if (!score || typeof score !== 'object') {
      errors.push('detection.score is required.');
    } else {
      checkAllowedKeys(score, new Set(['watchlist', 'contain']), 'detection.score', errors);
      if (typeof score.watchlist !== 'number' || score.watchlist < 10) {
        errors.push('detection.score.watchlist must be >= 10.');
      }
      if (typeof score.contain !== 'number' || score.contain < 50) {
        errors.push('detection.score.contain must be >= 50.');
      }
    }
  }

  // canary
  if (!doc.canary || typeof doc.canary !== 'object' || Array.isArray(doc.canary)) {
    errors.push('Field "canary" is required.');
  } else {
    const can = doc.canary as Record<string, unknown>;
    checkAllowedKeys(can, new Set(['count', 'refresh_hours']), 'canary', errors);
    if (typeof can.count !== 'number' || can.count < 1 || can.count > 200) {
      errors.push('canary.count must be between 1 and 200.');
    }
    if (typeof can.refresh_hours !== 'number' || can.refresh_hours < 1) {
      errors.push('canary.refresh_hours must be >= 1.');
    }
  }

  // hard_triggers
  if (!Array.isArray(doc.hard_triggers)) {
    errors.push('Field "hard_triggers" must be an array.');
  } else {
    for (const ht of doc.hard_triggers) {
      if (typeof ht !== 'string' || !ALLOWED_HARD_TRIGGERS.has(ht)) {
        errors.push(`Unknown hard_trigger "${String(ht)}".`);
      }
    }
  }

  // actions
  if (!doc.actions || typeof doc.actions !== 'object' || Array.isArray(doc.actions)) {
    errors.push('Field "actions" is required.');
  } else {
    const act = doc.actions as Record<string, unknown>;
    checkAllowedKeys(act, new Set(['on_p0']), 'actions', errors);
    if (!Array.isArray(act.on_p0)) {
      errors.push('actions.on_p0 must be an array.');
    } else {
      for (const a of act.on_p0) {
        if (typeof a !== 'string' || !ALLOWED_ACTIONS.has(a)) {
          errors.push(`Unknown action "${String(a)}" in actions.on_p0.`);
        }
      }
    }
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  return { valid: true, policy: doc as unknown as PolicyConfig, errors: [] };
}

export function serializePolicyYaml(policy: PolicyConfig): string {
  return yaml.dump(policy, {
    indent: 2,
    lineWidth: 100,
    noRefs: true,
    sortKeys: false,
  });
}

export function loadPersistedPolicy(): { policy: PolicyConfig; yamlText: string } {
  try {
    if (fs.existsSync(POLICY_FILE)) {
      const raw = fs.readFileSync(POLICY_FILE, 'utf8');
      const res = validatePolicyYaml(raw);
      if (res.valid && res.policy) {
        return { policy: res.policy, yamlText: raw };
      }
    }
  } catch {
    // Fallback to default policy on read error
  }
  const yamlText = serializePolicyYaml(DEFAULT_POLICY);
  savePersistedPolicy(DEFAULT_POLICY, yamlText);
  return { policy: structuredClone(DEFAULT_POLICY), yamlText };
}

export function savePersistedPolicy(policy: PolicyConfig, rawYaml?: string): string {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const text = rawYaml ?? serializePolicyYaml(policy);
  fs.writeFileSync(POLICY_FILE, text, 'utf8');
  return text;
}
