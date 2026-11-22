import type { Detector, DetectorOutput, DetectorRunContext, RecoveryModel } from '../types.ts';
import type { Event } from '../types.ts';
import {
  basename,
  entropyDelta,
  firstSuspiciousTime,
  isAllowlisted,
  isSuspiciousWrite,
  isWrite,
  makeAlert,
} from './helpers.ts';

function paramNumber(params: Record<string, unknown>, key: string, fallback: number): number {
  const value = params[key];
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

function paramStringArray(params: Record<string, unknown>, key: string, fallback: string[]): string[] {
  const value = params[key];
  if (Array.isArray(value) && value.every((v) => typeof v === 'string')) return value as string[];
  return fallback;
}

function noRecovery(): RecoveryModel {
  return { capable: false, mechanism: 'none', recoveryPointLossMs: null };
}

function versioningIntact(events: Event[]): boolean {
  for (const event of events) {
    if (
      event.operation === 'PutBucketVersioning' &&
      event.versioningTargetStatus === 'Suspended'
    ) {
      return false;
    }
    if (event.operation === 'DeleteObjectVersion') return false;
    if (
      event.operation === 'PutBucketLifecycleConfiguration' &&
      typeof event.lifecycleExpiryDays === 'number' &&
      event.lifecycleExpiryDays <= 1
    ) {
      return false;
    }
  }
  return true;
}

export const d0: Detector = {
  id: 'D0',
  name: 'No protection (versioning or nothing)',
  models: 'S3 versioning only, with no detection or automated response',
  run(_context: DetectorRunContext): DetectorOutput {
    return { alerts: [] };
  },
  recovery(_params: Record<string, unknown>, events: Event[]): RecoveryModel {
    const intact = versioningIntact(events);
    return {
      capable: intact,
      mechanism: intact ? 'S3 object versioning (attacker did not purge versions)' : 'none',
      recoveryPointLossMs: intact ? 0 : null,
    };
  },
};

export const d1: Detector = {
  id: 'D1',
  name: 'Snapshot / backup only',
  models: 'Scheduled backup every N hours with restore from the last snapshot',
  run(_context: DetectorRunContext): DetectorOutput {
    return { alerts: [] };
  },
  recovery(params: Record<string, unknown>, events: Event[]): RecoveryModel {
    const intervalHours = paramNumber(params, 'intervalHours', 24);
    const intervalMs = Math.max(1, intervalHours * 60 * 60 * 1000);
    const first = firstSuspiciousTime(events) ?? 0;
    const lastSnapshot = Math.floor(first / intervalMs) * intervalMs;
    return {
      capable: true,
      mechanism: `snapshot restore every ${intervalHours}h (everything since last snapshot is lost)`,
      recoveryPointLossMs: Math.max(0, first - lastSnapshot),
    };
  },
};

interface PrincipalHistory {
  deltas: number[];
  rates: number[];
  writeTimes: number[];
}

export const d2: Detector = {
  id: 'D2',
  name: 'Per-principal behavioural anomaly',
  models: 'Cloud-native S3 threat detection with a per-principal behavioural baseline (e.g. GuardDuty S3 Protection)',
  run(context: DetectorRunContext): DetectorOutput {
    const z = paramNumber(context.params, 'z', 3);
    const minHistory = paramNumber(context.params, 'minHistory', 5);
    const windowSeconds = paramNumber(context.params, 'windowSeconds', 15);
    const minEntropyDelta = paramNumber(context.params, 'minEntropyDelta', 1.0);
    const minRate = paramNumber(context.params, 'minRate', 25);
    const allowlist = paramStringArray(context.params, 'allowlist', []);
    const windowMs = windowSeconds * 1000;
    const histories = new Map<string, PrincipalHistory>();
    const globalDeltas: number[] = [];
    const alerts: DetectorOutput['alerts'] = [];

    for (const event of context.events) {
      if (!isWrite(event)) continue;
      if (allowlist.includes(event.principal)) continue;
      const delta = entropyDelta(event) ?? 0;
      const history = histories.get(event.principal) ?? { deltas: [], rates: [], writeTimes: [] };
      const writeTimes = history.writeTimes.filter((t) => event.timeMs - t <= windowMs);
      writeTimes.push(event.timeMs);
      const rate = writeTimes.length;

      let baselineDeltas = history.deltas.length >= minHistory ? history.deltas : globalDeltas;
      let baselineRates = history.rates;
      let anomaly = false;
      let reason = '';

      if (baselineDeltas.length >= minHistory && delta >= minEntropyDelta) {
        const mean = baselineDeltas.reduce((a, b) => a + b, 0) / baselineDeltas.length;
        const variance =
          baselineDeltas.reduce((a, b) => a + (b - mean) * (b - mean), 0) / baselineDeltas.length;
        const std = Math.max(0.05, Math.sqrt(variance));
        const zScore = (delta - mean) / std;
        if (zScore >= z) {
          anomaly = true;
          reason = `entropy delta ${delta.toFixed(2)} is ${zScore.toFixed(1)}σ above ${event.principal}'s baseline`;
        }
      }
      if (!anomaly && baselineRates.length >= minHistory && rate >= minRate) {
        const mean = baselineRates.reduce((a, b) => a + b, 0) / baselineRates.length;
        const variance =
          baselineRates.reduce((a, b) => a + (b - mean) * (b - mean), 0) / baselineRates.length;
        const std = Math.max(0.5, Math.sqrt(variance));
        const zScore = (rate - mean) / std;
        if (zScore >= z) {
          anomaly = true;
          reason = `write rate ${rate}/${windowSeconds}s is ${zScore.toFixed(1)}σ above ${event.principal}'s baseline`;
        }
      }

      if (anomaly) {
        alerts.push(makeAlert(event, 'D2', reason, true));
      }

      history.deltas.push(delta);
      history.rates.push(rate);
      history.writeTimes = writeTimes.slice(-200);
      if (history.deltas.length > 200) history.deltas.shift();
      if (history.rates.length > 200) history.rates.shift();
      histories.set(event.principal, history);
      globalDeltas.push(delta);
      if (globalDeltas.length > 500) globalDeltas.shift();
    }

    return { alerts };
  },
  recovery: noRecovery,
};

export const d3: Detector = {
  id: 'D3',
  name: 'Per-principal batch rate rule',
  models: 'Log alarm / SIEM rule evaluated in 1, 5 or 15 minute batches by a human analyst',
  run(context: DetectorRunContext): DetectorOutput {
    const batchMinutes = paramNumber(context.params, 'batchMinutes', 5);
    const writeThreshold = paramNumber(context.params, 'writeThreshold', 100);
    const suspiciousThreshold = paramNumber(context.params, 'suspiciousThreshold', 5);
    const allowlist = paramStringArray(context.params, 'allowlist', []);
    const batchMs = Math.max(1, batchMinutes * 60 * 1000);
    const maxTime = context.events.length > 0 ? context.events[context.events.length - 1].timeMs : 0;
    const alerts: DetectorOutput['alerts'] = [];

    for (let batchStart = 0; batchStart <= maxTime; batchStart += batchMs) {
      const batchEnd = batchStart + batchMs;
      const batch = context.events.filter((e) => e.timeMs >= batchStart && e.timeMs < batchEnd);
      if (batch.length === 0) continue;
      const byPrincipal = new Map<string, { writes: number; suspicious: number; lastEvent: Event }>();
      for (const event of batch) {
        if (!isWrite(event)) continue;
        if (allowlist.includes(event.principal)) continue;
        const entry = byPrincipal.get(event.principal) ?? {
          writes: 0,
          suspicious: 0,
          lastEvent: event,
        };
        entry.writes++;
        if (isSuspiciousWrite(event)) entry.suspicious++;
        entry.lastEvent = event;
        byPrincipal.set(event.principal, entry);
      }
      for (const [principal, entry] of byPrincipal) {
        if (entry.suspicious >= suspiciousThreshold || entry.writes >= writeThreshold) {
          const event = entry.lastEvent;
          alerts.push({
            seq: event.seq,
            timeMs: batchEnd,
            detectorId: 'D3',
            principal,
            reason: `batch ${batchMinutes}m: ${entry.suspicious} suspicious / ${entry.writes} writes for ${principal}`,
            containmentRequested: true,
          });
        }
      }
    }

    return { alerts };
  },
  recovery: noRecovery,
};

export const d4: Detector = {
  id: 'D4',
  name: 'Malware / signature scan on upload',
  models: 'Upload malware scanning such as Microsoft Defender for Storage malware scanning',
  run(context: DetectorRunContext): DetectorOutput {
    const entropyThreshold = paramNumber(context.params, 'entropyThreshold', 7.5);
    const alerts: DetectorOutput['alerts'] = [];
    for (const event of context.events) {
      if (!isWrite(event)) continue;
      const magicLost = event.magicValid === false;
      const highEntropyLocked =
        (event.entropy ?? 0) >= entropyThreshold && Boolean(event.key?.endsWith('.locked'));
      if (magicLost || highEntropyLocked) {
        alerts.push(
          makeAlert(
            event,
            'D4',
            magicLost
              ? `upload scan: magic header destroyed on ${event.key ?? 'object'}`
              : `upload scan: entropy ${event.entropy?.toFixed(2)} on locked artifact`,
            true,
          ),
        );
      }
    }
    return { alerts };
  },
  recovery: noRecovery,
};

export const d5: Detector = {
  id: 'D5',
  name: 'Sync-client ransomware heuristic',
  models: 'Endpoint sync client ransomware detection (Google Drive for desktop / OneDrive)',
  run(context: DetectorRunContext): DetectorOutput {
    const deltaThreshold = paramNumber(context.params, 'entropyDeltaThreshold', 1.5);
    const alerts: DetectorOutput['alerts'] = [];
    for (const event of context.events) {
      if (event.channel !== 'sync') continue;
      if (!isSuspiciousWrite(event, deltaThreshold)) continue;
      alerts.push(
        makeAlert(event, 'D5', `sync client saw suspicious overwrite on ${event.key ?? 'object'}`, true),
      );
    }
    return { alerts };
  },
  recovery: noRecovery,
};

export const d6: Detector = {
  id: 'D6',
  name: 'Extension and ransom-note blacklist',
  models: 'File screening and antivirus signature blacklists',
  run(context: DetectorRunContext): DetectorOutput {
    const extensions = paramStringArray(context.params, 'extensions', ['.locked']);
    const noteNames = paramStringArray(context.params, 'noteNames', [
      'readme_ransom.txt',
      'decrypt_files.html',
    ]);
    const alerts: DetectorOutput['alerts'] = [];
    for (const event of context.events) {
      if (event.plane !== 'data' || !event.key) continue;
      const lower = event.key.toLowerCase();
      const extensionMatch = extensions.some((ext) => lower.endsWith(ext.toLowerCase()));
      const noteMatch = noteNames.includes(basename(lower));
      if (extensionMatch || noteMatch) {
        alerts.push(
          makeAlert(event, 'D6', `blacklisted artifact ${basename(event.key)}`, true),
        );
      }
    }
    return { alerts };
  },
  recovery: noRecovery,
};

export const d7: Detector = {
  id: 'D7',
  name: 'Naive fixed-name canary',
  models: 'Canary-token tripwires with obvious fixed filenames',
  run(context: DetectorRunContext): DetectorOutput {
    const names = paramStringArray(context.params, 'names', []);
    const allowlist = paramStringArray(context.params, 'allowlist', []);
    const alerts: DetectorOutput['alerts'] = [];
    for (const event of context.events) {
      if (!event.key || !names.includes(event.key)) continue;
      if (allowlist.includes(event.principal)) continue;
      if (event.operation === 'GetObject' || isWrite(event) || event.operation === 'DeleteObject') {
        alerts.push(
          makeAlert(event, 'D7', `fixed-name canary ${event.key} touched by ${event.principal}`, true),
        );
      }
    }
    return { alerts };
  },
  recovery: noRecovery,
};

export const d8: Detector = {
  id: 'D8',
  name: 'Entropy-only threshold',
  models: 'Naive "high entropy means encrypted" rule',
  run(context: DetectorRunContext): DetectorOutput {
    const threshold = paramNumber(context.params, 'entropyThreshold', 7.8);
    const alerts: DetectorOutput['alerts'] = [];
    for (const event of context.events) {
      if (!isWrite(event)) continue;
      if ((event.entropy ?? 0) >= threshold) {
        alerts.push(
          makeAlert(
            event,
            'D8',
            `entropy ${event.entropy?.toFixed(2)} ≥ ${threshold.toFixed(2)} on ${event.key ?? 'object'}`,
            true,
          ),
        );
      }
    }
    return { alerts };
  },
  recovery: noRecovery,
};
