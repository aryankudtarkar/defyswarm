import type { DetectorId } from '../config.ts';
import type { Alert, Event } from '../types.ts';

export const WRITE_OPERATIONS = new Set([
  'PutObject',
  'CopyObject',
  'CompleteMultipartUpload',
]);

export function isWrite(event: Event): boolean {
  return WRITE_OPERATIONS.has(event.operation);
}

export function entropyDelta(event: Event): number | null {
  if (typeof event.entropy !== 'number' || typeof event.prevEntropy !== 'number') return null;
  return Number((event.entropy - event.prevEntropy).toFixed(3));
}

export function isSuspiciousWrite(event: Event, entropyDeltaThreshold = 1.5): boolean {
  if (!isWrite(event)) return false;
  if (event.magicValid === false) return true;
  if (event.key?.endsWith('.locked')) return true;
  if (event.sseAlgorithm === 'AES256-SSE-C') return true;
  const delta = entropyDelta(event);
  return delta !== null && delta >= entropyDeltaThreshold;
}

export function isAllowlisted(principal: string, params: Record<string, unknown>): boolean {
  const list = params.allowlist;
  if (!Array.isArray(list)) return false;
  return list.includes(principal);
}

export function inWindow(
  records: Array<{ timeMs: number }>,
  nowMs: number,
  windowMs: number,
): Array<{ timeMs: number }> {
  return records.filter((r) => nowMs - r.timeMs <= windowMs);
}

export function firstSuspiciousTime(events: Event[], threshold = 1.5): number | null {
  for (const event of events) {
    if (isSuspiciousWrite(event, threshold)) return event.timeMs;
  }
  return null;
}

export function basename(key: string | undefined): string {
  if (!key) return '';
  const parts = key.split('/');
  return parts[parts.length - 1] ?? key;
}

export function makeAlert(
  event: Event,
  detectorId: DetectorId,
  reason: string,
  containmentRequested: boolean,
): Alert {
  return {
    seq: event.seq,
    timeMs: event.timeMs,
    detectorId,
    principal: event.principal,
    reason,
    containmentRequested,
  };
}
