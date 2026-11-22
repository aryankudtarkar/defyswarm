import React, { useEffect, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { ArrowUpRight, ShieldAlert, ShieldCheck, X } from 'lucide-react';
import { useConsole } from '../context/ConsoleContext.tsx';
import type { PrincipalState, TelemetryEvent } from '../shared/types.ts';

export type ForensicTarget =
  | { kind: 'event'; event: TelemetryEvent }
  | { kind: 'principal'; principalId: string }
  | null;

interface ForensicDrawerProps {
  target: ForensicTarget;
  onClose: () => void;
}

export const ForensicDrawer: React.FC<ForensicDrawerProps> = ({ target, onClose }) => {
  const { state, apiFetch, pushToast, navigateTo, setSelectedIncidentId } = useConsole();
  const [statusBusy, setStatusBusy] = useState(false);

  useEffect(() => {
    if (!target) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [target, onClose]);

  if (!state) return null;

  const resolvedPrincipal: PrincipalState | undefined =
    target?.kind === 'principal'
      ? state.principals.find((p) => p.id === target.principalId)
      : target?.kind === 'event'
        ? state.principals.find((p) => p.id === target.event.principalId)
        : undefined;

  const relatedIncident =
    target?.kind === 'event'
      ? state.incidents.find(
          (i) => i.bucket === target.event.bucket && i.principals.includes(target.event.principalId),
        ) ?? state.incidents.find((i) => i.bucket === target.event.bucket)
      : target?.kind === 'principal'
        ? state.incidents.find((i) => i.principals.includes(target.principalId))
        : undefined;

  const deltaThreshold = state.policy.detection.entropy.delta_threshold;

  return (
    <AnimatePresence>
      {target && (
        <motion.aside
          initial={{ x: 440, opacity: 0.6 }}
          animate={{ x: 0, opacity: 1 }}
          exit={{ x: 440, opacity: 0 }}
          transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
          className="surface-vibrancy-overlay fixed bottom-0 right-0 top-[48px] z-30 flex w-full max-w-[440px] flex-col border-l border-[#E5E7EB]/85"
        >
          {/* Drawer Header */}
          <div className="flex h-[48px] items-center justify-between border-b border-[#E5E7EB]/80 bg-white/55 px-4">
            <div className="flex items-center gap-2 min-w-0">
              <span className="type-section text-[13.5px] truncate">
                {target.kind === 'event' ? 'Event Forensic Inspector' : 'Principal Security Ledger'}
              </span>
              <span className="type-mono-data text-[11px] text-[#6B7280] truncate">
                {target.kind === 'event' ? target.event.apiOp : target.principalId}
              </span>
            </div>
            <button
              type="button"
              onClick={onClose}
              aria-label="Close forensic inspector"
              className="rounded-[6px] p-1 text-[#6B7280] transition-colors hover:bg-[#111827]/[0.06] hover:text-[#111827]"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          {/* Drawer Body */}
          <div className="flex-1 overflow-y-auto divide-y divide-[#E5E7EB]">
            {target.kind === 'event' && (
              <>
                <div className="p-4 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[12.5px] font-semibold text-[#111827]">
                      {target.event.apiOp}
                    </span>
                    <span
                      className={`font-mono text-[12px] font-semibold tabular-nums ${
                        target.event.httpStatus === 403 ? 'text-[#DC2626]' : 'text-[#16A34A]'
                      }`}
                    >
                      HTTP {target.event.httpStatus}
                    </span>
                  </div>

                  <dl className="grid grid-cols-[110px_1fr] gap-y-1.5 text-[12px]">
                    <dt className="text-[#6B7280]">Timestamp</dt>
                    <dd className="font-mono text-[#111827] tabular-nums">{target.event.timestamp}</dd>

                    <dt className="text-[#6B7280]">Plane</dt>
                    <dd className="capitalize text-[#4B5563]">{target.event.plane} plane</dd>

                    <dt className="text-[#6B7280]">Source</dt>
                    <dd className="capitalize text-[#1D6CF0]">{target.event.source || 'simulator'}</dd>

                    <dt className="text-[#6B7280]">Bucket</dt>
                    <dd className="font-mono text-[#111827]">{target.event.bucket}</dd>

                    <dt className="text-[#6B7280]">Object Key</dt>
                    <dd className="font-mono text-[#111827] break-all">
                      {target.event.key || '— (bucket control call)'}
                    </dd>

                    <dt className="text-[#6B7280]">Principal</dt>
                    <dd className="font-mono text-[#111827]">{target.event.principalId}</dd>

                    <dt className="text-[#6B7280]">Canary Object</dt>
                    <dd className="text-[#4B5563]">
                      {target.event.isCanary ? 'Yes (Adaptive Decoy)' : 'No'}
                    </dd>

                    {target.event.sseAlgorithm && (
                      <>
                        <dt className="text-[#6B7280]">Encryption</dt>
                        <dd className="font-mono text-[#DC2626]">{target.event.sseAlgorithm}</dd>
                      </>
                    )}
                    {target.event.kmsKeyId && (
                      <>
                        <dt className="text-[#6B7280]">KMS Key ARN</dt>
                        <dd className="font-mono text-[#D97706] break-all">{target.event.kmsKeyId}</dd>
                      </>
                    )}
                  </dl>
                </div>

                {/* Payload Analysis */}
                <div className="p-4 space-y-3">
                  <div className="text-[12.5px] font-semibold text-[#111827]">
                    Payload Analysis
                  </div>

                  <div className="grid grid-cols-3 divide-x divide-[#E5E7EB] rounded-lg border border-[#E5E7EB] bg-[#F9FAFB] tabular-nums">
                    <div className="p-2.5">
                      <div className="text-[11px] text-[#6B7280]">Entropy (H)</div>
                      <div className="mt-0.5 text-[14px] font-semibold text-[#111827]">
                        {typeof target.event.entropy === 'number' ? target.event.entropy.toFixed(3) : '—'}
                      </div>
                    </div>
                    <div className="p-2.5">
                      <div className="text-[11px] text-[#6B7280]">ΔH vs Previous</div>
                      <div
                        className={`mt-0.5 text-[14px] font-semibold ${
                          typeof target.event.deltaEntropy === 'number' &&
                          target.event.deltaEntropy >= deltaThreshold
                            ? 'text-[#DC2626]'
                            : 'text-[#4B5563]'
                        }`}
                      >
                        {typeof target.event.deltaEntropy === 'number'
                          ? `${target.event.deltaEntropy >= 0 ? '+' : ''}${target.event.deltaEntropy.toFixed(2)}`
                          : '—'}
                      </div>
                    </div>
                    <div className="p-2.5">
                      <div className="text-[11px] text-[#6B7280]">File Signature</div>
                      <div
                        className={`mt-0.5 text-[12.5px] font-semibold ${
                          target.event.magicValid === false
                            ? 'text-[#DC2626]'
                            : target.event.magicValid
                              ? 'text-[#16A34A]'
                              : 'text-[#6B7280]'
                        }`}
                      >
                        {target.event.magicValid === undefined
                          ? 'N/A'
                          : target.event.magicValid
                            ? target.event.magicDetected || 'Valid'
                            : 'Lost'}
                      </div>
                    </div>
                  </div>

                  {typeof target.event.entropy === 'number' && (
                    <div>
                      <div className="mb-1 flex justify-between text-[11px] text-[#6B7280] tabular-nums">
                        <span>Shannon scale (0–8 bits/byte)</span>
                        <span>Threshold ΔH ≥ {deltaThreshold.toFixed(1)}</span>
                      </div>
                      <div className="h-1.5 w-full overflow-hidden rounded bg-[#E5E7EB]">
                        <div
                          className={`h-full ${
                            target.event.magicValid === false ||
                            (target.event.deltaEntropy ?? 0) >= deltaThreshold
                              ? 'bg-[#DC2626]'
                              : 'bg-[#1D6CF0]'
                          }`}
                          style={{ width: `${Math.min(100, (target.event.entropy / 8) * 100)}%` }}
                        />
                      </div>
                    </div>
                  )}
                </div>

                {/* Signals & Risk Attribution */}
                <div className="p-4 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-[12.5px] font-semibold text-[#111827]">
                      Signals &amp; Risk Contribution
                    </span>
                    <span className="text-[11.5px] font-medium text-[#4B5563] tabular-nums">
                      +{target.event.riskDelta} risk · Bucket {target.event.bucketRiskScore}
                    </span>
                  </div>

                  {target.event.signals.length === 0 ? (
                    <div className="flex items-center gap-2 rounded-md border border-[#BBF7D0] bg-[#F0FDF4] px-3 py-2 text-[12px] text-[#15803D]">
                      <ShieldCheck className="h-3.5 w-3.5 shrink-0" />
                      <span>
                        {target.event.note || 'No threat signals triggered on this call.'}
                      </span>
                    </div>
                  ) : (
                    <div className="space-y-1.5">
                      {target.event.signals.map((sig) => (
                        <div
                          key={sig}
                          className="flex items-center justify-between rounded-md border border-[#FECACA] bg-[#FEF2F2] px-3 py-2 text-[12px] text-[#DC2626]"
                        >
                          <span className="flex items-center gap-2 font-mono">
                            <ShieldAlert className="h-3.5 w-3.5 shrink-0" />
                            {sig}
                          </span>
                          <span className="text-[11.5px] font-medium">Triggered</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </>
            )}

            {/* Associated Principal Ledger */}
            {resolvedPrincipal && (
              <div className="p-4 space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="text-[12.5px] font-semibold text-[#111827]">
                    Principal Posture
                  </span>
                  <span
                    className={`text-[12px] font-semibold capitalize ${
                      resolvedPrincipal.status === 'REVOKED'
                        ? 'text-[#DC2626]'
                        : resolvedPrincipal.status === 'ACTIVE'
                          ? 'text-[#16A34A]'
                          : 'text-[#D97706]'
                    }`}
                  >
                    {resolvedPrincipal.status.toLowerCase()}
                  </span>
                </div>

                <dl className="grid grid-cols-[120px_1fr] gap-y-1.5 text-[12px]">
                  <dt className="text-[#6B7280]">Identity</dt>
                  <dd className="font-mono text-[#111827]">{resolvedPrincipal.id}</dd>

                  <dt className="text-[#6B7280]">Role / Type</dt>
                  <dd className="text-[#4B5563]">
                    {resolvedPrincipal.label} ({resolvedPrincipal.type})
                  </dd>

                  <dt className="text-[#6B7280]">Risk Score</dt>
                  <dd className="font-medium text-[#111827] tabular-nums">
                    {resolvedPrincipal.riskScore}
                  </dd>

                  <dt className="text-[#6B7280]">Quarantine Policy</dt>
                  <dd className="text-[#4B5563]">
                    {resolvedPrincipal.quarantinePolicyAttached ? 'Deny-All Attached' : 'None'}
                  </dd>

                  {resolvedPrincipal.revokedAt && (
                    <>
                      <dt className="text-[#6B7280]">Revoked At</dt>
                      <dd className="font-mono text-[#DC2626] tabular-nums">
                        {resolvedPrincipal.revokedAt.slice(11, 23)} UTC
                      </dd>
                    </>
                  )}
                  {resolvedPrincipal.first403At && (
                    <>
                      <dt className="text-[#6B7280]">First HTTP 403</dt>
                      <dd className="font-mono text-[#16A34A] tabular-nums">
                        {resolvedPrincipal.first403At.slice(11, 23)} UTC
                      </dd>
                    </>
                  )}
                </dl>

                {resolvedPrincipal.triggeredSignals.length > 0 && (
                  <div className="pt-1 font-mono text-[11.5px] text-[#4B5563]">
                    Correlated signals: {resolvedPrincipal.triggeredSignals.join(' · ')}
                  </div>
                )}

                <div className="pt-2">
                  <button
                    type="button"
                    disabled={statusBusy}
                    onClick={async () => {
                      setStatusBusy(true);
                      const nextStatus =
                        resolvedPrincipal.status === 'REVOKED' ? 'ACTIVE' : 'REVOKED';
                      try {
                        await apiFetch(
                          `/api/principals/${encodeURIComponent(resolvedPrincipal.id)}/status`,
                          {
                            method: 'POST',
                            body: JSON.stringify({ status: nextStatus }),
                          },
                        );
                        pushToast({
                          title:
                            nextStatus === 'REVOKED'
                              ? `Revoked ${resolvedPrincipal.id}`
                              : `Restored ${resolvedPrincipal.id}`,
                          detail:
                            nextStatus === 'REVOKED'
                              ? 'Subsequent uploads/writes from this principal now return HTTP 403.'
                              : 'Principal returned to ACTIVE standing.',
                          tone: nextStatus === 'REVOKED' ? 'warning' : 'success',
                        });
                      } catch (err) {
                        pushToast({
                          title: 'Could not update principal',
                          detail: err instanceof Error ? err.message : 'Operator or Admin required.',
                          tone: 'error',
                        });
                      } finally {
                        setStatusBusy(false);
                      }
                    }}
                    className={`h-[32px] w-full rounded-md border text-[12px] font-medium transition-colors disabled:opacity-50 ${
                      resolvedPrincipal.status === 'REVOKED'
                        ? 'border-[#BBF7D0] bg-[#F0FDF4] text-[#15803D] hover:bg-[#DCFCE7]'
                        : 'border-[#FECACA] bg-[#FEF2F2] text-[#DC2626] hover:bg-[#FEE2E2]'
                    }`}
                  >
                    {statusBusy
                      ? 'Updating Access…'
                      : resolvedPrincipal.status === 'REVOKED'
                        ? 'Restore Principal Access'
                        : 'Revoke Principal (HTTP 403 Lockout)'}
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Drawer Action Footer */}
          <div className="flex items-center justify-between gap-2 border-t border-[#E5E7EB] bg-[#F9FAFB] px-4 py-3">
            {relatedIncident ? (
              <button
                type="button"
                onClick={() => {
                  setSelectedIncidentId(relatedIncident.id);
                  navigateTo('threat-ops', 'incidents');
                  onClose();
                }}
                className="inline-flex flex-1 items-center justify-center gap-1.5 rounded-md bg-[#1D6CF0] px-3 py-1.5 text-[12px] font-medium text-white transition-colors hover:bg-[#1558D6]"
              >
                Open Incident {relatedIncident.id}
                <ArrowUpRight className="h-3.5 w-3.5" />
              </button>
            ) : (
              <button
                type="button"
                onClick={() => {
                  navigateTo('storage', 'canaries-vault');
                  onClose();
                }}
                className="inline-flex flex-1 items-center justify-center gap-1.5 rounded-md border border-[#D1D5DB] bg-white px-3 py-1.5 text-[12px] font-medium text-[#111827] hover:bg-[#F3F4F6]"
              >
                Inspect Vault &amp; Canaries
                <ArrowUpRight className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
        </motion.aside>
      )}
    </AnimatePresence>
  );
};
