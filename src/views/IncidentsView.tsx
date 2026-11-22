import React, { useEffect, useMemo, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import {
  CheckCircle2,
  Download,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
  X,
} from 'lucide-react';
import { SparklineArea } from '../components/Charts.tsx';
import { useConsole } from '../context/ConsoleContext.tsx';
import type { RestorePreview, RestoreReport } from '../shared/types.ts';

function formatIncidentStatus(status: string): string {
  switch (status) {
    case 'CONTAINED':
      return 'Contained';
    case 'RESTORED':
      return 'Restored';
    case 'DRY_RUN_LOGGED':
      return 'Dry-Run';
    case 'ACTIVE':
      return 'Active';
    default:
      return status;
  }
}

function formatArtifactType(type: string): string {
  switch (type) {
    case 'encrypted_overwrite':
      return 'Encrypted Overwrite';
    case 'ransom_note':
      return 'Ransom Note';
    case 'delete_marker':
      return 'Delete Marker';
    default:
      return type.replace(/_/g, ' ');
  }
}

export const IncidentsView: React.FC = () => {
  const {
    state,
    selectedIncidentId,
    setSelectedIncidentId,
    apiFetch,
    pushToast,
    navigateTo,
  } = useConsole();

  const [filter, setFilter] = useState<'all' | 'CONTAINED' | 'RESTORED' | 'DRY_RUN_LOGGED'>('all');
  const [preview, setPreview] = useState<RestorePreview | null>(null);
  const [restoring, setRestoring] = useState(false);

  const incidents = state?.incidents ?? [];

  const filtered = useMemo(() => {
    if (filter === 'all') return incidents;
    return incidents.filter((i) => i.status === filter);
  }, [incidents, filter]);

  useEffect(() => {
    if (!selectedIncidentId && filtered.length > 0) {
      setSelectedIncidentId(filtered[0].id);
    }
  }, [filtered, selectedIncidentId, setSelectedIncidentId]);

  const activeIncident =
    incidents.find((i) => i.id === selectedIncidentId) ?? filtered[0] ?? null;

  const riskSparkData = useMemo(() => {
    if (!state) return [0, 0, 0, 0, 0, 0];
    const pts = state.events
      .slice(0, 24)
      .reverse()
      .map((e) => e.bucketRiskScore);
    return pts.length >= 2 ? pts : [0, 0, 0, 0, 0, 0];
  }, [state]);

  const openRestorePreview = async (incidentId: string) => {
    try {
      const data = await apiFetch<RestorePreview>(`/api/incidents/${incidentId}/restore-preview`);
      setPreview(data);
    } catch (err) {
      pushToast({
        title: 'Preview unavailable',
        detail: err instanceof Error ? err.message : 'Unable to generate restore preview.',
        tone: 'error',
      });
    }
  };

  const confirmRestore = async () => {
    if (!preview) return;
    setRestoring(true);
    try {
      const res = await apiFetch<{ ok: boolean; report: RestoreReport }>(
        `/api/incidents/${preview.incidentId}/restore`,
        { method: 'POST' },
      );
      setPreview(null);
      pushToast({
        title: '1-Click Restore Verified',
        detail: `${res.report.filesRestored} object(s) restored · ${res.report.restoreAccuracyPct}% SHA-256 match.`,
        tone: 'success',
      });
    } catch (err) {
      pushToast({
        title: 'Restore failed',
        detail: err instanceof Error ? err.message : 'Could not complete restore.',
        tone: 'error',
      });
    } finally {
      setRestoring(false);
    }
  };

  const handleAdminDecision = async (incidentId: string, decision: 'approved' | 'denied') => {
    try {
      await apiFetch(`/api/incidents/${incidentId}/approve-admin`, {
        method: 'POST',
        body: JSON.stringify({ decision }),
      });
      pushToast({
        title: decision === 'approved' ? 'Quarantine Approved' : 'Quarantine Released',
        detail: `Recorded ${decision} decision in operator audit log.`,
        tone: decision === 'approved' ? 'warning' : 'success',
      });
    } catch (err) {
      pushToast({
        title: 'Action denied',
        detail: err instanceof Error ? err.message : 'Unable to update approval.',
        tone: 'error',
      });
    }
  };

  const exportForensicJson = (incidentId: string) => {
    window.location.href = `/api/incidents/${incidentId}/export`;
  };

  if (!state) return null;

  const containedCount = incidents.filter((i) => i.status === 'CONTAINED').length;
  const restoredCount = incidents.filter((i) => i.status === 'RESTORED').length;
  const avgPreservedPct =
    incidents.length > 0
      ? Math.round(
          incidents.reduce((acc, inc) => acc + inc.filesPreservedPct, 0) / incidents.length,
        )
      : 100;

  return (
    <div className="mx-auto max-w-[1380px] space-y-6 px-4 py-6 sm:px-6">
      {/* Header Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="type-page-title">
            Incidents &amp; One-Click Restore
          </h1>
          <p className="mt-1.5 text-[13px] text-[#6B7280]">
            Forensic ledger · Human-admin quarantine approvals · SHA-256 verified WORM vault
            rollbacks
          </p>
        </div>

        <div className="flex items-center rounded-[8px] border border-[#E5E7EB]/80 bg-[#F2F4F7] p-0.5">
          {(['all', 'CONTAINED', 'RESTORED', 'DRY_RUN_LOGGED'] as const).map((tab) => (
            <button
              key={tab}
              type="button"
              onClick={() => setFilter(tab)}
              className={`rounded-[6px] px-2.5 py-1 text-[12px] font-medium transition-colors whitespace-nowrap shrink-0 ${
                filter === tab
                  ? 'segmented-thumb-shadow bg-white text-[#111827]'
                  : 'text-[#6B7280] hover:text-[#111827]'
              }`}
            >
              {tab === 'all' ? 'All' : formatIncidentStatus(tab)}
            </button>
          ))}
        </div>
      </div>

      {/* Active Protection Summary Banner */}
      <div className="surface-card grid grid-cols-1 divide-y divide-[#E5E7EB] overflow-hidden lg:grid-cols-12 lg:divide-x lg:divide-y-0">
        <div className="p-5 lg:col-span-8">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <p className="text-[12px] font-medium text-[#6B7280]">
                Active Containment &amp; Preservation Coverage
              </p>
              <div className="mt-1.5 flex items-baseline gap-3 tabular-nums">
                <span className="type-kpi text-[#111827]">
                  {avgPreservedPct}%
                </span>
                <span className="text-[12.5px] text-[#4B5563]">
                  objects preserved across {incidents.length} recorded incident(s) ·{' '}
                  <strong className="font-semibold text-[#111827]">{containedCount}</strong> awaiting restore ·{' '}
                  <strong className="font-semibold text-[#16A34A]">{restoredCount}</strong> restored
                </span>
              </div>
            </div>
            <span className="text-[12px] font-medium text-[#1D6CF0] tabular-nums">
              WORM Vault: {state.vault.manifestCount} clean snapshots
            </span>
          </div>

          <div className="mt-3.5 h-1.5 w-full overflow-hidden rounded-full bg-[#F2F4F7]">
            <div
              className="h-full rounded-full bg-[#1D6CF0] transition-all duration-300"
              style={{ width: `${Math.max(4, Math.min(100, avgPreservedPct))}%` }}
            />
          </div>
        </div>

        <div className="flex flex-col justify-between bg-[#F9FAFB]/50 p-4 lg:col-span-4">
          <div className="flex items-center justify-between text-[12px]">
            <span className="font-medium text-[#6B7280]">Recent Risk Trajectory</span>
            <span className="font-medium text-[#111827]">
              {state.policy.mode === 'active' ? 'Active' : 'Dry-Run'}
            </span>
          </div>
          <div className="mt-2 h-[48px]">
            <SparklineArea values={riskSparkData} fillId="inc-risk-spark" />
          </div>
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-lg border border-[#E5E7EB] bg-white px-6 py-16 text-center">
          <ShieldCheck className="h-7 w-7 text-[#16A34A]" />
          <h3 className="mt-3 text-[15px] font-semibold text-[#111827]">No Incidents Recorded</h3>
          <p className="mt-1 max-w-md text-[13px] text-[#6B7280]">
            Run a containment drill in the Simulator (or simulate an encrypted overwrite in Live
            Storage) to inspect containment and 1-Click Restore.
          </p>
          <button
            type="button"
            onClick={() => navigateTo('validation', 'simulator')}
            className="mt-4 rounded-md bg-[#1D6CF0] px-4 py-2 text-[12.5px] font-medium text-white hover:bg-[#1558D6]"
          >
            Open Simulator
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
          {/* Left Master Queue (4 cols) */}
          <div className="overflow-hidden rounded-lg border border-[#E5E7EB] bg-white lg:col-span-4">
            <div className="border-b border-[#E5E7EB] bg-[#F9FAFB] px-4 py-2.5 text-[12px] font-semibold text-[#111827] tabular-nums">
              Incident Queue ({filtered.length})
            </div>
            <div className="max-h-[640px] divide-y divide-[#E5E7EB] overflow-y-auto">
              {filtered.map((inc) => {
                const selected = activeIncident?.id === inc.id;
                return (
                  <button
                    key={inc.id}
                    type="button"
                    onClick={() => setSelectedIncidentId(inc.id)}
                    className={`w-full px-4 py-3.5 text-left transition-colors ${
                      selected ? 'bg-[#EFF6FF]' : 'hover:bg-[#F9FAFB]'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 text-[11.5px]">
                      <span className="font-mono text-[#6B7280]">{inc.id}</span>
                      <span
                        className={`font-semibold ${
                          inc.status === 'RESTORED'
                            ? 'text-[#16A34A]'
                            : inc.status === 'DRY_RUN_LOGGED'
                              ? 'text-[#D97706]'
                              : 'text-[#DC2626]'
                        }`}
                      >
                        {formatIncidentStatus(inc.status)}
                      </span>
                    </div>
                    <p className="mt-1 text-[13px] font-semibold leading-snug text-[#111827]">
                      {inc.title}
                    </p>
                    <p className="mt-1 text-[11.5px] text-[#6B7280] tabular-nums">
                      MTTD {inc.mttdMs} ms · Preserved {inc.filesPreservedPct}% ·{' '}
                      {inc.principals.length} principal(s)
                    </p>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Right Forensic Detail Pane (8 cols) */}
          {activeIncident && (
            <div className="flex flex-col overflow-hidden rounded-lg border border-[#E5E7EB] bg-white lg:col-span-8">
              {/* Detail Header */}
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#E5E7EB] bg-[#F9FAFB] px-5 py-3.5">
                <div>
                  <div className="flex items-center gap-2 text-[12px] text-[#6B7280]">
                    <span className="font-mono font-medium text-[#374151]">{activeIncident.id}</span>
                    <span>·</span>
                    <span className="font-mono">{activeIncident.bucket}</span>
                    <span>·</span>
                    <span>{activeIncident.mode === 'active' ? 'Active' : 'Dry-Run'}</span>
                  </div>
                  <h2 className="mt-1 text-[16px] font-semibold text-[#111827]">
                    {activeIncident.title}
                  </h2>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => exportForensicJson(activeIncident.id)}
                    className="inline-flex h-[32px] items-center gap-1.5 rounded-md border border-[#D1D5DB] bg-white px-3 text-[12px] font-medium text-[#374151] hover:bg-[#F9FAFB] whitespace-nowrap shrink-0"
                  >
                    <Download className="h-3.5 w-3.5 text-[#6B7280]" />
                    Forensic JSON
                  </button>

                  {activeIncident.status !== 'RESTORED' && (
                    <button
                      type="button"
                      onClick={() => openRestorePreview(activeIncident.id)}
                      className="inline-flex h-[32px] items-center gap-1.5 rounded-md bg-[#1D6CF0] px-3.5 text-[12px] font-medium text-white hover:bg-[#1558D6] whitespace-nowrap shrink-0"
                    >
                      <RotateCcw className="h-3.5 w-3.5" />
                      1-Click Restore
                    </button>
                  )}
                </div>
              </div>

              {/* Pending Human-Admin Approval Banner */}
              {activeIncident.pendingAdminApproval &&
                !activeIncident.pendingAdminApproval.decision && (
                  <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#FDE68A] bg-[#FFFBEB] px-5 py-3">
                    <div className="flex items-start gap-2.5 text-[12.5px]">
                      <UserCheck className="mt-0.5 h-4 w-4 shrink-0 text-[#D97706]" />
                      <div>
                        <span className="font-semibold text-[#92400E]">
                          Human-Admin Quarantine Approval Required
                        </span>
                        <p className="text-[12px] text-[#B45309]">
                          {activeIncident.pendingAdminApproval.reason}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => handleAdminDecision(activeIncident.id, 'denied')}
                        className="rounded-md border border-[#D1D5DB] bg-white px-3 py-1.5 text-[12px] font-medium text-[#374151] hover:bg-[#F9FAFB]"
                      >
                        Release Admin
                      </button>
                      <button
                        type="button"
                        onClick={() => handleAdminDecision(activeIncident.id, 'approved')}
                        className="rounded-md bg-[#DC2626] px-3 py-1.5 text-[12px] font-medium text-white hover:bg-[#B91C1C]"
                      >
                        Approve Revocation
                      </button>
                    </div>
                  </div>
                )}

              {/* 4-Cell Incident KPI Row */}
              <div className="grid grid-cols-2 divide-x divide-[#E5E7EB] border-b border-[#E5E7EB] bg-white sm:grid-cols-4 tabular-nums">
                <div className="px-5 py-3">
                  <div className="text-[11.5px] text-[#6B7280]">MTTD</div>
                  <div className="mt-0.5 text-[16px] font-semibold text-[#111827]">
                    {activeIncident.mttdMs} ms
                  </div>
                </div>
                <div className="px-5 py-3">
                  <div className="text-[11.5px] text-[#6B7280]">MTTC (to 403)</div>
                  <div className="mt-0.5 text-[16px] font-semibold text-[#111827]">
                    {activeIncident.mttcMs !== undefined ? `${activeIncident.mttcMs} ms` : '—'}
                  </div>
                </div>
                <div className="px-5 py-3">
                  <div className="text-[11.5px] text-[#6B7280]">Files Preserved</div>
                  <div className="mt-0.5 text-[16px] font-semibold text-[#16A34A]">
                    {activeIncident.filesPreservedPct}%
                  </div>
                </div>
                <div className="px-5 py-3">
                  <div className="text-[11.5px] text-[#6B7280]">Principals</div>
                  <div className="mt-0.5 truncate font-mono text-[12px] font-medium text-[#111827]">
                    {activeIncident.principals.join(', ')}
                  </div>
                </div>
              </div>

              {/* Verified Restore Strip */}
              {activeIncident.restoreReport && (
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#BBF7D0] bg-[#F0FDF4] px-5 py-2.5 text-[12.5px] tabular-nums">
                  <div className="flex items-center gap-2 font-medium text-[#15803D]">
                    <CheckCircle2 className="h-4 w-4" />
                    <span>
                      SHA-256 Vault Restore Verified (
                      {activeIncident.restoreReport.restoreAccuracyPct}%) —{' '}
                      {activeIncident.restoreReport.filesRestored} restored,{' '}
                      {activeIncident.restoreReport.artifactsRemoved} artifacts purged
                    </span>
                  </div>
                  <span className="text-[12px] text-[#166534]">
                    {activeIncident.restoreReport.durationMs} ms · Max recovery gap{' '}
                    {activeIncident.restoreReport.maxDataLossWindowMs} ms
                  </span>
                </div>
              )}

              {/* Chronological Timeline */}
              <div className="border-b border-[#E5E7EB]">
                <div className="flex h-[36px] items-center border-b border-[#E5E7EB] bg-[#F9FAFB] px-5 text-[12px] font-semibold text-[#111827]">
                  Incident Timeline
                </div>
                <div className="divide-y divide-[#F3F4F6]">
                  {activeIncident.timeline.map((t, i) => (
                    <div key={i} className="flex items-start gap-3 px-5 py-2.5 text-[12.5px]">
                      <span className="mt-0.5 shrink-0 text-[11.5px] text-[#6B7280] tabular-nums">
                        {t.timestamp.slice(11, 23)}
                      </span>
                      <div>
                        <span className="font-medium text-[#111827]">{t.label}</span>
                        <p className="text-[12px] text-[#4B5563]">{t.detail}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Affected Objects Table */}
              <div>
                <div className="flex h-[36px] items-center justify-between border-b border-[#E5E7EB] bg-[#F9FAFB] px-5 text-[12px] font-semibold text-[#111827]">
                  <span className="tabular-nums">Affected Objects ({activeIncident.affectedObjects.length})</span>
                  <span className="text-[11.5px] font-normal text-[#6B7280]">
                    Pre-attack manifest SHA-256 &amp; replication gap
                  </span>
                </div>

                {activeIncident.affectedObjects.length === 0 ? (
                  <div className="px-5 py-6 text-[12.5px] font-medium text-[#16A34A]">
                    Contained before any business file was encrypted (0 impacted objects).
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[600px] border-collapse text-left text-[12px]">
                      <thead className="bg-[#F9FAFB] text-[11.5px] font-medium text-[#6B7280]">
                        <tr className="h-[32px] border-b border-[#E5E7EB]">
                          <th className="pl-5 pr-3 font-medium">Object Key</th>
                          <th className="pr-3 font-medium">Impact Type</th>
                          <th className="pr-3 font-medium">Manifest SHA-256</th>
                          <th className="pr-3 text-right font-medium">Gap</th>
                          <th className="pr-5 text-right font-medium">Verification</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#F3F4F6] tabular-nums">
                        {activeIncident.affectedObjects.map((obj) => (
                          <tr key={obj.key} className="h-[36px] hover:bg-[#F9FAFB]">
                            <td className="max-w-[240px] truncate pl-5 pr-3 font-mono text-[11.5px] text-[#111827]">
                              {obj.key}
                            </td>
                            <td className="pr-3 text-[12px] text-[#4B5563]">
                              {formatArtifactType(obj.artifactType)}
                            </td>
                            <td className="pr-3 font-mono text-[11.5px] text-[#6B7280]">
                              {obj.preAttackSha256 ? `${obj.preAttackSha256.slice(0, 14)}…` : '—'}
                            </td>
                            <td className="pr-3 text-right text-[12px] text-[#4B5563]">
                              {obj.replicationLagMs} ms
                            </td>
                            <td className="pr-5 text-right text-[12px]">
                              {obj.restored ? (
                                <span className="font-medium text-[#16A34A]">
                                  {obj.verifiedSha256Match ? 'SHA-256 Match' : 'Mismatch'}
                                </span>
                              ) : (
                                <span className="font-medium text-[#D97706]">Pending</span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* 1-Click Restore Preview Modal with Apple Vibrancy */}
      <AnimatePresence>
        {preview && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.14 }}
            className="fixed inset-0 z-50 flex items-center justify-center bg-[#111827]/28 backdrop-blur-[4px] p-4"
            onClick={() => !restoring && setPreview(null)}
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.97, y: 8 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.98, y: 4 }}
              transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }}
              className="surface-vibrancy-overlay w-full max-w-[620px] overflow-hidden rounded-[12px] border border-[#E5E7EB]/85"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-center justify-between border-b border-[#E5E7EB]/80 bg-white/55 px-5 py-3.5">
                <div className="flex items-center gap-2.5">
                  <ShieldAlert className="h-4 w-4 text-[#1D6CF0]" />
                  <div>
                    <h3 className="type-section text-[15px]">
                      1-Click Vault Restore Preview
                    </h3>
                    <p className="text-[12px] text-[#6B7280] tabular-nums">
                      <span className="font-mono text-[#374151]">{preview.incidentId}</span> ·{' '}
                      <span className="font-mono">{preview.bucket}</span> · Max recovery gap{' '}
                      {preview.maxDataLossWindowMs} ms
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => !restoring && setPreview(null)}
                  className="rounded-[6px] p-1 text-[#6B7280] transition-colors hover:bg-[#111827]/[0.06] hover:text-[#111827]"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              <div className="grid grid-cols-3 divide-x divide-[#E5E7EB] border-b border-[#E5E7EB] bg-white tabular-nums">
                <div className="px-5 py-3">
                  <span className="text-[11.5px] text-[#6B7280]">Objects to Roll Back</span>
                  <p className="mt-0.5 text-[18px] font-semibold text-[#111827]">
                    {preview.objectsToRestore.length}
                  </p>
                </div>
                <div className="px-5 py-3">
                  <span className="text-[11.5px] text-[#6B7280]">Artifacts to Purge</span>
                  <p className="mt-0.5 text-[18px] font-semibold text-[#D97706]">
                    {preview.artifactsToRemove.length}
                  </p>
                </div>
                <div className="px-5 py-3">
                  <span className="text-[11.5px] text-[#6B7280]">Unrecoverable</span>
                  <p className="mt-0.5 text-[18px] font-semibold text-[#16A34A]">
                    {preview.unrecoverableCount}
                  </p>
                </div>
              </div>

              <div className="max-h-[220px] divide-y divide-[#F3F4F6] overflow-y-auto px-5 py-2 text-[12px]">
                {preview.objectsToRestore.length === 0 ? (
                  <p className="py-3 text-[#16A34A]">
                    0 encrypted objects to roll back; confirming resolves the incident and resumes
                    vault replication.
                  </p>
                ) : (
                  preview.objectsToRestore.map((obj) => (
                    <div
                      key={obj.key}
                      className="flex h-[34px] items-center justify-between gap-4"
                    >
                      <span className="truncate font-mono text-[11.5px] text-[#111827]">{obj.key}</span>
                      <span className="shrink-0 text-[11.5px] text-[#6B7280] tabular-nums">
                        <span className="font-mono">{obj.preAttackSha256.slice(0, 12)}…</span> · gap{' '}
                        {obj.dataLossWindowMs} ms
                      </span>
                    </div>
                  ))
                )}
              </div>

              <div className="flex items-center justify-end gap-2 border-t border-[#E5E7EB] bg-[#F9FAFB] px-5 py-3">
                <button
                  type="button"
                  disabled={restoring}
                  onClick={() => setPreview(null)}
                  className="rounded-md border border-[#D1D5DB] bg-white px-3.5 py-1.5 text-[12.5px] font-medium text-[#374151] hover:bg-[#F9FAFB]"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  disabled={restoring}
                  onClick={confirmRestore}
                  className="rounded-md bg-[#1D6CF0] px-4 py-1.5 text-[12.5px] font-medium text-white hover:bg-[#1558D6] disabled:opacity-50"
                >
                  {restoring ? 'Restoring & Verifying…' : 'Confirm 1-Click Restore'}
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};
