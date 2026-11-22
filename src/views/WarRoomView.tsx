import React, { useMemo, useState } from 'react';
import { ArrowRight, Search, ShieldAlert, ShieldCheck } from 'lucide-react';
import { EntropyTimeSeriesChart, RiskScoreGauge } from '../components/Charts.tsx';
import { ForensicDrawer, type ForensicTarget } from '../components/ForensicDrawer.tsx';
import { useConsole } from '../context/ConsoleContext.tsx';
import type { PrincipalStatus } from '../shared/types.ts';

function statusColor(status: PrincipalStatus): string {
  switch (status) {
    case 'REVOKED':
      return 'text-[#DC2626]';
    case 'PENDING_APPROVAL':
    case 'WATCHLIST':
      return 'text-[#D97706]';
    default:
      return 'text-[#16A34A]';
  }
}

function formatPrincipalStatus(status: PrincipalStatus): string {
  switch (status) {
    case 'REVOKED':
      return 'Revoked';
    case 'PENDING_APPROVAL':
      return 'Pending Approval';
    case 'WATCHLIST':
      return 'Watchlist';
    default:
      return 'Active';
  }
}

function formatIncidentStatus(status: string): string {
  switch (status) {
    case 'RESTORED':
      return 'Restored';
    case 'CONTAINED':
      return 'Contained';
    case 'DRY_RUN_LOGGED':
      return 'Dry-Run';
    case 'ACTIVE':
      return 'Active';
    default:
      return status;
  }
}

function sourceLabel(source?: string): string {
  switch (source) {
    case 'webhook':
      return 'Webhook';
    case 'live-api':
      return 'Live API';
    case 'poller':
      return 'Poller';
    default:
      return 'Simulator';
  }
}

function sourceBadgeStyle(source?: string): string {
  switch (source) {
    case 'webhook':
      return 'border-[#BFDBFE] bg-[#EFF6FF] text-[#1D6CF0]';
    case 'live-api':
      return 'border-[#BBF7D0] bg-[#F0FDF4] text-[#15803D]';
    case 'poller':
      return 'border-[#FDE68A] bg-[#FFFBEB] text-[#B45309]';
    default:
      return 'border-[#E5E7EB] bg-[#F9FAFB] text-[#4B5563]';
  }
}

export const WarRoomView: React.FC = () => {
  const { state, navigateTo, setSelectedIncidentId } = useConsole();
  const [feedFilter, setFeedFilter] = useState<'all' | 'flagged' | 'blocked'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [inspected, setInspected] = useState<ForensicTarget>(null);

  const latestIncident = state?.incidents[0];
  const swarmIncident = state?.incidents.find(
    (i) => i.isSwarm && (i.status === 'ACTIVE' || i.status === 'CONTAINED'),
  );

  const currentBucketRisk = useMemo(() => {
    if (!state) return 0;
    const latest = state.events.find((e) => !e.selfLoopIgnored);
    if (latestIncident && latestIncident.status === 'RESTORED') return 0;
    return latest?.bucketRiskScore ?? 0;
  }, [state, latestIncident]);

  const filteredEvents = useMemo(() => {
    if (!state) return [];
    const q = searchQuery.trim().toLowerCase();
    return state.events.filter((evt) => {
      if (feedFilter === 'flagged' && evt.signals.length === 0 && evt.riskDelta <= 0) return false;
      if (feedFilter === 'blocked' && evt.httpStatus !== 403) return false;
      if (q) {
        const hay =
          `${evt.apiOp} ${evt.principalId} ${evt.bucket} ${evt.key || ''} ${evt.signals.join(' ')} ${evt.source || ''}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [state, feedFilter, searchQuery]);

  if (!state) return null;

  const openIncidentInConsole = (id: string) => {
    setSelectedIncidentId(id);
    navigateTo('threat-ops', 'incidents');
  };

  const adapterLabel =
    state.storage.provider === 'local'
      ? 'Local Sandbox'
      : state.storage.provider === 'backblaze-b2'
        ? 'Backblaze B2'
        : state.storage.provider === 'supabase-s3'
          ? 'Supabase Storage'
          : state.storage.provider === 'minio'
            ? 'MinIO'
            : 'Custom S3';

  return (
    <div className="mx-auto max-w-[1380px] space-y-6 px-4 py-6 sm:px-6">
      {/* Header row */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="type-page-title">
            Observability &amp; Live Telemetry
          </h1>
          <p className="mt-1.5 text-[13px] text-[#6B7280] tabular-nums">
            {state.buckets.length} monitored buckets · Backend:{' '}
            <span className="font-medium text-[#374151]">{adapterLabel}</span> · Select any event or
            credential to inspect forensics
          </p>
        </div>

        <div className="flex items-center gap-2">
          {latestIncident && (
            <button
              type="button"
              onClick={() => openIncidentInConsole(latestIncident.id)}
              className="inline-flex h-[32px] items-center gap-1.5 rounded-md border border-[#D1D5DB] bg-white px-3 text-[12.5px] font-medium text-[#374151] transition-colors hover:bg-[#F9FAFB] whitespace-nowrap shrink-0"
            >
              {latestIncident.status === 'CONTAINED'
                ? 'Open 1-Click Restore'
                : 'Inspect Latest Incident'}
              <ArrowRight className="h-3.5 w-3.5 text-[#6B7280]" />
            </button>
          )}
        </div>
      </div>

      {/* Cross-Principal Swarm Containment Strip */}
      {swarmIncident && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-[#FECACA] bg-[#FEF2F2] px-4 py-3">
          <div className="flex items-center gap-2.5 text-[13px]">
            <ShieldAlert className="h-4 w-4 shrink-0 text-[#DC2626]" />
            <span className="font-semibold text-[#991B1B]">
              Cross-Principal Swarm Contained · {swarmIncident.bucket}
            </span>
            <span className="text-[#7F1D1D]">
              {swarmIncident.principals.length} identities (
              <span className="font-mono font-medium">{swarmIncident.principals.join(', ')}</span>)
              quarantined together
            </span>
          </div>
          <button
            type="button"
            onClick={() => openIncidentInConsole(swarmIncident.id)}
            className="rounded-md bg-[#DC2626] px-3 py-1.5 text-[12px] font-medium text-white hover:bg-[#B91C1C] whitespace-nowrap shrink-0"
          >
            Restore Vault Snapshots
          </button>
        </div>
      )}

      {/* 4-Column KPI Ledger */}
      <div className="surface-card grid grid-cols-1 divide-y divide-[#E5E7EB] overflow-hidden sm:grid-cols-2 sm:divide-y-0 sm:divide-x xl:grid-cols-4">
        <div className="px-4 py-4">
          <div className="text-[12px] font-medium text-[#6B7280]">Measured MTTD</div>
          <div className="mt-2 flex items-baseline justify-between gap-2 tabular-nums">
            <span className="type-kpi text-[26px] text-[#111827]">
              {latestIncident ? `${latestIncident.mttdMs} ms` : '—'}
            </span>
            <span className="text-[11.5px] text-[#6B7280]">Target &lt; 5s</span>
          </div>
        </div>

        <div className="px-4 py-4">
          <div className="text-[12px] font-medium text-[#6B7280]">Measured MTTC (to HTTP 403)</div>
          <div className="mt-2 flex items-baseline justify-between gap-2 tabular-nums">
            <span className="type-kpi text-[26px] text-[#111827]">
              {latestIncident?.mttcMs !== undefined ? `${latestIncident.mttcMs} ms` : '—'}
            </span>
            <span className="text-[11.5px] text-[#6B7280]">Target &lt; 10s</span>
          </div>
        </div>

        <div className="px-4 py-4">
          <div className="text-[12px] font-medium text-[#6B7280]">Files Preserved vs. Impacted</div>
          <div className="mt-2 flex items-baseline justify-between gap-2 tabular-nums">
            <span className="type-kpi text-[26px] text-[#16A34A]">
              {latestIncident ? `${latestIncident.filesPreservedPct}%` : '100%'}
            </span>
            <span className="text-[11.5px] text-[#4B5563]">
              {latestIncident
                ? `${latestIncident.filesPreserved} clean / ${latestIncident.filesImpacted} hit`
                : `${state.health.monitoredObjects} clean / 0 hit`}
            </span>
          </div>
        </div>

        <div className="px-4 py-4">
          <div className="text-[12px] font-medium text-[#6B7280]">WORM Vault Replication</div>
          <div className="mt-2 flex items-baseline justify-between gap-2 tabular-nums">
            <span
              className={`type-kpi text-[26px] ${
                state.vault.replicationPaused ? 'text-[#D97706]' : 'text-[#16A34A]'
              }`}
            >
              {state.vault.replicationPaused ? 'Held' : `${state.vault.avgReplicationLagMs} ms`}
            </span>
            <span className="text-[11.5px] text-[#4B5563]">
              {state.vault.manifestCount} snapshots
            </span>
          </div>
        </div>
      </div>

      {/* Row 1: Entropy Time-Series (8) | Bucket Risk Gauge (4) */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
        <div className="rounded-lg border border-[#E5E7EB] bg-white p-5 lg:col-span-8">
          <EntropyTimeSeriesChart
            events={state.events}
            deltaThreshold={state.policy.detection.entropy.delta_threshold}
            onSelectEvent={(evt) => setInspected({ kind: 'event', event: evt })}
          />
        </div>

        <div className="flex flex-col justify-between rounded-lg border border-[#E5E7EB] bg-white p-5 lg:col-span-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-[13.5px] font-semibold text-[#111827]">Bucket Risk Score</h3>
              <p className="mt-0.5 text-[12px] text-[#6B7280]">Composite threat score</p>
            </div>
            <span className="rounded border border-[#E5E7EB] bg-[#F9FAFB] px-2 py-0.5 text-[11.5px] font-medium text-[#4B5563]">
              {state.policy.mode === 'active' ? 'Active' : 'Dry-Run'}
            </span>
          </div>
          <div className="mt-4">
            <RiskScoreGauge
              score={currentBucketRisk}
              watchlistThreshold={state.policy.detection.score.watchlist}
              containThreshold={state.policy.detection.score.contain}
              mode={state.policy.mode}
            />
          </div>
        </div>
      </div>

      {/* Row 2: Monitored Credentials (6) | Attack & Response Timeline (6) */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
        {/* Monitored Credentials */}
        <div className="overflow-hidden rounded-lg border border-[#E5E7EB] bg-white lg:col-span-6">
          <div className="flex h-[40px] items-center justify-between border-b border-[#E5E7EB] bg-[#F9FAFB] px-4">
            <h3 className="text-[13px] font-semibold text-[#111827]">Monitored Credentials</h3>
            <span className="text-[12px] text-[#6B7280] tabular-nums">
              {state.principals.filter((p) => p.status === 'REVOKED').length} revoked ·{' '}
              {state.principals.length} total
            </span>
          </div>
          <div className="max-h-[272px] divide-y divide-[#F3F4F6] overflow-y-auto">
            {state.principals.map((p) => {
              const isSelected =
                inspected?.kind === 'principal' && inspected.principalId === p.id;
              return (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => setInspected({ kind: 'principal', principalId: p.id })}
                  className={`flex h-[38px] w-full items-center justify-between gap-3 px-4 text-left text-[12.5px] transition-colors ${
                    isSelected ? 'bg-[#EFF6FF]' : 'hover:bg-[#F9FAFB]'
                  }`}
                >
                  <div className="flex min-w-0 items-center gap-2">
                    <span className="truncate font-mono text-[12px] font-medium text-[#111827]">{p.id}</span>
                    <span className="hidden truncate text-[11.5px] text-[#6B7280] sm:inline">
                      · {p.allowlisted ? 'Allowlisted' : p.type.replace('_', ' ')}
                    </span>
                  </div>
                  <div className="flex shrink-0 items-center gap-4 text-[12px] tabular-nums">
                    <span className="text-[#6B7280]">Score {p.riskScore}</span>
                    <span className={`w-[96px] text-right font-medium ${statusColor(p.status)}`}>
                      {formatPrincipalStatus(p.status)}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Attack & Response Timeline */}
        <div className="overflow-hidden rounded-lg border border-[#E5E7EB] bg-white lg:col-span-6">
          <div className="flex h-[40px] items-center justify-between border-b border-[#E5E7EB] bg-[#F9FAFB] px-4">
            <h3 className="truncate text-[13px] font-semibold text-[#111827]">
              {latestIncident ? (
                <>
                  Timeline · <span className="font-mono text-[12px]">{latestIncident.id}</span>
                </>
              ) : (
                'Attack & Response Timeline'
              )}
            </h3>
            {latestIncident ? (
              <span
                className={`text-[12px] font-semibold ${
                  latestIncident.status === 'RESTORED'
                    ? 'text-[#16A34A]'
                    : latestIncident.status === 'DRY_RUN_LOGGED'
                      ? 'text-[#D97706]'
                      : 'text-[#DC2626]'
                }`}
              >
                {formatIncidentStatus(latestIncident.status)}
              </span>
            ) : (
              <span className="text-[12px] font-medium text-[#16A34A]">Nominal</span>
            )}
          </div>

          {!latestIncident ? (
            <div className="flex h-[272px] flex-col items-center justify-center px-6 text-center">
              <ShieldCheck className="h-6 w-6 text-[#16A34A]" />
              <p className="mt-2.5 text-[13.5px] font-semibold text-[#111827]">No Active Threats</p>
              <p className="mt-1 max-w-sm text-[12.5px] text-[#6B7280]">
                Upload files in Live Storage or run a validation drill in Simulator to stream live
                telemetry.
              </p>
              <button
                type="button"
                onClick={() => navigateTo('validation', 'simulator')}
                className="mt-3.5 rounded-md bg-[#1D6CF0] px-3.5 py-1.5 text-[12.5px] font-medium text-white hover:bg-[#1558D6]"
              >
                Open Simulator
              </button>
            </div>
          ) : (
            <div className="max-h-[272px] divide-y divide-[#F3F4F6] overflow-y-auto">
              {latestIncident.timeline.map((step, idx) => (
                <div key={`${step.timestamp}-${idx}`} className="flex items-start gap-3 px-4 py-2.5">
                  <span className="mt-0.5 shrink-0 font-mono text-[11px] text-[#6B7280] tabular-nums">
                    {step.timestamp.slice(11, 23)}
                  </span>
                  <div className="min-w-0">
                    <p
                      className={`text-[12.5px] font-medium ${
                        step.severity === 'critical'
                          ? 'text-[#DC2626]'
                          : step.severity === 'warning'
                            ? 'text-[#D97706]'
                            : step.severity === 'success'
                              ? 'text-[#16A34A]'
                              : 'text-[#111827]'
                      }`}
                    >
                      {step.label}
                    </p>
                    <p className="mt-0.5 text-[12px] leading-snug text-[#4B5563]">{step.detail}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Full-Width Live Activity Feed */}
      <div className="overflow-hidden rounded-lg border border-[#E5E7EB] bg-white">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#E5E7EB] bg-[#F9FAFB] px-4 py-2.5">
          <div className="flex items-center gap-2.5">
            <h3 className="text-[13px] font-semibold text-[#111827]">Live Activity Feed</h3>
            <span className="text-[12px] text-[#6B7280] tabular-nums">
              {filteredEvents.length} events · Select row to inspect
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-2 h-3.5 w-3.5 text-[#9CA3AF]" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter principal, key, op..."
                className="h-[30px] w-[200px] rounded-md border border-[#D1D5DB] bg-white pl-8 pr-2.5 text-[12px] text-[#111827] placeholder:text-[#9CA3AF] focus:border-[#1D6CF0] focus:outline-none"
              />
            </div>

            <div className="flex items-center rounded-[8px] border border-[#E5E7EB]/80 bg-[#F2F4F7] p-0.5">
              {(['all', 'flagged', 'blocked'] as const).map((tab) => (
                <button
                  key={tab}
                  type="button"
                  onClick={() => setFeedFilter(tab)}
                  className={`rounded-[6px] px-2.5 py-1 text-[11.5px] font-medium capitalize transition-colors whitespace-nowrap shrink-0 ${
                    feedFilter === tab
                      ? 'segmented-thumb-shadow bg-white text-[#111827]'
                      : 'text-[#6B7280] hover:text-[#111827]'
                  }`}
                >
                  {tab === 'blocked' ? 'HTTP 403' : tab}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="max-h-[440px] overflow-auto">
          <table className="w-full min-w-[920px] border-collapse text-left text-[12.5px]">
            <thead className="kumo-table-head sticky top-0 z-10 type-caption text-[#6B7280]">
              <tr className="h-[36px]">
                <th className="pl-4 pr-3 font-medium">Time</th>
                <th className="pr-3 font-medium">Source</th>
                <th className="pr-3 font-medium">Operation</th>
                <th className="pr-3 font-medium">Principal</th>
                <th className="pr-3 font-medium">Object / Target</th>
                <th className="pr-3 text-right font-medium">Entropy / ΔH</th>
                <th className="pr-3 font-medium">Signature</th>
                <th className="pr-3 text-right font-medium">HTTP</th>
                <th className="pr-4 font-medium">Signals</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#F3F4F6] tabular-nums">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-10 text-center text-[13px] text-[#6B7280]">
                    No events match the current filter. Upload a file in Live Storage or run a drill
                    in Simulator.
                  </td>
                </tr>
              ) : (
                filteredEvents.slice(0, 80).map((evt) => {
                  const isSelected =
                    inspected?.kind === 'event' && inspected.event.id === evt.id;
                  return (
                    <tr
                      key={evt.id}
                      onClick={() => setInspected({ kind: 'event', event: evt })}
                      className={`h-[40px] cursor-pointer transition-colors ${
                        isSelected ? 'bg-[#EFF6FF]' : 'hover:bg-[#F8F9FB]'
                      }`}
                    >
                      <td className="pl-4 pr-3 text-[12px] text-[#6B7280] whitespace-nowrap">
                        {evt.timestamp.slice(11, 23)}
                      </td>
                      <td className="pr-3 whitespace-nowrap">
                        <span
                          className={`inline-block rounded border px-1.5 py-0.5 text-[11px] font-medium ${sourceBadgeStyle(
                            evt.source,
                          )}`}
                        >
                          {sourceLabel(evt.source)}
                        </span>
                      </td>
                      <td className="pr-3 font-mono text-[11.5px] font-medium text-[#111827] whitespace-nowrap">
                        {evt.apiOp}
                      </td>
                      <td className="pr-3 font-mono text-[11.5px] text-[#4B5563] whitespace-nowrap">
                        {evt.principalId}
                      </td>
                      <td className="max-w-[240px] truncate pr-3 font-mono text-[11.5px] text-[#111827]">
                        {evt.key ? `${evt.bucket}/${evt.key}` : evt.bucket}
                      </td>
                      <td className="pr-3 text-right text-[12px] whitespace-nowrap">
                        {typeof evt.entropy === 'number' ? (
                          <span
                            className={
                              typeof evt.deltaEntropy === 'number' &&
                              evt.deltaEntropy >= state.policy.detection.entropy.delta_threshold
                                ? 'font-semibold text-[#DC2626]'
                                : 'text-[#111827]'
                            }
                          >
                            {evt.entropy.toFixed(2)}
                            {typeof evt.deltaEntropy === 'number' &&
                              ` (${evt.deltaEntropy >= 0 ? '+' : ''}${evt.deltaEntropy.toFixed(2)})`}
                          </span>
                        ) : (
                          <span className="text-[#9CA3AF]">—</span>
                        )}
                      </td>
                      <td className="pr-3 text-[12px] whitespace-nowrap">
                        {evt.magicValid === undefined ? (
                          <span className="text-[#9CA3AF]">—</span>
                        ) : evt.magicValid ? (
                          <span className="text-[#16A34A]">{evt.magicDetected || 'Valid'}</span>
                        ) : (
                          <span className="font-medium text-[#DC2626]">Lost</span>
                        )}
                      </td>
                      <td className="pr-3 text-right text-[12px] whitespace-nowrap">
                        <span
                          className={
                            evt.httpStatus === 403
                              ? 'font-semibold text-[#DC2626]'
                              : 'text-[#4B5563]'
                          }
                        >
                          {evt.httpStatus}
                        </span>
                      </td>
                      <td className="max-w-[220px] truncate pr-4 text-[11.5px]">
                        {evt.selfLoopIgnored ? (
                          <span className="text-[#9CA3AF]">Self-loop ignored</span>
                        ) : evt.signals.length > 0 ? (
                          <span className="font-mono font-medium text-[#DC2626]">
                            {evt.signals.join(' · ')}
                          </span>
                        ) : evt.note ? (
                          <span className="text-[#4B5563]">{evt.note}</span>
                        ) : (
                          <span className="text-[#16A34A]">Clean</span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      <ForensicDrawer target={inspected} onClose={() => setInspected(null)} />
    </div>
  );
};
