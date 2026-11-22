import React, { useMemo, useState } from 'react';
import { Activity, AlertTriangle, CheckCircle2, Search } from 'lucide-react';
import { useConsole } from '../context/ConsoleContext.tsx';

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export const HealthView: React.FC = () => {
  const { state, wsConnected, apiFetch, pushToast } = useConsole();
  const [auditQuery, setAuditQuery] = useState('');
  const [togglingGap, setTogglingGap] = useState(false);

  const filteredAudit = useMemo(() => {
    const list = state?.auditLog ?? [];
    const q = auditQuery.trim().toLowerCase();
    if (!q) return list;
    return list.filter(
      (a) =>
        a.action.toLowerCase().includes(q) ||
        a.target.toLowerCase().includes(q) ||
        a.detail.toLowerCase().includes(q) ||
        a.role.toLowerCase().includes(q),
    );
  }, [state?.auditLog, auditQuery]);

  if (!state) return null;

  const h = state.health;

  const toggleStreamGap = async () => {
    setTogglingGap(true);
    try {
      await apiFetch('/api/health/stream-gap', {
        method: 'POST',
        body: JSON.stringify({ simulated: !h.streamGapSimulated }),
      });
      pushToast({
        title: !h.streamGapSimulated ? 'Stream-Gap Alarm Triggered' : 'Stream Ingestion Restored',
        detail: !h.streamGapSimulated
          ? 'Degraded banner active across the DefySwarm console.'
          : 'Live event ingestion resumed normally.',
        tone: !h.streamGapSimulated ? 'warning' : 'success',
      });
    } catch (err) {
      pushToast({
        title: 'Action denied',
        detail: err instanceof Error ? err.message : 'Operator or Admin role required.',
        tone: 'error',
      });
    } finally {
      setTogglingGap(false);
    }
  };

  return (
    <div className="mx-auto max-w-[1380px] space-y-6 px-4 py-6 sm:px-6">
      {/* Header Row */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="type-page-title">
            Usage &amp; System Health
          </h1>
          <p className="mt-1.5 text-[13px] text-[#6B7280]">
            Ingestion pipeline health, AI request budget, and immutable operator audit trail.
          </p>
        </div>

        <button
          type="button"
          disabled={togglingGap}
          onClick={toggleStreamGap}
          className={`inline-flex h-[32px] items-center gap-1.5 rounded-[7px] border px-3.5 type-control transition-colors whitespace-nowrap shrink-0 ${
            h.streamGapSimulated
              ? 'border-[#BBF7D0] bg-[#F0FDF4] text-[#15803D] hover:bg-[#DCFCE7]'
              : 'border-[#FDE68A] bg-[#FFFBEB] text-[#B45309] hover:bg-[#FEF3C7]'
          }`}
        >
          <Activity className="h-3.5 w-3.5" />
          {h.streamGapSimulated ? 'Restore Stream Health' : 'Simulate Stream Gap'}
        </button>
      </div>

      {/* 4-Cell Operational KPI Ledger */}
      <div className="surface-card grid grid-cols-1 divide-y divide-[#E5E7EB] overflow-hidden sm:grid-cols-2 sm:divide-y-0 sm:divide-x xl:grid-cols-4">
        <div className="px-4 py-4">
          <p className="text-[12px] font-medium text-[#6B7280]">Events Ingested (60s)</p>
          <p className="mt-2 type-kpi text-[26px] text-[#111827]">
            {h.eventsPerMinute}
            <span className="ml-1 text-[14px] font-medium text-[#6B7280]">/ min</span>
          </p>
          <p className="mt-1 text-[12px] text-[#6B7280] tabular-nums">
            Avg ingestion latency: {h.avgIngestionLatencyMs} ms
          </p>
        </div>

        <div className="px-4 py-4">
          <p className="text-[12px] font-medium text-[#6B7280]">Monitored Inventory</p>
          <p className="mt-2 type-kpi text-[26px] text-[#111827]">
            {h.monitoredObjects}
          </p>
          <p className="mt-1 text-[12px] text-[#6B7280] tabular-nums">
            {h.monitoredBuckets} buckets · {h.activeCanaries} active canaries
          </p>
        </div>

        <div className="px-4 py-4">
          <p className="text-[12px] font-medium text-[#6B7280]">Vault Footprint</p>
          <p className="mt-2 type-kpi text-[26px] text-[#111827]">
            {formatBytes(h.vaultSizeBytes)}
          </p>
          <p className="mt-1 text-[12px] text-[#6B7280] tabular-nums">
            {state.vault.manifestCount} clean snapshots verified
          </p>
        </div>

        <div className="px-4 py-4">
          <p className="text-[12px] font-medium text-[#6B7280]">Control Plane Uptime</p>
          <p className="mt-2 type-kpi text-[26px] text-[#16A34A]">
            {h.uptimeSeconds}s
          </p>
          <p className="mt-1 text-[12px] text-[#6B7280] tabular-nums">
            Heartbeat {h.lastHeartbeatAt.slice(11, 19)} UTC
          </p>
        </div>
      </div>

      {/* 4-Column Component Health Strip */}
      <div className="surface-card grid grid-cols-1 divide-y divide-[#E5E7EB] overflow-hidden md:grid-cols-2 md:divide-y-0 md:divide-x xl:grid-cols-4">
        {[
          {
            name: 'Detection Engine',
            healthy: h.engineStatus === 'healthy',
            detail: h.streamGapSimulated
              ? 'Degraded — ingestion gap simulated'
              : '4 signals & swarm windows active',
          },
          {
            name: 'Control Plane API',
            healthy: h.apiStatus === 'healthy',
            detail: 'REST + RBAC enforcement online',
          },
          {
            name: 'Live WebSocket (/ws/live)',
            healthy: wsConnected,
            detail: wsConnected
              ? 'Sub-second event push connected'
              : 'Disconnected — auto-retrying',
          },
          {
            name: 'Alert Delivery',
            healthy: state.alerts.lastDeliveryStatus !== 'error',
            detail: state.alerts.enabled
              ? `${state.alerts.deliveredCount} alert(s) delivered`
              : 'Console feed active · webhooks optional',
          },
        ].map((comp) => (
          <div key={comp.name} className="flex items-start justify-between gap-3 px-4 py-3.5">
            <div>
              <p className="text-[13px] font-semibold text-[#111827]">{comp.name}</p>
              <p className="mt-0.5 text-[12px] text-[#6B7280]">{comp.detail}</p>
            </div>
            {comp.healthy ? (
              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-[#16A34A]" />
            ) : (
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-[#D97706]" />
            )}
          </div>
        ))}
      </div>

      {/* Operator Audit Log */}
      <section className="surface-card overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#E5E7EB] bg-[#F8F9FA] px-5 py-3">
          <div className="flex flex-wrap items-baseline gap-x-2.5 gap-y-0.5">
            <h2 className="type-section text-[14px]">
              Operator Audit Log ({filteredAudit.length})
            </h2>
            <span className="text-[12px] text-[#6B7280]">
              Every privileged action and RBAC denial recorded with role and timestamp
            </span>
          </div>
          <div className="relative w-full sm:w-64">
            <Search className="pointer-events-none absolute left-2.5 top-2 h-3.5 w-3.5 text-[#9CA3AF]" />
            <input
              type="text"
              value={auditQuery}
              onChange={(e) => setAuditQuery(e.target.value)}
              placeholder="Filter action, role, target…"
              className="h-[30px] w-full rounded-[7px] border border-[#D1D5DB] bg-white pl-8 pr-3 text-[12px] text-[#111827] placeholder:text-[#9CA3AF] focus:border-[#1D6CF0] focus:outline-none"
            />
          </div>
        </div>

        <div className="overflow-x-auto bg-white">
          <table className="w-full min-w-[740px] text-left text-[12.5px]">
            <thead className="kumo-table-head">
              <tr className="h-[36px] type-caption text-[#6B7280]">
                <th className="pl-5 pr-3 font-medium">Timestamp</th>
                <th className="px-3 font-medium">Role</th>
                <th className="px-3 font-medium">Action</th>
                <th className="px-3 font-medium">Target</th>
                <th className="px-3 font-medium">Outcome</th>
                <th className="pl-3 pr-5 font-medium">Detail</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#F3F4F6]">
              {filteredAudit.map((entry) => (
                <tr key={entry.id} className="h-[40px] transition-colors hover:bg-[#F8F9FB]">
                  <td className="whitespace-nowrap pl-5 pr-3 text-[12px] text-[#6B7280] tabular-nums">
                    {entry.timestamp.slice(0, 19).replace('T', ' ')}
                  </td>
                  <td className="px-3 text-[12px] font-medium capitalize text-[#111827]">
                    {entry.role}
                  </td>
                  <td className="px-3 font-mono text-[11.5px] font-medium text-[#1D6CF0]">
                    {entry.action}
                  </td>
                  <td className="px-3 font-mono text-[11.5px] text-[#4B5563]">{entry.target}</td>
                  <td className="px-3 text-[12px] font-medium capitalize">
                    <span
                      className={
                        entry.outcome === 'success'
                          ? 'text-[#16A34A]'
                          : entry.outcome === 'denied'
                            ? 'text-[#D97706]'
                            : 'text-[#DC2626]'
                      }
                    >
                      {entry.outcome}
                    </span>
                  </td>
                  <td className="pl-3 pr-5 text-[12px] text-[#4B5563]">{entry.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
