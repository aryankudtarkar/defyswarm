import React, { useMemo, useState } from 'react';
import {
  ArrowRight,
  Bell,
  ChevronDown,
  ChevronUp,
  Code2,
  Copy,
  Database,
  Globe,
  HardDrive,
  Plus,
  Radio,
  RefreshCw,
  Shield,
  ShieldCheck,
  Sparkles,
  Upload,
  Vault,
  Webhook,
} from 'lucide-react';
import { SparklineArea } from '../components/Charts.tsx';
import { ForensicDrawer, type ForensicTarget } from '../components/ForensicDrawer.tsx';
import { useConsole } from '../context/ConsoleContext.tsx';

export const OverviewView: React.FC = () => {
  const {
    state,
    navigateTo,
    openSettingsSection,
    setSelectedIncidentId,
    pushToast,
    apiFetch,
  } = useConsole();

  const [expandedNode, setExpandedNode] = useState<'buckets' | 'webhooks' | 'poller' | 'uploads' | null>(null);
  const [bindingsOpen, setBindingsOpen] = useState(true);
  const [forensicTarget, setForensicTarget] = useState<ForensicTarget>(null);
  const [syncing, setSyncing] = useState(false);
  const [hardening, setHardening] = useState(false);

  const eventSeries = useMemo(() => {
    const evs = state?.events ?? [];
    if (evs.length < 2) return [];
    const buckets = new Array(16).fill(0) as number[];
    evs.slice(0, 64).forEach((e, idx) => {
      buckets[15 - (idx % 16)] += 1 + (e.signals.length > 0 ? 2 : 0);
    });
    return buckets;
  }, [state?.events]);

  const entropySeries = useMemo(() => {
    const evs = (state?.events ?? []).filter((e) => typeof e.entropy === 'number').slice(0, 20).reverse();
    if (evs.length < 2) return [];
    return evs.map((e) => e.entropy ?? 4.2);
  }, [state?.events]);

  if (!state) return null;

  const activeBucket = state.storage.productionBucket || state.buckets[0]?.name || 'finance-prod';
  const latestEvent = state.events[0];
  const openIncidents = state.incidents.filter((i) => i.status !== 'RESTORED');
  const revokedCount = state.principals.filter((p) => p.status === 'REVOKED').length;

  const bindingCount =
    1 + // WORM Vault always active
    (state.groq.configured ? 1 : 0) +
    (state.alerts.enabled &&
    (state.alerts.ntfyTopic || state.alerts.discordWebhookUrl || state.alerts.slackWebhookUrl || state.alerts.webhookUrl)
      ? 1
      : 0);

  const copyId = (text: string, label: string) => {
    void navigator.clipboard.writeText(text).then(() => {
      pushToast({ title: `${label} copied`, tone: 'info' });
    });
  };

  const handleManualSync = async () => {
    setSyncing(true);
    try {
      const res = await apiFetch<{ changedCount: number; apiCallsToday: number }>(
        '/api/ingest/poll-now',
        { method: 'POST' },
      );
      pushToast({
        title: 'S3 Bucket Synced',
        detail: `${res.changedCount} changed object(s) inspected · ${res.apiCallsToday} API calls today.`,
        tone: 'success',
      });
    } catch (err) {
      pushToast({
        title: 'Sync skipped',
        detail: err instanceof Error ? err.message : 'Connect an external S3 bucket in Settings first.',
        tone: 'info',
      });
    } finally {
      setSyncing(false);
    }
  };

  const toggleNode = (node: 'buckets' | 'webhooks' | 'poller' | 'uploads') => {
    setExpandedNode((prev) => (prev === node ? null : node));
  };

  const providerLabel =
    state.storage.provider === 'backblaze-b2'
      ? 'Backblaze B2'
      : state.storage.provider === 'supabase-s3'
        ? 'Supabase Storage'
        : state.storage.provider === 'minio'
          ? 'MinIO'
          : state.storage.provider === 'custom-s3'
            ? 'Custom S3'
            : 'Local Sandbox';

  const handleQuickHarden = async () => {
    setHardening(true);
    try {
      await apiFetch(`/api/buckets/${encodeURIComponent(activeBucket)}/harden`, { method: 'POST' });
      pushToast({
        title: `Auto-Harden verified: ${activeBucket}`,
        detail: 'Versioning, WORM Vault, Audit, and Canaries confirmed.',
        tone: 'success',
      });
    } catch (err) {
      pushToast({
        title: 'Auto-Harden failed',
        detail: err instanceof Error ? err.message : 'Error',
        tone: 'error',
      });
    } finally {
      setHardening(false);
    }
  };

  return (
    <div className="mx-auto max-w-[1380px] space-y-6 px-4 py-6 sm:px-6">
      {/* Overview Header with Contextual Posture Actions */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="type-page-title">Overview</h1>
          <p className="mt-1 text-[13px] text-[#6B7280]">
            Live object-storage protection pipeline, bindings, and recent telemetry
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            disabled={hardening}
            onClick={handleQuickHarden}
            className="inline-flex h-[32px] items-center gap-1.5 rounded-[7px] border border-[#E5E7EB] bg-white px-3 type-control text-[#374151] transition-colors hover:border-[#D1D5DB] hover:bg-[#F8F9FA] hover:text-[#111827] disabled:opacity-50 whitespace-nowrap shrink-0"
          >
            <ShieldCheck className="h-3.5 w-3.5 text-[#16A34A]" />
            {hardening ? 'Verifying…' : 'Auto-Harden'}
          </button>
          <button
            type="button"
            onClick={() => openSettingsSection('policy-yaml')}
            className="inline-flex h-[32px] items-center gap-1.5 rounded-[7px] border border-[#E5E7EB] bg-white px-3 type-control text-[#374151] transition-colors hover:border-[#D1D5DB] hover:bg-[#F8F9FA] hover:text-[#111827] whitespace-nowrap shrink-0"
          >
            <Code2 className="h-3.5 w-3.5 text-[#6B7280]" />
            Edit Policy
          </button>
        </div>
      </div>

      {/* Top Status Strip */}
      <div className="surface-card flex flex-wrap items-center justify-between gap-3 px-4 py-2.5">
        <div className="flex flex-wrap items-center gap-3 min-w-0">
          <div className="flex items-center gap-2 text-[13px]">
            <Globe className="h-3.5 w-3.5 shrink-0 text-[#4B5563]" />
            <button
              type="button"
              onClick={() => navigateTo('storage', 'live-files')}
              className="font-medium tracking-[-0.008em] text-[#111827] underline decoration-[#D1D5DB] underline-offset-4 transition-colors hover:decoration-[#1D6CF0]"
            >
              <span className="font-mono">{activeBucket}</span> · {providerLabel}
            </button>
          </div>
          <span className="hidden text-[#D1D5DB] sm:inline">|</span>
          <span className="truncate text-[12.5px] text-[#4B5563]">
            {latestEvent
              ? `Last event: ${latestEvent.apiOp} ${latestEvent.key || latestEvent.bucket} (HTTP ${latestEvent.httpStatus})`
              : 'Detection active · 0 active threats'}
          </span>
        </div>

        <div className="flex items-center gap-3.5 text-[12px] text-[#6B7280] shrink-0 tabular-nums">
          <button
            type="button"
            onClick={() => openSettingsSection('storage-connector')}
            className="inline-flex items-center gap-1.5 rounded-[6px] border border-[#E5E7EB] bg-[#F8F9FA] px-2.5 py-0.5 text-[12px] font-medium text-[#111827] transition-colors hover:border-[#D1D5DB]"
          >
            <Database className="h-3 w-3 text-[#6B7280]" />
            <span>{providerLabel}</span>
          </button>
          <span className="hidden sm:inline text-[12px]">
            {state.health.monitoredObjects} objects · {state.health.activeCanaries} canaries
          </span>
        </div>
      </div>

      {/* Interactive Live Protection Architecture Flow Graph */}
      <section className="topology-stage rounded-[10px] border border-[#E5E7EB] p-5 sm:p-6">
        <div className="grid grid-cols-1 items-center gap-4 lg:grid-cols-[248px_minmax(48px,1fr)_292px_minmax(48px,1fr)_296px] lg:gap-0">
          {/* COLUMN 1: Expandable Ingest & Storage Source Nodes (each collapsed card = 46px tall + 10px gap = 214px total) */}
          <div className="space-y-2.5">
            {/* Node 1: Monitored Buckets */}
            <div className="rounded-[9px] border border-[#E5E7EB] bg-white transition-colors hover:border-[#D1D5DB]">
              <button
                type="button"
                onClick={() => toggleNode('buckets')}
                className="flex h-[44px] w-full items-center justify-between px-3.5 text-left"
              >
                <span className="flex items-center gap-2 text-[13px] font-medium text-[#111827]">
                  <HardDrive className="h-3.5 w-3.5 text-[#6B7280]" />
                  <span>Buckets</span>
                  <span className="rounded bg-[#F3F4F6] px-1.5 py-0.5 text-[11px] font-semibold text-[#4B5563] tabular-nums">
                    {state.buckets.length}
                  </span>
                </span>
                {expandedNode === 'buckets' ? (
                  <ChevronUp className="h-3.5 w-3.5 text-[#6B7280]" />
                ) : (
                  <ChevronDown className="h-3.5 w-3.5 text-[#6B7280]" />
                )}
              </button>
              {expandedNode === 'buckets' && (
                <div className="border-t border-[#E5E7EB] px-3.5 py-2.5 space-y-1.5 text-[11.5px]">
                  {state.buckets.map((b) => (
                    <div key={b.name} className="flex items-center justify-between">
                      <span className="font-mono text-[#111827]">{b.name}</span>
                      <span className="text-[#6B7280] tabular-nums">{b.objectCount} objects</span>
                    </div>
                  ))}
                  <button
                    type="button"
                    onClick={() => navigateTo('storage', 'live-files')}
                    className="mt-1 inline-flex items-center gap-1 text-[11.5px] font-medium text-[#1D6CF0] hover:underline"
                  >
                    Browse files <ArrowRight className="h-3 w-3" />
                  </button>
                </div>
              )}
            </div>

            {/* Node 2: S3 / MinIO Webhooks */}
            <div className="rounded-[9px] border border-[#E5E7EB] bg-white transition-colors hover:border-[#D1D5DB]">
              <button
                type="button"
                onClick={() => toggleNode('webhooks')}
                className="flex h-[44px] w-full items-center justify-between px-3.5 text-left"
              >
                <span className="flex items-center gap-2 text-[13px] font-medium text-[#111827]">
                  <Webhook className="h-3.5 w-3.5 text-[#6B7280]" />
                  <span>Webhooks</span>
                  <span className="rounded bg-[#F3F4F6] px-1.5 py-0.5 text-[11px] font-semibold text-[#4B5563] tabular-nums">
                    {state.ingest?.webhookEventsReceived ?? 0}
                  </span>
                </span>
                {expandedNode === 'webhooks' ? (
                  <ChevronUp className="h-3.5 w-3.5 text-[#6B7280]" />
                ) : (
                  <ChevronDown className="h-3.5 w-3.5 text-[#6B7280]" />
                )}
              </button>
              {expandedNode === 'webhooks' && (
                <div className="border-t border-[#E5E7EB] px-3.5 py-2.5 space-y-1.5 text-[11.5px] text-[#4B5563]">
                  <div className="font-mono text-[11px] text-[#111827]">POST /api/ingest/s3-event</div>
                  <div>Bearer &amp; HMAC-SHA256 verified</div>
                  <button
                    type="button"
                    onClick={() => openSettingsSection('webhooks-containment')}
                    className="inline-flex items-center gap-1 font-medium text-[#1D6CF0] hover:underline"
                  >
                    Configure webhook <ArrowRight className="h-3 w-3" />
                  </button>
                </div>
              )}
            </div>

            {/* Node 3: Bucket Change Poller */}
            <div className="rounded-[9px] border border-[#E5E7EB] bg-white transition-colors hover:border-[#D1D5DB]">
              <button
                type="button"
                onClick={() => toggleNode('poller')}
                className="flex h-[44px] w-full items-center justify-between px-3.5 text-left"
              >
                <span className="flex items-center gap-2 text-[13px] font-medium text-[#111827]">
                  <RefreshCw className="h-3.5 w-3.5 text-[#6B7280]" />
                  <span>Change Poller</span>
                  <span className="rounded bg-[#F3F4F6] px-1.5 py-0.5 text-[11px] font-semibold text-[#4B5563] tabular-nums">
                    {state.ingest?.polledDiffsDetected ?? 0}
                  </span>
                </span>
                {expandedNode === 'poller' ? (
                  <ChevronUp className="h-3.5 w-3.5 text-[#6B7280]" />
                ) : (
                  <ChevronDown className="h-3.5 w-3.5 text-[#6B7280]" />
                )}
              </button>
              {expandedNode === 'poller' && (
                <div className="border-t border-[#E5E7EB] px-3.5 py-2.5 space-y-1.5 text-[11.5px] text-[#4B5563]">
                  <div className="flex justify-between tabular-nums">
                    <span>Interval</span>
                    <span className="font-medium text-[#111827]">{state.storage.pollingIntervalSec}s</span>
                  </div>
                  <div className="flex justify-between tabular-nums">
                    <span>Checks today</span>
                    <span className="font-medium text-[#111827]">{state.storage.apiCallsToday ?? 0}</span>
                  </div>
                  <button
                    type="button"
                    disabled={syncing}
                    onClick={handleManualSync}
                    className="inline-flex items-center gap-1 font-medium text-[#1D6CF0] hover:underline"
                  >
                    {syncing ? 'Syncing…' : 'Sync bucket now'} <ArrowRight className="h-3 w-3" />
                  </button>
                </div>
              )}
            </div>

            {/* Node 4: Direct Uploads */}
            <div className="rounded-[9px] border border-[#E5E7EB] bg-white transition-colors hover:border-[#D1D5DB]">
              <button
                type="button"
                onClick={() => toggleNode('uploads')}
                className="flex h-[44px] w-full items-center justify-between px-3.5 text-left"
              >
                <span className="flex items-center gap-2 text-[13px] font-medium text-[#111827]">
                  <Upload className="h-3.5 w-3.5 text-[#6B7280]" />
                  <span>Live Uploads</span>
                  <span className="rounded bg-[#F3F4F6] px-1.5 py-0.5 text-[11px] font-semibold text-[#4B5563] tabular-nums">
                    {state.ingest?.directUploadsProcessed ?? 0}
                  </span>
                </span>
                {expandedNode === 'uploads' ? (
                  <ChevronUp className="h-3.5 w-3.5 text-[#6B7280]" />
                ) : (
                  <ChevronDown className="h-3.5 w-3.5 text-[#6B7280]" />
                )}
              </button>
              {expandedNode === 'uploads' && (
                <div className="border-t border-[#E5E7EB] px-3.5 py-2.5 space-y-1.5 text-[11.5px] text-[#4B5563]">
                  <div>Drag-and-drop &amp; curl binary API (up to 10 MB)</div>
                  <button
                    type="button"
                    onClick={() => navigateTo('storage', 'live-files')}
                    className="inline-flex items-center gap-1 font-medium text-[#1D6CF0] hover:underline"
                  >
                    Upload &amp; test files <ArrowRight className="h-3 w-3" />
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* COLUMN 2: Flush Edge-to-Edge Left Bus Connector (Desktop) */}
          <div className="relative hidden h-[214px] w-full items-center lg:flex" aria-hidden="true">
            <svg
              className="h-[214px] w-full"
              viewBox="0 0 100 214"
              preserveAspectRatio="none"
              fill="none"
            >
              <path
                d="M 0 23 H 45 Q 50 23 50 29 V 101 Q 50 107 55 107 H 98"
                stroke="#9CA3AF"
                strokeWidth="1.25"
                vectorEffect="non-scaling-stroke"
              />
              <path
                d="M 0 79 H 50"
                stroke="#9CA3AF"
                strokeWidth="1.25"
                vectorEffect="non-scaling-stroke"
              />
              <path
                d="M 0 135 H 50"
                stroke="#9CA3AF"
                strokeWidth="1.25"
                vectorEffect="non-scaling-stroke"
              />
              <path
                d="M 0 191 H 45 Q 50 191 50 185 V 113 Q 50 107 55 107"
                stroke="#9CA3AF"
                strokeWidth="1.25"
                vectorEffect="non-scaling-stroke"
              />
            </svg>
            <svg
              className="pointer-events-none absolute right-0 top-1/2 h-[10px] w-[7px] -translate-y-1/2"
              viewBox="0 0 7 10"
              fill="none"
            >
              <polygon points="0,1 7,5 0,9" fill="#6B7280" />
            </svg>
          </div>

          {/* COLUMN 3: Center DefySwarm Engine Hub Card */}
          <div className="w-full rounded-[11px] border border-[#E5E7EB] bg-white p-4 shadow-[0_6px_20px_-6px_rgba(17,24,39,0.08)]">
            <div className="flex items-center justify-between border-b border-[#F3F4F6] pb-3">
              <div className="flex items-center gap-2">
                <div className="flex h-6 w-6 items-center justify-center rounded-[6px] bg-gradient-to-br from-[#F6821F] to-[#EA580C] text-white">
                  <Shield className="h-3.5 w-3.5" />
                </div>
                <span className="type-section text-[14px]">
                  DefySwarm Engine
                </span>
              </div>
              <span
                className="flex h-4 w-4 items-center justify-center rounded-full bg-[#DBEAFE]"
                title="Control plane active"
              >
                <span className="h-2 w-2 rounded-full bg-[#1D6CF0]" />
              </span>
            </div>

            <div className="mt-3 space-y-2.5 text-[12.5px]">
              <div className="type-caption text-[#6B7280]">Protection Posture</div>

              <div className="flex items-center justify-between gap-2">
                <span className="text-[#111827]">Threat Detection</span>
                <span className="flex-1 border-b border-dashed border-[#E5E7EB]" />
                <span className="inline-flex items-center gap-1.5 text-[12px] font-medium text-[#111827]">
                  <span className="h-1.5 w-1.5 rounded-full bg-[#16A34A]" />
                  Enabled
                </span>
              </div>

              <div className="flex items-center justify-between gap-2">
                <span className="text-[#111827]">Enforcement Mode</span>
                <span className="flex-1 border-b border-dashed border-[#E5E7EB]" />
                <span className="inline-flex items-center gap-1.5 text-[12px] font-medium text-[#111827]">
                  <span
                    className={`h-1.5 w-1.5 rounded-full ${
                      state.policy.mode === 'active' ? 'bg-[#16A34A]' : 'bg-[#D97706]'
                    }`}
                  />
                  {state.policy.mode === 'active' ? 'Active' : 'Dry-Run'}
                </span>
              </div>

              <div className="flex items-center justify-between gap-2">
                <span className="text-[#111827]">Vault Replication</span>
                <span className="flex-1 border-b border-dashed border-[#E5E7EB]" />
                <span className="inline-flex items-center gap-1.5 text-[12px] font-medium text-[#4B5563]">
                  <span
                    className={`h-1.5 w-1.5 rounded-full ${
                      state.vault.replicationPaused ? 'bg-[#D97706]' : 'bg-[#16A34A]'
                    }`}
                  />
                  {state.vault.replicationPaused ? 'Paused' : 'Protected'}
                </span>
              </div>
            </div>
          </div>

          {/* COLUMN 4: Flush Edge-to-Edge Right Outbound Connector (Desktop) */}
          <div className="hidden w-full items-center lg:flex" aria-hidden="true">
            <div className="h-[1.25px] flex-1 bg-[#9CA3AF]" />
            <svg
              className="-ml-[1px] h-[10px] w-[7px] shrink-0"
              viewBox="0 0 7 10"
              fill="none"
            >
              <polygon points="0,1 7,5 0,9" fill="#6B7280" />
            </svg>
          </div>

          {/* COLUMN 5: Bindings Card (Immutable Vault, AI Analysis, Alerts) with fixed-axis arrow alignment */}
          <div className="rounded-[9px] border border-[#E5E7EB] bg-white">
            <button
              type="button"
              onClick={() => setBindingsOpen((prev) => !prev)}
              className="flex h-[44px] w-full items-center justify-between px-4 text-left"
            >
              <span className="flex items-center gap-2 text-[13px] font-medium text-[#111827]">
                <span>Bindings</span>
                <span className="rounded bg-[#F3F4F6] px-1.5 py-0.5 text-[11px] font-semibold text-[#4B5563] tabular-nums">
                  {bindingCount}
                </span>
              </span>
              {bindingsOpen ? (
                <ChevronUp className="h-3.5 w-3.5 text-[#6B7280]" />
              ) : (
                <ChevronDown className="h-3.5 w-3.5 text-[#6B7280]" />
              )}
            </button>

            {bindingsOpen && (
              <div className="divide-y divide-[#E5E7EB] border-t border-[#E5E7EB]">
                <button
                  type="button"
                  onClick={() => openSettingsSection('storage-connector')}
                  className="flex h-[38px] w-full items-center justify-between px-4 text-[12.5px] text-[#4B5563] transition-colors hover:bg-[#F9FAFB] hover:text-[#111827]"
                >
                  <span>Add or edit binding</span>
                  <Plus className="h-3.5 w-3.5 text-[#6B7280]" />
                </button>

                <div className="space-y-3 px-4 py-3 text-[12px]">
                  <div>
                    <div className="text-[11px] text-[#6B7280]">Immutable Vault</div>
                    <div className="mt-1 grid grid-cols-[54px_20px_1fr] items-center gap-1.5">
                      <span className="font-mono font-medium text-[#111827]">VAULT</span>
                      <span className="text-center text-[#9CA3AF]">→</span>
                      <div className="flex justify-end min-w-0">
                        <button
                          type="button"
                          onClick={() => navigateTo('storage', 'canaries-vault')}
                          className="inline-flex max-w-full items-center gap-1 truncate font-medium text-[#111827] underline decoration-[#D1D5DB] underline-offset-4 hover:decoration-[#1D6CF0]"
                        >
                          <Vault className="h-3.5 w-3.5 shrink-0 text-[#1D6CF0]" />
                          <span className="truncate font-mono">{state.vault.vaultBucket}</span>
                        </button>
                      </div>
                    </div>
                  </div>

                  <div>
                    <div className="text-[11px] text-[#6B7280]">AI Threat Analysis</div>
                    <div className="mt-1 grid grid-cols-[54px_20px_1fr] items-center gap-1.5">
                      <span className="font-mono font-medium text-[#111827]">AI</span>
                      <span className="text-center text-[#9CA3AF]">→</span>
                      <div className="flex justify-end min-w-0">
                        <button
                          type="button"
                          onClick={() => openSettingsSection('groq-ai')}
                          className="inline-flex max-w-full items-center gap-1 truncate font-medium text-[#111827] underline decoration-[#D1D5DB] underline-offset-4 hover:decoration-[#1D6CF0]"
                        >
                          <Sparkles className="h-3.5 w-3.5 shrink-0 text-[#1D6CF0]" />
                          <span className="truncate">
                            {state.groq.configured ? 'Connected' : 'Configure AI'}
                          </span>
                        </button>
                      </div>
                    </div>
                  </div>

                  <div>
                    <div className="text-[11px] text-[#6B7280]">Incident Alerts</div>
                    <div className="mt-1 grid grid-cols-[54px_20px_1fr] items-center gap-1.5">
                      <span className="font-mono font-medium text-[#111827]">NOTIFY</span>
                      <span className="text-center text-[#9CA3AF]">→</span>
                      <div className="flex justify-end min-w-0">
                        <button
                          type="button"
                          onClick={() => openSettingsSection('alert-channels')}
                          className="inline-flex max-w-full items-center gap-1 truncate font-medium text-[#111827] underline decoration-[#D1D5DB] underline-offset-4 hover:decoration-[#1D6CF0]"
                        >
                          <Bell className="h-3.5 w-3.5 shrink-0 text-[#6B7280]" />
                          <span className="truncate">
                            {state.alerts.ntfyTopic
                              ? `ntfy.sh/${state.alerts.ntfyTopic}`
                              : state.alerts.discordWebhookUrl
                                ? 'Discord Webhook'
                                : 'Configure alerts'}
                          </span>
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Metrics Sparkline Card + Protected Endpoints Summary */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
        {/* Metrics 3-column Sparkline Strip (flex-col so cells anchor cleanly to card bottom) */}
        <section className="surface-card flex flex-col overflow-hidden lg:col-span-8">
          <div className="flex items-center justify-between border-b border-[#E5E7EB] px-4 py-3">
            <div className="flex items-center gap-2.5">
              <h2 className="type-section text-[14px]">Metrics</h2>
              <span className="type-caption text-[#6B7280]">
                Live window
              </span>
            </div>
            <button
              type="button"
              onClick={() => navigateTo('validation', 'analytics')}
              className="inline-flex items-center gap-1 text-[12px] font-medium text-[#6B7280] transition-colors hover:text-[#111827]"
            >
              <span>Analytics</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>

          <div className="grid flex-1 grid-cols-1 divide-y divide-[#E5E7EB] sm:grid-cols-3 sm:divide-y-0 sm:divide-x tabular-nums">
            <div className="flex flex-col justify-between pt-4">
              <div className="px-4">
                <div className="text-[12px] font-medium text-[#6B7280]">Events / min</div>
                <div className="mt-1.5 flex items-baseline gap-2.5">
                  <span className="type-kpi text-[#111827]">
                    {state.health.eventsPerMinute}
                  </span>
                  <span className="text-[12px] font-medium text-[#16A34A]">
                    {state.events.length} total
                  </span>
                </div>
              </div>
              <div className="mt-auto pt-4">
                <SparklineArea
                  values={eventSeries}
                  empty={eventSeries.length < 2}
                  emptyLabel="No data"
                  fillId="ov-events-spark"
                />
              </div>
            </div>

            <div className="flex flex-col justify-between pt-4">
              <div className="px-4">
                <div className="text-[12px] font-medium text-[#6B7280]">Avg Ingestion Latency</div>
                <div className="mt-1.5 flex items-baseline gap-2">
                  <span className="type-kpi text-[#111827]">
                    {state.health.avgIngestionLatencyMs}
                    <span className="ml-0.5 text-[16px] font-medium text-[#6B7280]">ms</span>
                  </span>
                  <span className="text-[12px] text-[#6B7280]">Header scan</span>
                </div>
              </div>
              <div className="mt-auto pt-4">
                <SparklineArea
                  values={entropySeries}
                  empty={entropySeries.length < 2}
                  emptyLabel="No data"
                  fillId="ov-latency-spark"
                />
              </div>
            </div>

            <div className="flex flex-col justify-between pt-4">
              <div className="px-4">
                <div className="text-[12px] font-medium text-[#6B7280]">Active Threats / Revoked</div>
                <div className="mt-1.5 flex items-baseline gap-2.5">
                  <span
                    className={`type-kpi ${
                      openIncidents.length > 0 ? 'text-[#DC2626]' : 'text-[#111827]'
                    }`}
                  >
                    {openIncidents.length}
                  </span>
                  <span className="text-[12px] text-[#6B7280]">
                    {revokedCount} quarantined
                  </span>
                </div>
              </div>
              <div className="mt-auto pt-4">
                <div className="relative flex h-[46px] items-center justify-center px-4">
                  <div className="pointer-events-none absolute inset-x-0 top-1/2 -translate-y-1/2 border-b border-[#E5E7EB]" />
                  {openIncidents.length === 0 ? (
                    <span className="relative z-10 inline-flex items-center gap-1.5 bg-white px-2.5 text-[11.5px] font-medium text-[#16A34A]">
                      <span className="h-1.5 w-1.5 rounded-full bg-[#16A34A]" />
                      0 active threats
                    </span>
                  ) : (
                    <button
                      type="button"
                      onClick={() => navigateTo('threat-ops', 'incidents')}
                      className="relative z-10 rounded-[6px] border border-[#FECACA] bg-[#FEF2F2] px-2.5 py-0.5 text-[11.5px] font-medium text-[#DC2626] transition-colors hover:bg-[#FEE2E2]"
                    >
                      Inspect {openIncidents.length} incident(s) →
                    </button>
                  )}
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Right Summary Card: Protected Endpoints & Ingestion */}
        <section className="surface-card overflow-hidden lg:col-span-4">
          <div className="flex items-center justify-between border-b border-[#E5E7EB] px-4 py-3">
            <h2 className="type-section text-[14px]">Protected Endpoints</h2>
            <button
              type="button"
              onClick={() => openSettingsSection('storage-connector')}
              className="text-[#6B7280] transition-colors hover:text-[#111827]"
              aria-label="Open storage settings"
            >
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>
          <div className="divide-y divide-[#F3F4F6] px-4 text-[12.5px]">
            <div className="py-3">
              <div className="type-caption text-[#6B7280]">Primary Bucket</div>
              <div className="mt-0.5 type-mono-data text-[12px] font-medium text-[#111827] truncate">
                {activeBucket} ({providerLabel})
              </div>
            </div>
            <div className="py-3">
              <div className="type-caption text-[#6B7280]">Webhook Receiver</div>
              <div className="mt-0.5 type-mono-data text-[12px] text-[#111827] truncate">/api/ingest/s3-event</div>
            </div>
            <div className="py-3">
              <div className="type-caption text-[#6B7280]">Clean WORM Vault</div>
              <div className="mt-0.5 type-mono-data text-[12px] text-[#111827]">
                {state.vault.vaultBucket} · {state.vault.manifestCount} verified snapshots
              </div>
            </div>
          </div>
        </section>
      </div>

      {/* Recent Telemetry & Incidents Activity Table */}
      <section className="surface-card overflow-hidden">
        <div className="flex items-center justify-between border-b border-[#E5E7EB] px-4 py-3">
          <div className="flex items-center gap-2">
            <Radio className="h-3.5 w-3.5 text-[#1D6CF0]" />
            <h2 className="type-section text-[14px]">Recent Telemetry &amp; Incidents</h2>
          </div>
          <button
            type="button"
            onClick={() => navigateTo('threat-ops', 'telemetry')}
            className="inline-flex items-center gap-1 text-[12px] font-medium text-[#6B7280] transition-colors hover:text-[#111827]"
          >
            <span>Open Live Telemetry</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </button>
        </div>

        {state.events.length === 0 && state.incidents.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-10 px-4 text-center">
            <p className="text-[13px] font-medium text-[#111827]">No live events recorded yet</p>
            <p className="mt-1 text-[12px] text-[#6B7280]">
              Upload a real file in Storage, send a curl request, or run a safe drill in Simulator.
            </p>
            <div className="mt-4 flex items-center gap-2">
              <button
                type="button"
                onClick={() => navigateTo('storage', 'live-files')}
                className="rounded-md bg-[#1D6CF0] px-3.5 py-1.5 text-[12px] font-medium text-white hover:bg-[#1558D6]"
              >
                Upload Real File
              </button>
              <button
                type="button"
                onClick={() => navigateTo('validation', 'simulator')}
                className="rounded-md border border-[#D1D5DB] bg-white px-3.5 py-1.5 text-[12px] font-medium text-[#374151] hover:bg-[#F9FAFB]"
              >
                Run Simulator Drill
              </button>
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[12.5px]">
              <tbody className="divide-y divide-[#F3F4F6]">
                {state.incidents.slice(0, 3).map((inc) => (
                  <tr
                    key={inc.id}
                    onClick={() => {
                      setSelectedIncidentId(inc.id);
                      navigateTo('threat-ops', 'incidents');
                    }}
                    className="h-[42px] cursor-pointer bg-[#FEF2F2]/40 transition-colors hover:bg-[#FEF2F2]/80"
                  >
                    <td className="px-4 font-mono text-[12px] text-[#6B7280] whitespace-nowrap">
                      <span className="inline-flex items-center gap-1.5">
                        {inc.id}
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            copyId(inc.id, 'Incident ID');
                          }}
                          className="text-[#9CA3AF] hover:text-[#111827]"
                          aria-label={`Copy ${inc.id}`}
                        >
                          <Copy className="h-3 w-3" />
                        </button>
                      </span>
                    </td>
                    <td className="px-4 font-medium text-[#111827] max-w-[380px] truncate">
                      {inc.title}
                    </td>
                    <td className="px-4 whitespace-nowrap">
                      <span className="inline-flex items-center gap-1.5 font-medium text-[#DC2626]">
                        <span className="h-1.5 w-1.5 rounded-full bg-[#DC2626]" />
                        {inc.status}
                      </span>
                    </td>
                    <td className="px-4 font-mono text-[11.5px] text-[#4B5563] whitespace-nowrap">
                      {inc.bucket}
                    </td>
                    <td className="px-4 text-right font-mono text-[11.5px] text-[#6B7280] whitespace-nowrap tabular-nums">
                      {new Date(inc.detectedAtMs).toISOString().slice(11, 19)} UTC
                    </td>
                  </tr>
                ))}

                {state.events.slice(0, 8).map((ev) => {
                  const isFlagged = ev.signals.length > 0 || ev.httpStatus === 403;
                  return (
                    <tr
                      key={ev.id}
                      onClick={() => setForensicTarget({ kind: 'event', event: ev })}
                      className="h-[40px] cursor-pointer transition-colors hover:bg-[#F9FAFB]"
                    >
                      <td className="px-4 font-mono text-[12px] text-[#6B7280] whitespace-nowrap">
                        <span className="inline-flex items-center gap-1.5">
                          {ev.id.slice(0, 9)}
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              copyId(ev.id, 'Event ID');
                            }}
                            className="text-[#9CA3AF] hover:text-[#111827]"
                            aria-label="Copy Event ID"
                          >
                            <Copy className="h-3 w-3" />
                          </button>
                        </span>
                      </td>
                      <td className="px-4 text-[#111827] max-w-[380px] truncate">
                        <span className="font-mono text-[12px] font-medium">{ev.apiOp}</span>{' '}
                        <span className="text-[#4B5563]">{ev.key || ev.bucket}</span>
                      </td>
                      <td className="px-4 whitespace-nowrap">
                        <span
                          className={`inline-flex items-center gap-1.5 font-mono text-[12px] font-medium tabular-nums ${
                            isFlagged ? 'text-[#DC2626]' : 'text-[#16A34A]'
                          }`}
                        >
                          <span
                            className={`h-1.5 w-1.5 rounded-full ${
                              isFlagged ? 'bg-[#DC2626]' : 'bg-[#16A34A]'
                            }`}
                          />
                          HTTP {ev.httpStatus}
                        </span>
                      </td>
                      <td className="px-4 font-mono text-[11.5px] text-[#4B5563] whitespace-nowrap">
                        {ev.principalId}
                      </td>
                      <td className="px-4 text-right font-mono text-[11.5px] text-[#6B7280] whitespace-nowrap tabular-nums">
                        {ev.timestamp.slice(11, 19)} UTC
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <ForensicDrawer target={forensicTarget} onClose={() => setForensicTarget(null)} />
    </div>
  );
};
