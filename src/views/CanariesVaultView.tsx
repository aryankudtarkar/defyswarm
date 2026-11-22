import React, { useState } from 'react';
import {
  BrainCircuit,
  KeyRound,
  Lock,
  RefreshCw,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import { useConsole } from '../context/ConsoleContext.tsx';

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export const CanariesVaultView: React.FC = () => {
  const { state, apiFetch, pushToast, openSettingsSection, setShowOnboarding } = useConsole();
  const [refreshing, setRefreshing] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [classifying, setClassifying] = useState(false);

  if (!state) return null;

  const latestAudit = state.classifierAudits[0] ?? null;
  const quota = state.groq.quota;

  const handleRefreshCanaries = async () => {
    setRefreshing(true);
    try {
      const res = await apiFetch<{ refreshedCount: number }>('/api/canaries/refresh', {
        method: 'POST',
        body: JSON.stringify({ bucket: 'finance-prod' }),
      });
      pushToast({
        title: 'Canaries Rotated (Self-Loop Safe)',
        detail: `Refreshed ${res.refreshedCount} canaries under defyswarm-service with 0 alerts.`,
        tone: 'success',
      });
    } catch (err) {
      pushToast({
        title: 'Refresh failed',
        detail: err instanceof Error ? err.message : 'Unable to refresh canaries.',
        tone: 'error',
      });
    } finally {
      setRefreshing(false);
    }
  };

  const handleGenerateCanaries = async () => {
    setGenerating(true);
    try {
      const res = await apiFetch<{ installed: unknown[]; tokensUsed: number }>(
        '/api/canaries/generate',
        {
          method: 'POST',
          body: JSON.stringify({ bucket: 'finance-prod' }),
        },
      );
      pushToast({
        title: 'Adaptive Canaries Deployed',
        detail: `Deployed ${res.installed.length} tenant-matched decoy objects.`,
        tone: 'success',
      });
    } catch (err) {
      pushToast({
        title: 'AI Generation Notice',
        detail: err instanceof Error ? err.message : 'Generation failed.',
        tone: 'error',
      });
    } finally {
      setGenerating(false);
    }
  };

  const handleRunClassifier = async () => {
    setClassifying(true);
    try {
      const res = await apiFetch<{ audit: { accuracyPct: number; tokensUsed: number } }>(
        '/api/canaries/classify',
        {
          method: 'POST',
          body: JSON.stringify({ bucket: 'finance-prod' }),
        },
      );
      pushToast({
        title: 'AI Evasion Audit Complete',
        detail: `Blind classifier scored ${res.audit.accuracyPct}% accuracy across mixed objects.`,
        tone: 'info',
      });
    } catch (err) {
      pushToast({
        title: 'Audit Notice',
        detail: err instanceof Error ? err.message : 'Audit failed.',
        tone: 'error',
      });
    } finally {
      setClassifying(false);
    }
  };

  return (
    <div className="mx-auto max-w-[1380px] space-y-6 px-4 py-6 sm:px-6">
      {/* Header Row */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="type-page-title">
            Canaries &amp; Immutable Vault
          </h1>
          <p className="mt-1.5 text-[13px] text-[#6B7280]">
            Tenant-matched decoy objects, AI-assisted evasion testing, and isolated WORM snapshot
            protection.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            disabled={refreshing}
            onClick={handleRefreshCanaries}
            className="inline-flex h-[32px] items-center gap-1.5 rounded-[7px] border border-[#D1D5DB] bg-white px-3 type-control text-[#374151] transition-colors hover:bg-[#F8F9FA] disabled:opacity-50 whitespace-nowrap shrink-0"
          >
            <RefreshCw className={`h-3.5 w-3.5 text-[#6B7280] ${refreshing ? 'animate-spin' : ''}`} />
            Refresh Now
          </button>

          <button
            type="button"
            disabled={generating || quota.cooldownSecondsRemaining > 0}
            onClick={handleGenerateCanaries}
            className="inline-flex h-[32px] items-center gap-1.5 rounded-[7px] bg-[#1D6CF0] px-3.5 type-control text-white transition-colors hover:bg-[#1558D6] disabled:opacity-50 whitespace-nowrap shrink-0"
          >
            <Sparkles className="h-3.5 w-3.5" />
            {generating ? 'Generating…' : 'Generate Adaptive Canaries'}
          </button>
        </div>
      </div>

      {/* 4-Cell WORM Vault Telemetry Strip */}
      <div className="surface-card grid grid-cols-1 divide-y divide-[#E5E7EB] overflow-hidden sm:grid-cols-2 sm:divide-y-0 sm:divide-x xl:grid-cols-4">
        <div className="px-4 py-4">
          <div className="flex items-center justify-between text-[12px] font-medium text-[#6B7280]">
            <span>Vault Retention</span>
            <Lock className="h-3.5 w-3.5 text-[#16A34A]" />
          </div>
          <p className="mt-2 type-kpi text-[22px] text-[#111827]">
            {state.vault.retentionMode} · {state.vault.retentionDays}d
          </p>
          <p className="mt-1 truncate text-[12px] text-[#16A34A]">
            Isolated · <span className="font-mono">{state.vault.vaultBucket}</span>
          </p>
        </div>

        <div className="px-4 py-4">
          <p className="text-[12px] font-medium text-[#6B7280]">Replication Lag</p>
          <p className="mt-2 type-kpi text-[24px] text-[#111827]">
            {state.vault.avgReplicationLagMs} ms
          </p>
          <p className="mt-1 text-[12px] text-[#6B7280]">
            {state.vault.replicationPaused
              ? 'Paused during active incident'
              : 'Recovery point continuously verified'}
          </p>
        </div>

        <div className="px-4 py-4">
          <p className="text-[12px] font-medium text-[#6B7280]">Clean-Version Manifest</p>
          <p className="mt-2 type-kpi text-[24px] text-[#16A34A]">
            {state.vault.manifestIntegrityPct}% verified
          </p>
          <p className="mt-1 text-[12px] text-[#6B7280] tabular-nums">
            {state.vault.manifestCount} snapshots · {formatBytes(state.vault.totalVaultBytes)}
          </p>
        </div>

        <div className="px-4 py-4">
          <p className="text-[12px] font-medium text-[#6B7280]">Evasion Audit Score</p>
          <p className="mt-2 type-kpi text-[24px] text-[#111827]">
            {latestAudit ? `${latestAudit.accuracyPct}%` : 'Not Run'}
          </p>
          <p className="mt-1 text-[12px] text-[#6B7280]">Target: near 50% (indistinguishable)</p>
        </div>
      </div>

      {/* AI Canary Evasion Audit */}
      <section className="overflow-hidden rounded-lg border border-[#E5E7EB] bg-white">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#E5E7EB] bg-[#F9FAFB] px-5 py-3.5">
          <div className="flex items-start gap-2.5">
            <BrainCircuit className="mt-0.5 h-4 w-4 shrink-0 text-[#1D6CF0]" />
            <div>
              <h2 className="text-[14px] font-semibold text-[#111827]">
                AI Canary Evasion Audit
              </h2>
              <p className="mt-0.5 text-[12.5px] text-[#4B5563]">
                Evaluates a blind 50/50 mix of real business objects and deployed canaries. Accuracy
                near 50% confirms automated attackers cannot selectively skip decoys.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {!state.groq.configured ? (
              <button
                type="button"
                onClick={() => setShowOnboarding(true)}
                className="inline-flex h-[32px] items-center gap-1.5 rounded-md bg-[#1D6CF0] px-3.5 text-[12.5px] font-medium text-white hover:bg-[#1558D6] transition-colors whitespace-nowrap shrink-0"
              >
                <KeyRound className="h-3.5 w-3.5" />
                Connect AI Key
              </button>
            ) : (
              <button
                type="button"
                disabled={classifying || quota.cooldownSecondsRemaining > 0}
                onClick={handleRunClassifier}
                className="inline-flex h-[32px] items-center gap-1.5 rounded-md border border-[#D1D5DB] bg-white px-3.5 text-[12.5px] font-medium text-[#374151] hover:bg-[#F9FAFB] transition-colors disabled:opacity-50 whitespace-nowrap shrink-0"
              >
                {classifying
                  ? 'Evaluating 10 Files…'
                  : quota.cooldownSecondsRemaining > 0
                    ? `Cooldown (${quota.cooldownSecondsRemaining}s)`
                    : 'Run Evasion Audit'}
              </button>
            )}
          </div>
        </div>

        {/* Inline AI Request Budget Readout */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#E5E7EB] bg-white px-5 py-2.5 text-[12px] text-[#4B5563] tabular-nums">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <span>
              AI Engine:{' '}
              <strong className={state.groq.configured ? 'text-[#16A34A]' : 'text-[#D97706]'}>
                {state.groq.configured ? 'Connected' : 'Not configured'}
              </strong>
            </span>
            <span className="text-[#D1D5DB]" aria-hidden="true">
              ·
            </span>
            <span>
              Tokens/min {quota.tpmUsed.toLocaleString()}/{quota.tpmLimit.toLocaleString()}
            </span>
            <span className="text-[#D1D5DB]" aria-hidden="true">
              ·
            </span>
            <span>
              Req/min {quota.rpmUsed}/{quota.rpmLimit}
            </span>
          </div>
          <button
            type="button"
            onClick={() => openSettingsSection('groq-ai')}
            className="text-[12px] font-medium text-[#1D6CF0] hover:underline"
          >
            Configure in Settings →
          </button>
        </div>

        {latestAudit && (
          <div>
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#E5E7EB] bg-[#F0FDF4] px-5 py-2.5 text-[12.5px] tabular-nums">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-[#16A34A]" />
                <span className="font-semibold text-[#166534]">
                  Measured Accuracy: {latestAudit.accuracyPct}% ({latestAudit.correctCount}/
                  {latestAudit.sampleSize} correct)
                </span>
              </div>
              <div className="text-[12px] text-[#15803D]">
                TP {latestAudit.truePositives} · FP {latestAudit.falsePositives} · TN{' '}
                {latestAudit.trueNegatives} · FN {latestAudit.falseNegatives}
              </div>
            </div>

            <div className="overflow-x-auto bg-white">
              <table className="w-full min-w-[700px] text-left text-[12.5px]">
                <thead>
                  <tr className="h-[34px] border-b border-[#E5E7EB] bg-[#F9FAFB] text-[11.5px] font-medium text-[#6B7280]">
                    <th className="pl-5 pr-3 font-medium">Evaluated Object</th>
                    <th className="px-3 font-medium">Actual</th>
                    <th className="px-3 font-medium">Prediction</th>
                    <th className="px-3 text-right font-medium">Confidence</th>
                    <th className="pl-3 pr-5 font-medium">Reasoning</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#F3F4F6]">
                  {latestAudit.verdicts.map((v) => (
                    <tr key={v.key} className="h-[38px] hover:bg-[#F9FAFB] transition-colors">
                      <td className="max-w-[260px] truncate pl-5 pr-3 font-mono text-[12px] text-[#111827]">
                        {v.key}
                      </td>
                      <td className="px-3 text-[12px] capitalize text-[#4B5563]">
                        {v.actualLabel}
                      </td>
                      <td
                        className={`px-3 text-[12px] font-medium capitalize ${
                          v.correct ? 'text-[#D97706]' : 'text-[#16A34A]'
                        }`}
                      >
                        {v.predictedLabel} ({v.correct ? 'matched' : 'fooled'})
                      </td>
                      <td className="px-3 text-right text-[12px] text-[#4B5563] tabular-nums">
                        {Math.round(v.confidence * 100)}%
                      </td>
                      <td className="pl-3 pr-5 text-[12px] text-[#4B5563]">{v.reasoning}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </section>

      {/* Active Canary Inventory Table */}
      <section className="surface-card overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#E5E7EB] bg-[#F8F9FA] px-5 py-3">
          <h2 className="type-section text-[14px]">
            Active Canary Inventory ({state.canaries.length})
          </h2>
          <span className="text-[12px] text-[#6B7280] tabular-nums">
            Read trip +45 (watchlist) · Write or delete +100 (auto-contain)
          </span>
        </div>

        <div className="overflow-x-auto bg-white">
          <table className="w-full min-w-[780px] text-left text-[12.5px]">
            <thead className="kumo-table-head">
              <tr className="h-[36px] type-caption text-[#6B7280]">
                <th className="pl-5 pr-3 font-medium">Location</th>
                <th className="px-3 text-right font-medium">Depth</th>
                <th className="px-3 font-medium">Type</th>
                <th className="px-3 text-right font-medium">Size</th>
                <th className="px-3 font-medium">Source</th>
                <th className="px-3 font-medium">Last Refreshed</th>
                <th className="pl-3 pr-5 text-right font-medium">Trips (R / W)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#F3F4F6] tabular-nums">
              {state.canaries.map((c) => (
                <tr key={c.id} className="h-[40px] transition-colors hover:bg-[#F8F9FB]">
                  <td className="pl-5 pr-3 font-mono text-[12px] text-[#111827]">
                    {c.bucket}/{c.key}
                  </td>
                  <td className="px-3 text-right text-[12px] text-[#4B5563]">
                    {c.folderDepth}
                  </td>
                  <td className="px-3 font-mono text-[12px] text-[#4B5563]">{c.fileType}</td>
                  <td className="px-3 text-right text-[12px] text-[#4B5563]">
                    {formatBytes(c.sizeBytes)}
                  </td>
                  <td className="px-3 text-[12px]">
                    <span
                      className={
                        c.generatedBy === 'groq-gpt-oss-120b'
                          ? 'font-medium text-[#1D6CF0]'
                          : 'text-[#4B5563]'
                      }
                    >
                      {c.generatedBy === 'groq-gpt-oss-120b' ? 'AI-Generated' : 'Built-In'}
                    </span>
                  </td>
                  <td className="px-3 text-[12px] text-[#6B7280]">
                    {c.lastRefreshedAt.slice(0, 19).replace('T', ' ')}
                  </td>
                  <td className="pl-3 pr-5 text-right text-[12px]">
                    <span className={c.writeTrips > 0 ? 'font-semibold text-[#DC2626]' : 'text-[#4B5563]'}>
                      {c.readTrips} / {c.writeTrips}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
