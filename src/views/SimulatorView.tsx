import React, { useState } from 'react';
import {
  CheckCircle2,
  Clock,
  Lock,
  Play,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
  XCircle,
} from 'lucide-react';
import { useConsole } from '../context/ConsoleContext.tsx';
import type { SimScenarioId } from '../shared/types.ts';

const BENIGN_VARIANTS: Array<{ id: SimScenarioId; label: string; desc: string }> = [
  { id: 'benign_bulk', label: '50 Mixed Docs', desc: '.pdf, .jpg, .docx, .csv, .txt' },
  { id: 'benign_compressed', label: 'Compressed Media', desc: 'High-entropy valid .jpg & .docx' },
  { id: 'benign_rename', label: 'Bulk Rename', desc: 'Valid-header archival copies' },
  { id: 'benign_backup_sync', label: 'Backup Sync', desc: 'Allowlisted agent reads canaries' },
];

export const SimulatorView: React.FC = () => {
  const { state, apiFetch, pushToast, requestConfirm, navigateTo, setSelectedIncidentId } =
    useConsole();
  const [targetBucket, setTargetBucket] = useState('finance-prod');
  const [benignVariant, setBenignVariant] = useState<SimScenarioId>('benign_bulk');
  const [launching, setLaunching] = useState<string | null>(null);

  if (!state) return null;

  const selectedBucketObj = state.buckets.find((b) => b.name === targetBucket) ?? state.buckets[0];
  const blastLockPass = selectedBucketObj?.tags.env === 'ransomware-sim-only';

  const launchScenario = async (scenario: SimScenarioId) => {
    setLaunching(scenario);
    try {
      await apiFetch('/api/simulator/run', {
        method: 'POST',
        body: JSON.stringify({ scenario, bucket: targetBucket }),
      });
      pushToast({
        title: 'Simulation started',
        detail: `Executing ${scenario.replace(/_/g, ' ')} on ${targetBucket}.`,
        tone: 'info',
      });
    } catch (err) {
      pushToast({
        title: 'Simulation blocked',
        detail: err instanceof Error ? err.message : 'Unable to start scenario.',
        tone: 'error',
      });
    } finally {
      setLaunching(null);
    }
  };

  const triggerAdminGateTest = async () => {
    try {
      await apiFetch('/api/simulator/admin-gate-test', {
        method: 'POST',
        body: JSON.stringify({ bucket: targetBucket }),
      });
      pushToast({
        title: 'Human-Admin Approval Gate Triggered',
        detail: 'Review pending quarantine decision on admin-elena-chen in Incidents.',
        tone: 'warning',
      });
      navigateTo('threat-ops', 'incidents');
    } catch (err) {
      pushToast({
        title: 'Could not trigger admin gate',
        detail: err instanceof Error ? err.message : 'Error',
        tone: 'error',
      });
    }
  };

  const handleResetDemo = () => {
    requestConfirm({
      title: 'Reset Sandbox Baseline?',
      message:
        'Restores baseline objects, returns all principals to Active standing, clears recent incidents and events, and reverts policies.yaml to defaults.',
      confirmLabel: 'Reset Sandbox',
      destructive: true,
      onConfirm: async () => {
        await apiFetch('/api/simulator/reset', { method: 'POST' });
        pushToast({
          title: 'Sandbox reset complete',
          detail: 'Baseline buckets, vault snapshots, and credentials restored.',
          tone: 'success',
        });
      },
    });
  };

  return (
    <div className="mx-auto max-w-[1380px] space-y-6 px-4 py-6 sm:px-6">
      {/* Header Row */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="type-page-title">
            Attack Simulator
          </h1>
          <p className="mt-1.5 text-[13px] text-[#6B7280]">
            Validate automated ransomware detection, principal quarantine, and immutable vault
            recovery against realistic storage attack drills.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={triggerAdminGateTest}
            className="inline-flex h-[32px] items-center gap-1.5 rounded-[7px] border border-[#D1D5DB] bg-white px-3 type-control text-[#374151] transition-colors hover:bg-[#F8F9FA] whitespace-nowrap shrink-0"
          >
            <UserCheck className="h-3.5 w-3.5 text-[#D97706]" />
            Test Approval Gate
          </button>

          <button
            type="button"
            onClick={handleResetDemo}
            disabled={state.simulator.running}
            className="inline-flex h-[32px] items-center gap-1.5 rounded-[7px] border border-[#D1D5DB] bg-white px-3 type-control text-[#374151] transition-colors hover:bg-[#F8F9FA] disabled:opacity-50 whitespace-nowrap shrink-0"
          >
            <RotateCcw className="h-3.5 w-3.5 text-[#6B7280]" />
            Reset Sandbox
          </button>
        </div>
      </div>

      {/* Blast-Radius Guard Banner */}
      <div
        className={`flex flex-wrap items-center justify-between gap-4 rounded-lg border px-4 py-3 ${
          blastLockPass
            ? 'border-[#BBF7D0] bg-[#F0FDF4]'
            : 'border-[#FECACA] bg-[#FEF2F2]'
        }`}
      >
        <div className="flex items-center gap-2.5 text-[13px]">
          {blastLockPass ? (
            <ShieldCheck className="h-4 w-4 shrink-0 text-[#16A34A]" />
          ) : (
            <Lock className="h-4 w-4 shrink-0 text-[#DC2626]" />
          )}
          <span className={`font-semibold ${blastLockPass ? 'text-[#166534]' : 'text-[#991B1B]'}`}>
            Blast-Radius Guard: {blastLockPass ? 'Verified' : 'Blocked'}
          </span>
          <span className={blastLockPass ? 'text-[#15803D]' : 'text-[#B91C1C]'}>
            {blastLockPass ? (
              <>
                Target <span className="font-mono">{targetBucket}</span> carries{' '}
                <span className="font-mono">env=ransomware-sim-only</span>
              </>
            ) : (
              <>
                Target <span className="font-mono">{targetBucket}</span> is not tagged for drills.
                Production buckets are protected.
              </>
            )}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <label htmlFor="sim-bucket-select" className="text-[12px] font-medium text-[#374151]">
            Target Bucket
          </label>
          <select
            id="sim-bucket-select"
            value={targetBucket}
            onChange={(e) => setTargetBucket(e.target.value)}
            className="h-[30px] rounded-md border border-[#D1D5DB] bg-white px-2.5 font-mono text-[12px] text-[#111827] focus:border-[#1D6CF0] focus:outline-none"
          >
            {state.buckets.map((b) => (
              <option key={b.name} value={b.name}>
                {b.name} ({b.tags.env || 'prod'})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* 2x2 Readiness Drills Grid */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        {/* Drill 1: Benign Workload Verification */}
        <div className="surface-card flex flex-col justify-between p-5">
          <div>
            <div className="flex items-center justify-between text-[12px]">
              <span className="font-medium text-[#6B7280]">False-Positive Check</span>
              <span className="font-medium text-[#16A34A]">Zero-alert target</span>
            </div>
            <h2 className="mt-2 type-section text-[16px]">
              Benign Backup Surge
            </h2>
            <p className="mt-1 text-[13px] leading-relaxed text-[#4B5563]">
              Confirms high-entropy legitimate uploads, archival renames, and allowlisted backup
              syncs complete cleanly without triggering false revocations.
            </p>

            <div className="mt-4 grid grid-cols-2 gap-2">
              {BENIGN_VARIANTS.map((v) => (
                <button
                  key={v.id}
                  type="button"
                  onClick={() => setBenignVariant(v.id)}
                  className={`rounded-md border px-3 py-2 text-left transition-colors ${
                    benignVariant === v.id
                      ? 'border-[#1D6CF0] bg-[#EFF6FF]'
                      : 'border-[#E5E7EB] bg-[#F9FAFB] hover:bg-[#F3F4F6]'
                  }`}
                >
                  <div
                    className={`text-[12.5px] font-medium ${
                      benignVariant === v.id ? 'text-[#1D6CF0]' : 'text-[#111827]'
                    }`}
                  >
                    {v.label}
                  </div>
                  <div className="truncate text-[11.5px] text-[#6B7280]">{v.desc}</div>
                </button>
              ))}
            </div>
          </div>

          <div className="mt-5 flex items-center justify-between border-t border-[#E5E7EB] pt-3.5">
            <span className="text-[12px] text-[#6B7280] tabular-nums">
              Target: 0 alerts · Risk &lt; 45
            </span>
            <button
              type="button"
              disabled={state.simulator.running || launching !== null}
              onClick={() => launchScenario(benignVariant)}
              className="inline-flex h-[32px] items-center gap-1.5 rounded-md bg-[#1D6CF0] px-3.5 text-[12.5px] font-medium text-white hover:bg-[#1558D6] disabled:opacity-45 whitespace-nowrap shrink-0"
            >
              <Play className="h-3.5 w-3.5" />
              Run Benign Workload
            </button>
          </div>
        </div>

        {/* Drill 2: Sabotage & Encryption */}
        <div className="surface-card flex flex-col justify-between p-5">
          <div>
            <div className="flex items-center justify-between text-[12px]">
              <span className="font-medium text-[#6B7280]">Ransomware Drill</span>
              <span className="font-medium text-[#DC2626]">Auto-containment</span>
            </div>
            <h2 className="mt-2 type-section text-[16px]">
              Versioning Sabotage &amp; Encryption
            </h2>
            <p className="mt-1 text-[13px] leading-relaxed text-[#4B5563]">
              Simulates pre-encryption versioning suspension (
              <span className="font-mono text-[#111827]">PutBucketVersioning</span>) followed by
              AES-256-GCM encryption and{' '}
              <span className="font-mono text-[#111827]">.locked</span> rename bursts under{' '}
              <span className="font-mono text-[#111827]">svc-billing-etl</span>.
            </p>
          </div>

          <div className="mt-5 flex items-center justify-between border-t border-[#E5E7EB] pt-3.5">
            <span className="text-[12px] text-[#6B7280] tabular-nums">
              Target: HTTP 403 mid-attack · ≥ 90% preserved
            </span>
            <button
              type="button"
              disabled={state.simulator.running || launching !== null}
              onClick={() => launchScenario('standard_ransomware')}
              className="inline-flex h-[32px] items-center gap-1.5 rounded-[7px] bg-[#DC2626] px-3.5 type-control text-white transition-colors hover:bg-[#B91C1C] disabled:opacity-45 whitespace-nowrap shrink-0"
            >
              <ShieldAlert className="h-3.5 w-3.5" />
              Run Ransomware Drill
            </button>
          </div>
        </div>

        {/* Drill 3: Distributed Key Swarm */}
        <div className="surface-card flex flex-col justify-between p-5">
          <div>
            <div className="flex items-center justify-between text-[12px]">
              <span className="font-medium text-[#6B7280]">Distributed Attack</span>
              <span className="font-medium text-[#D97706]">Cross-key correlation</span>
            </div>
            <h2 className="mt-2 type-section text-[16px]">
              Multi-Principal Swarm Evasion
            </h2>
            <p className="mt-1 text-[13px] leading-relaxed text-[#4B5563]">
              Bypasses canary objects and spreads slow AES-256 overwrites plus SSE-C{' '}
              <span className="font-mono text-[#111827]">CopyObject</span> abuse across 4
              assumed-role principals (
              <span className="font-mono text-[#111827]">swarm-node-alpha…delta</span>).
            </p>
          </div>

          <div className="mt-5 flex items-center justify-between border-t border-[#E5E7EB] pt-3.5">
            <span className="text-[12px] text-[#6B7280] tabular-nums">
              Target: All 4 principals quarantined
            </span>
            <button
              type="button"
              disabled={state.simulator.running || launching !== null}
              onClick={() => launchScenario('stealth_ai_swarm')}
              className="inline-flex h-[32px] items-center gap-1.5 rounded-[7px] bg-[#DC2626] px-3.5 type-control text-white transition-colors hover:bg-[#B91C1C] disabled:opacity-45 whitespace-nowrap shrink-0"
            >
              <ShieldAlert className="h-3.5 w-3.5" />
              Run Swarm Drill
            </button>
          </div>
        </div>

        {/* Drill 4: Automated Vault Recovery */}
        <div className="surface-card flex flex-col justify-between p-5">
          <div>
            <div className="flex items-center justify-between text-[12px]">
              <span className="font-medium text-[#6B7280]">Recovery Verification</span>
              <span className="font-medium text-[#16A34A]">Byte-verified restore</span>
            </div>
            <h2 className="mt-2 type-section text-[16px]">
              Automated Vault Recovery
            </h2>
            <p className="mt-1 text-[13px] leading-relaxed text-[#4B5563]">
              Executes 1-Click Restore from the immutable vault after an attack, removes{' '}
              <span className="font-mono text-[#111827]">.locked</span> artifacts and delete
              markers, and verifies 100% SHA-256 integrity.
            </p>
          </div>

          <div className="mt-5 flex items-center justify-between border-t border-[#E5E7EB] pt-3.5">
            <span className="text-[12px] text-[#6B7280] tabular-nums">Target: 100% SHA-256 match</span>
            <button
              type="button"
              disabled={state.simulator.running || launching !== null}
              onClick={() => launchScenario('recovery_verification')}
              className="inline-flex h-[32px] items-center gap-1.5 rounded-md bg-[#16A34A] px-3.5 text-[12.5px] font-medium text-white hover:bg-[#15803D] disabled:opacity-45 whitespace-nowrap shrink-0"
            >
              <CheckCircle2 className="h-3.5 w-3.5" />
              Verify Vault Recovery
            </button>
          </div>
        </div>
      </div>

      {/* Live Drill Results */}
      <div className="overflow-hidden rounded-lg border border-[#E5E7EB] bg-white">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#E5E7EB] bg-[#F9FAFB] px-5 py-3">
          <div>
            <h3 className="text-[13.5px] font-semibold text-[#111827]">Drill Verification Checks</h3>
            <p className="text-[12px] text-[#6B7280]">
              {state.simulator.scenario
                ? `${state.simulator.scenario.replace(/_/g, ' ')} on ${state.simulator.bucket} · ${
                    state.simulator.running ? 'Running…' : 'Completed'
                  }`
                : 'Select a drill above to inspect live verification checks.'}
            </p>
          </div>

          {state.simulator.incidentId && (
            <button
              type="button"
              onClick={() => {
                setSelectedIncidentId(state.simulator.incidentId ?? null);
                navigateTo('threat-ops', 'incidents');
              }}
              className="h-[30px] rounded-md border border-[#D1D5DB] bg-white px-3 text-[12px] font-medium text-[#374151] hover:bg-[#F9FAFB]"
            >
              Inspect Incident <span className="font-mono">{state.simulator.incidentId}</span>
            </button>
          )}
        </div>

        {state.simulator.assertions.length === 0 ? (
          <div className="py-10 text-center text-[13px] text-[#6B7280]">
            No checks recorded yet. Run any drill above to verify detection and recovery outcomes.
          </div>
        ) : (
          <div className="divide-y divide-[#F3F4F6]">
            {state.simulator.assertions.map((a) => (
              <div key={a.id} className="flex items-center justify-between gap-4 px-5 py-3">
                <div className="flex items-start gap-2.5">
                  {a.status === 'pass' ? (
                    <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-[#16A34A]" />
                  ) : a.status === 'fail' ? (
                    <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-[#DC2626]" />
                  ) : (
                    <Clock className="mt-0.5 h-4 w-4 shrink-0 text-[#D97706]" />
                  )}
                  <div>
                    <p className="text-[13px] font-medium text-[#111827]">{a.label}</p>
                    {a.detail && <p className="text-[12px] text-[#4B5563]">{a.detail}</p>}
                  </div>
                </div>
                <span
                  className={`text-[12px] font-medium capitalize whitespace-nowrap shrink-0 ${
                    a.status === 'pass'
                      ? 'text-[#16A34A]'
                      : a.status === 'fail'
                        ? 'text-[#DC2626]'
                        : 'text-[#D97706]'
                  }`}
                >
                  {a.status === 'pass' ? 'Passed' : a.status === 'fail' ? 'Failed' : 'Pending'}
                </span>
              </div>
            ))}
          </div>
        )}

        {state.simulator.summary && (
          <div className="border-t border-[#E5E7EB] bg-[#F9FAFB] px-5 py-3 text-[12.5px] text-[#111827]">
            {state.simulator.summary}
          </div>
        )}
      </div>
    </div>
  );
};
