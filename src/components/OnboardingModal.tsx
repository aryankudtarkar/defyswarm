import React, { useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { ArrowRight, Check, KeyRound, Lock, ShieldCheck, X } from 'lucide-react';
import { useConsole } from '../context/ConsoleContext.tsx';

export const OnboardingModal: React.FC = () => {
  const { showOnboarding, setShowOnboarding, apiFetch, pushToast, navigateTo } = useConsole();
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [apiKey, setApiKey] = useState('');
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(null);
  const [saving, setSaving] = useState(false);

  const handleSaveAndVerify = async () => {
    if (!apiKey.trim()) {
      setTestResult({ ok: false, message: 'Enter your Groq API key (gsk_...) or choose Skip for Now.' });
      return;
    }
    setTesting(true);
    setTestResult(null);
    try {
      const testRes = await apiFetch<{ ok: boolean; message: string }>('/api/settings/llm/test', {
        method: 'POST',
        body: JSON.stringify({ apiKey: apiKey.trim() }),
      });
      await apiFetch('/api/settings/llm', {
        method: 'POST',
        body: JSON.stringify({
          apiKey: apiKey.trim(),
          onboardingCompleted: true,
        }),
      });
      setTestResult({ ok: true, message: testRes.message });
      pushToast({
        title: 'AI Analysis Connected',
        detail: 'Credentials verified with automatic request pacing enabled.',
        tone: 'success',
      });
      setTimeout(() => setStep(3), 450);
    } catch (err) {
      setTestResult({
        ok: false,
        message: err instanceof Error ? err.message : 'Verification failed.',
      });
    } finally {
      setTesting(false);
    }
  };

  const handleSkip = async () => {
    setSaving(true);
    try {
      await apiFetch('/api/settings/llm', {
        method: 'POST',
        body: JSON.stringify({ onboardingCompleted: true }),
      });
      setShowOnboarding(false);
    } catch {
      setShowOnboarding(false);
    } finally {
      setSaving(false);
    }
  };

  const handleFinish = (destination: 'overview' | 'settings') => {
    setShowOnboarding(false);
    if (destination === 'settings') {
      navigateTo('settings', 'configuration');
    } else {
      navigateTo('overview');
    }
  };

  return (
    <AnimatePresence>
      {showOnboarding && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.16 }}
          className="fixed inset-0 z-50 flex items-center justify-center bg-[#111827]/28 backdrop-blur-[4px] p-4"
          onClick={handleSkip}
        >
          <motion.div
            initial={{ opacity: 0, scale: 0.97, y: 8 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.98, y: 4 }}
            transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
            className="surface-vibrancy-overlay relative w-full max-w-[548px] overflow-hidden rounded-[12px] border border-[#E5E7EB]/85"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex h-[46px] items-center justify-between border-b border-[#E5E7EB]/80 bg-white/55 px-5">
              <div className="flex items-center gap-2 text-[12px] text-[#6B7280] tabular-nums">
                <span className={step === 1 ? 'text-[#111827] font-semibold' : ''}>1. Posture</span>
                <span>·</span>
                <span className={step === 2 ? 'text-[#111827] font-semibold' : ''}>2. AI Analysis</span>
                <span>·</span>
                <span className={step === 3 ? 'text-[#111827] font-semibold' : ''}>3. Ready</span>
              </div>
              <button
                type="button"
                onClick={handleSkip}
                aria-label="Close setup"
                className="rounded-[6px] p-1 text-[#6B7280] transition-colors hover:bg-[#111827]/[0.06] hover:text-[#111827]"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="bg-white/75 p-6">
              <AnimatePresence mode="wait">
                {step === 1 && (
                  <motion.div
                    key="step1"
                    initial={{ opacity: 0, x: 8 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -8 }}
                    transition={{ duration: 0.14 }}
                  >
                    <div className="flex items-center gap-2.5">
                      <div className="flex h-8 w-8 items-center justify-center rounded-md border border-[#BFDBFE] bg-[#EFF6FF] text-[#1D6CF0]">
                        <ShieldCheck className="h-4.5 w-4.5" />
                      </div>
                      <h2 className="text-[17px] font-semibold text-[#111827]">
                        DefySwarm Protection Ready
                      </h2>
                    </div>
                    <p className="mt-2.5 text-[13px] leading-relaxed text-[#4B5563]">
                      Automated ransomware defense for cloud object storage. Every entropy anomaly,
                      access revocation, and immutable vault recovery is verified end to end.
                    </p>

                    <div className="mt-5 divide-y divide-[#E5E7EB] rounded-lg border border-[#E5E7EB] bg-[#F9FAFB] text-[12.5px]">
                      <div className="flex items-center justify-between gap-4 px-3.5 py-2.5">
                        <div>
                          <p className="font-medium text-[#111827]">S3 Storage Connectors</p>
                          <p className="text-[11.5px] text-[#6B7280]">Local Sandbox, Backblaze B2, Supabase Storage &amp; MinIO</p>
                        </div>
                        <span className="text-[12px] font-medium text-[#16A34A]">Ready</span>
                      </div>
                      <div className="flex items-center justify-between gap-4 px-3.5 py-2.5">
                        <div>
                          <p className="font-medium text-[#111827]">Immutable Vault &amp; Clean Manifest</p>
                          <p className="text-[11.5px] text-[#6B7280]">Tenant credentials isolated with snapshot integrity checks</p>
                        </div>
                        <span className="text-[12px] font-medium text-[#16A34A]">Locked</span>
                      </div>
                      <div className="flex items-center justify-between gap-4 px-3.5 py-2.5">
                        <div>
                          <p className="font-medium text-[#111827]">Drill Blast-Radius Guard</p>
                          <p className="text-[11.5px] text-[#6B7280]">
                            Requires <span className="font-mono text-[#374151]">env=ransomware-sim-only</span> bucket tag
                          </p>
                        </div>
                        <span className="text-[12px] font-medium text-[#16A34A]">Armed</span>
                      </div>
                    </div>

                    <div className="mt-6 flex items-center justify-between">
                      <button
                        type="button"
                        onClick={handleSkip}
                        disabled={saving}
                        className="text-[12px] font-medium text-[#6B7280] hover:text-[#111827]"
                      >
                        Close
                      </button>
                      <button
                        type="button"
                        onClick={() => setStep(2)}
                        className="inline-flex items-center gap-1.5 rounded-md bg-[#1D6CF0] px-4 py-2 text-[12.5px] font-medium text-white hover:bg-[#1558D6]"
                      >
                        Connect AI Analysis
                        <ArrowRight className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </motion.div>
                )}

                {step === 2 && (
                  <motion.div
                    key="step2"
                    initial={{ opacity: 0, x: 8 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -8 }}
                    transition={{ duration: 0.14 }}
                  >
                    <div className="flex items-center gap-2.5">
                      <div className="flex h-8 w-8 items-center justify-center rounded-md border border-[#BFDBFE] bg-[#EFF6FF] text-[#1D6CF0]">
                        <KeyRound className="h-4 w-4" />
                      </div>
                      <h2 className="text-[17px] font-semibold text-[#111827]">
                        Connect AI Threat Analysis
                      </h2>
                    </div>
                    <p className="mt-2 text-[12.5px] leading-relaxed text-[#4B5563]">
                      Enable adaptive canary generation and automated evasion audits. Your API key
                      is held exclusively in server memory—never written to{' '}
                      <span className="font-mono text-[#111827]">policies.yaml</span> or browser
                      storage.
                    </p>

                    <div className="mt-4 rounded-lg border border-[#E5E7EB] bg-[#F9FAFB] p-3.5">
                      <div className="flex items-center justify-between text-[11.5px] text-[#4B5563]">
                        <span className="font-medium text-[#111827]">Automatic Request Pacing</span>
                        <span className="text-[#4B5563] tabular-nums">
                          30 req/min · 8,000 tok/min
                        </span>
                      </div>
                      <p className="mt-1 text-[11.5px] text-[#6B7280]">
                        Batched structured analysis with automatic cooldown throttling keeps API
                        usage predictable.
                      </p>
                    </div>

                    <div className="mt-4">
                      <label
                        htmlFor="onboarding-groq-key"
                        className="block text-[12px] font-medium text-[#111827]"
                      >
                        Groq API Key
                      </label>
                      <div className="relative mt-1.5">
                        <input
                          id="onboarding-groq-key"
                          type="password"
                          autoComplete="off"
                          value={apiKey}
                          onChange={(e) => setApiKey(e.target.value)}
                          placeholder="gsk_..."
                          className="w-full rounded-md border border-[#D1D5DB] bg-white px-3 py-2 pr-9 font-mono text-[12.5px] text-[#111827] placeholder:text-[#9CA3AF] focus:border-[#1D6CF0] focus:outline-none"
                        />
                        <Lock className="pointer-events-none absolute right-3 top-2.5 h-3.5 w-3.5 text-[#9CA3AF]" />
                      </div>
                      {testResult && (
                        <p
                          className={`mt-2 text-[12px] ${
                            testResult.ok ? 'text-[#16A34A]' : 'text-[#DC2626]'
                          }`}
                        >
                          {testResult.message}
                        </p>
                      )}
                    </div>

                    <div className="mt-6 flex items-center justify-between gap-3">
                      <button
                        type="button"
                        onClick={handleSkip}
                        disabled={testing || saving}
                        className="text-[12px] font-medium text-[#6B7280] hover:text-[#111827]"
                      >
                        Skip for now
                      </button>
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => setStep(1)}
                          disabled={testing}
                          className="rounded-md border border-[#D1D5DB] bg-white px-3.5 py-1.5 text-[12px] font-medium text-[#374151] hover:bg-[#F3F4F6]"
                        >
                          Back
                        </button>
                        <button
                          type="button"
                          onClick={handleSaveAndVerify}
                          disabled={testing}
                          className="rounded-md bg-[#1D6CF0] px-4 py-1.5 text-[12px] font-medium text-white hover:bg-[#1558D6] disabled:opacity-50"
                        >
                          {testing ? 'Verifying…' : 'Verify & Save'}
                        </button>
                      </div>
                    </div>
                  </motion.div>
                )}

                {step === 3 && (
                  <motion.div
                    key="step3"
                    initial={{ opacity: 0, x: 8 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -8 }}
                    transition={{ duration: 0.14 }}
                  >
                    <div className="flex items-center gap-2.5">
                      <div className="flex h-8 w-8 items-center justify-center rounded-md border border-[#BBF7D0] bg-[#F0FDF4] text-[#16A34A]">
                        <Check className="h-4.5 w-4.5" />
                      </div>
                      <h2 className="text-[17px] font-semibold text-[#111827]">
                        AI Analysis Connected
                      </h2>
                    </div>
                    <p className="mt-2.5 text-[13px] leading-relaxed text-[#4B5563]">
                      Adaptive canary generation and automated evasion audits are now active. Press{' '}
                      <kbd className="rounded border border-[#E5E7EB] bg-[#F9FAFB] px-1 font-mono text-[11px] text-[#111827]">
                        ⌘K
                      </kbd>{' '}
                      anytime to jump across workspaces or run readiness drills.
                    </p>

                    <div className="mt-6 flex items-center justify-end gap-2">
                      <button
                        type="button"
                        onClick={() => handleFinish('settings')}
                        className="rounded-md border border-[#D1D5DB] bg-white px-3.5 py-1.5 text-[12px] font-medium text-[#374151] hover:bg-[#F3F4F6]"
                      >
                        Open Settings
                      </button>
                      <button
                        type="button"
                        onClick={() => handleFinish('overview')}
                        className="inline-flex items-center gap-1.5 rounded-md bg-[#1D6CF0] px-4 py-1.5 text-[12px] font-medium text-white hover:bg-[#1558D6]"
                      >
                        Return to Overview
                        <ArrowRight className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};
