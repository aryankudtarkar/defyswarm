import React, { useState } from 'react';
import { BarChart3, Download, Play } from 'lucide-react';
import { SignalBreakdownBars } from '../components/Charts.tsx';
import { useConsole } from '../context/ConsoleContext.tsx';

export const AnalyticsView: React.FC = () => {
  const { state, apiFetch, pushToast, benchmarkProgress, setBenchmarkProgress } = useConsole();
  const [iterations, setIterations] = useState(30);
  const [compareIdx, setCompareIdx] = useState<number>(1);

  if (!state) return null;

  const latest = state.benchmarks[0] ?? null;
  const previous = state.benchmarks[compareIdx] ?? null;

  const runBenchmark = async () => {
    setBenchmarkProgress({
      running: true,
      completed: 0,
      total: iterations * 4,
      stage: 'Running detection and recovery drills…',
    });
    try {
      const res = await apiFetch<{ ok: boolean; benchmark: { id: string; durationMs: number } }>(
        '/api/benchmarks/run',
        {
          method: 'POST',
          body: JSON.stringify({ iterations }),
        },
      );
      pushToast({
        title: 'Validation Suite Complete',
        detail: `Completed ${iterations} runs per drill in ${res.benchmark.durationMs} ms.`,
        tone: 'success',
      });
    } catch (err) {
      pushToast({
        title: 'Validation failed',
        detail: err instanceof Error ? err.message : 'Unable to execute validation suite.',
        tone: 'error',
      });
    } finally {
      setBenchmarkProgress((prev) => ({ ...prev, running: false }));
    }
  };

  const exportBenchmarkJson = () => {
    if (!latest) return;
    const blob = new Blob([JSON.stringify(latest, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `defyswarm-report-${latest.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const stdMetrics = latest?.scenarios[1];
  const benignMetrics = latest?.scenarios[0];
  const recMetrics = latest?.scenarios[3];
  const prevStd = previous?.scenarios[1];

  return (
    <div className="mx-auto max-w-[1380px] space-y-6 px-4 py-6 sm:px-6">
      {/* Header Row */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="type-page-title">
            Detection &amp; Response Analytics
          </h1>
          <p className="mt-1.5 text-[13px] text-[#6B7280]">
            Measured median and p95 detection latency, containment speed, and data preservation
            across automated attack drills.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <select
            value={iterations}
            onChange={(e) => setIterations(Number(e.target.value))}
            disabled={benchmarkProgress.running}
            className="h-[32px] rounded-md border border-[#D1D5DB] bg-white px-2.5 text-[12px] font-medium text-[#111827] tabular-nums focus:border-[#1D6CF0] focus:outline-none"
          >
            <option value={30}>30 runs per drill (Full)</option>
            <option value={15}>15 runs per drill (Quick)</option>
          </select>

          {latest && (
            <button
              type="button"
              onClick={exportBenchmarkJson}
              className="inline-flex h-[32px] items-center gap-1.5 rounded-md border border-[#D1D5DB] bg-white px-3 text-[12.5px] font-medium text-[#374151] hover:bg-[#F9FAFB] transition-colors whitespace-nowrap shrink-0"
            >
              <Download className="h-3.5 w-3.5 text-[#6B7280]" />
              Export JSON
            </button>
          )}

          <button
            type="button"
            disabled={benchmarkProgress.running}
            onClick={runBenchmark}
            className="inline-flex h-[32px] items-center gap-1.5 rounded-md bg-[#1D6CF0] px-3.5 text-[12.5px] font-medium text-white hover:bg-[#1558D6] transition-colors disabled:opacity-50 whitespace-nowrap shrink-0"
          >
            <Play className="h-3.5 w-3.5" />
            {benchmarkProgress.running ? 'Running Suite…' : 'Run Validation Suite'}
          </button>
        </div>
      </div>

      {/* Live Progress Strip */}
      {benchmarkProgress.running && (
        <div className="rounded-lg border border-[#BFDBFE] bg-[#EFF6FF] px-4 py-3">
          <div className="flex items-center justify-between text-[12.5px]">
            <span className="font-medium text-[#1E3A8A]">{benchmarkProgress.stage}</span>
            <span className="font-medium text-[#1D6CF0] tabular-nums">
              {benchmarkProgress.completed} / {benchmarkProgress.total} runs
            </span>
          </div>
          <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-[#DBEAFE]">
            <div
              className="h-full rounded-full bg-[#1D6CF0] transition-all duration-150"
              style={{
                width: `${Math.min(
                  100,
                  Math.round(
                    (benchmarkProgress.completed / Math.max(1, benchmarkProgress.total)) * 100,
                  ),
                )}%`,
              }}
            />
          </div>
        </div>
      )}

      {!latest ? (
        <div className="flex flex-col items-center justify-center rounded-lg border border-[#E5E7EB] bg-white px-6 py-20 text-center">
          <div className="flex h-11 w-11 items-center justify-center rounded-lg border border-[#E5E7EB] bg-[#F9FAFB] text-[#1D6CF0]">
            <BarChart3 className="h-5 w-5" />
          </div>
          <h3 className="mt-3 text-[15px] font-semibold text-[#111827]">No Validation Runs Yet</h3>
          <p className="mt-1 max-w-md text-[13px] text-[#6B7280]">
            Run the validation suite to measure median and p95 detection latency, containment speed,
            preserved objects, false-positive rate, and restore accuracy.
          </p>
          <button
            type="button"
            onClick={runBenchmark}
            className="mt-4 inline-flex h-[34px] items-center gap-1.5 rounded-md bg-[#1D6CF0] px-4 text-[12.5px] font-medium text-white hover:bg-[#1558D6]"
          >
            <Play className="h-3.5 w-3.5" />
            Run Validation Suite
          </button>
        </div>
      ) : (
        <>
          {/* 5-Cell Measured vs Target KPI Ledger */}
          <div className="surface-card grid grid-cols-1 divide-y divide-[#E5E7EB] overflow-hidden sm:grid-cols-2 sm:divide-y-0 sm:divide-x xl:grid-cols-5">
            <div className="px-4 py-4">
              <p className="text-[12px] font-medium text-[#6B7280]">MTTD (Median / p95)</p>
              <p className="mt-2 type-kpi text-[22px] text-[#16A34A]">
                {stdMetrics?.mttdMedianMs} / {stdMetrics?.mttdP95Ms} ms
              </p>
              <p className="mt-1 text-[11.5px] text-[#6B7280] tabular-nums">Target &lt; 5,000 ms</p>
            </div>

            <div className="px-4 py-4">
              <p className="text-[12px] font-medium text-[#6B7280]">MTTC to 403 (Median / p95)</p>
              <p className="mt-2 type-kpi text-[22px] text-[#16A34A]">
                {stdMetrics?.mttcMedianMs} / {stdMetrics?.mttcP95Ms} ms
              </p>
              <p className="mt-1 text-[11.5px] text-[#6B7280] tabular-nums">Target &lt; 10,000 ms</p>
            </div>

            <div className="px-4 py-4">
              <p className="text-[12px] font-medium text-[#6B7280]">Files Preserved</p>
              <p className="mt-2 type-kpi text-[24px] text-[#111827]">
                {stdMetrics?.filesPreservedMedianPct}%
              </p>
              <p className="mt-1 text-[11.5px] text-[#6B7280] tabular-nums">
                Min {stdMetrics?.filesPreservedMinPct}% · Target ≥ 90%
              </p>
            </div>

            <div className="px-4 py-4">
              <p className="text-[12px] font-medium text-[#6B7280]">False-Positive Rate</p>
              <p
                className={`mt-2 type-kpi text-[24px] ${
                  (benignMetrics?.falseAlarms ?? 0) === 0 ? 'text-[#16A34A]' : 'text-[#DC2626]'
                }`}
              >
                {benignMetrics?.falsePositiveRatePct}%
              </p>
              <p className="mt-1 text-[11.5px] text-[#6B7280] tabular-nums">
                {benignMetrics?.falseAlarms} / {benignMetrics?.runs} benign · Target 0
              </p>
            </div>

            <div className="px-4 py-4">
              <p className="text-[12px] font-medium text-[#6B7280]">Restore Integrity</p>
              <p className="mt-2 type-kpi text-[24px] text-[#16A34A]">
                {recMetrics?.restoreAccuracyPct}%
              </p>
              <p className="mt-1 text-[11.5px] text-[#6B7280] tabular-nums">
                Median {recMetrics?.restoreTimeMedianMs} ms · Target 100%
              </p>
            </div>
          </div>

          {/* Drill Scoreboard */}
          <section className="surface-card overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#E5E7EB] bg-[#F8F9FA] px-5 py-3">
              <div className="flex flex-wrap items-baseline gap-x-2.5 gap-y-0.5">
                <h2 className="type-section text-[14px]">
                  Drill Results · <span className="font-mono text-[12.5px]">{latest.id}</span>
                </h2>
                <span className="text-[12px] text-[#6B7280] tabular-nums">
                  {latest.iterationsPerScenario} runs per drill · {latest.durationMs} ms
                </span>
              </div>
              <span
                className={`inline-flex items-center gap-1.5 text-[12px] font-medium ${
                  latest.overallPass ? 'text-[#15803D]' : 'text-[#B45309]'
                }`}
              >
                <span
                  className={`h-1.5 w-1.5 rounded-full ${
                    latest.overallPass ? 'bg-[#16A34A]' : 'bg-[#D97706]'
                  }`}
                />
                {latest.overallPass ? 'All targets met' : 'Review required'}
              </span>
            </div>

            <div className="overflow-x-auto bg-white">
              <table className="w-full min-w-[780px] text-left text-[12.5px]">
                <thead className="kumo-table-head">
                  <tr className="h-[36px] type-caption text-[#6B7280]">
                    <th className="pl-5 pr-3 font-medium">Drill</th>
                    <th className="px-3 text-right font-medium">Runs</th>
                    <th className="px-3 text-right font-medium">MTTD Med / p95</th>
                    <th className="px-3 text-right font-medium">MTTC Med / p95</th>
                    <th className="px-3 text-right font-medium">Preserved</th>
                    <th className="px-3 text-right font-medium">False Alarms</th>
                    <th className="px-3 text-right font-medium">Restore Acc</th>
                    <th className="pl-3 pr-5 text-right font-medium">Repl Lag</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#F3F4F6] tabular-nums">
                  {latest.scenarios.map((s) => (
                    <tr
                      key={s.scenario}
                      className="h-[40px] transition-colors hover:bg-[#F8F9FB]"
                    >
                      <td className="pl-5 pr-3 font-medium text-[#111827]">{s.scenario}</td>
                      <td className="px-3 text-right text-[#4B5563]">{s.runs}</td>
                      <td className="px-3 text-right text-[#111827]">
                        {s.mttdMedianMs > 0 ? `${s.mttdMedianMs} / ${s.mttdP95Ms} ms` : '—'}
                      </td>
                      <td className="px-3 text-right text-[#111827]">
                        {s.mttcMedianMs > 0 ? `${s.mttcMedianMs} / ${s.mttcP95Ms} ms` : '—'}
                      </td>
                      <td className="px-3 text-right font-medium text-[#16A34A]">
                        {s.filesPreservedMedianPct}%
                      </td>
                      <td className="px-3 text-right">
                        <span className={s.falseAlarms === 0 ? 'text-[#16A34A]' : 'font-semibold text-[#DC2626]'}>
                          {s.falseAlarms}
                        </span>
                      </td>
                      <td className="px-3 text-right font-medium text-[#16A34A]">
                        {s.restoreAccuracyPct}%
                      </td>
                      <td className="pl-3 pr-5 text-right text-[#4B5563]">
                        {s.replicationLagMedianMs} ms
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          {/* Lower 2-Column Split */}
          <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
            {/* Left Pane: Detections by Signal */}
            <section className="overflow-hidden rounded-lg border border-[#E5E7EB] bg-white">
              <div className="flex items-center justify-between border-b border-[#E5E7EB] bg-[#F9FAFB] px-5 py-3">
                <h2 className="text-[14px] font-semibold text-[#111827]">Detections by Signal</h2>
                <span className="font-mono text-[11.5px] text-[#6B7280]">
                  {latest.id}
                </span>
              </div>
              <div className="p-5">
                <SignalBreakdownBars counts={latest.detectionsBySignal} />
              </div>
            </section>

            {/* Right Pane: Evasion & Late-Detection Audit + Run-to-Run Comparison */}
            <div className="space-y-5">
              <section className="overflow-hidden rounded-lg border border-[#E5E7EB] bg-white">
                <div className="flex items-center justify-between border-b border-[#E5E7EB] bg-[#F9FAFB] px-5 py-3">
                  <h2 className="text-[14px] font-semibold text-[#111827]">
                    Late-Detection &amp; Evasion Audit
                  </h2>
                  <span className="text-[11.5px] text-[#6B7280]">All runs included</span>
                </div>
                <div className="px-5 py-4">
                  <p className="text-[12.5px] leading-relaxed text-[#4B5563]">
                    Drills that exceed latency or preservation targets are recorded alongside the
                    signal that triggered containment.
                  </p>
                  <div className="mt-3 divide-y divide-[#F3F4F6] border-t border-[#E5E7EB] text-[12.5px] tabular-nums">
                    {latest.scenarios
                      .filter((s) => s.scenario.includes('Standard') || s.scenario.includes('Swarm'))
                      .map((s) => (
                        <div
                          key={s.scenario}
                          className="flex h-[36px] items-center justify-between"
                        >
                          <span className="font-medium text-[#111827]">{s.scenario}</span>
                          <span
                            className={`text-[12px] font-medium ${
                              s.evasionOrLateRuns === 0 ? 'text-[#16A34A]' : 'text-[#D97706]'
                            }`}
                          >
                            {s.evasionOrLateRuns} late or evading run(s)
                          </span>
                        </div>
                      ))}
                  </div>
                </div>
              </section>

              <section className="overflow-hidden rounded-lg border border-[#E5E7EB] bg-white">
                <div className="flex items-center justify-between gap-3 border-b border-[#E5E7EB] bg-[#F9FAFB] px-5 py-2.5">
                  <h2 className="text-[14px] font-semibold text-[#111827]">Run-to-Run Comparison</h2>
                  {state.benchmarks.length > 1 && (
                    <select
                      value={compareIdx}
                      onChange={(e) => setCompareIdx(Number(e.target.value))}
                      className="h-[28px] rounded-md border border-[#D1D5DB] bg-white px-2 font-mono text-[11.5px] text-[#111827] focus:border-[#1D6CF0] focus:outline-none"
                    >
                      {state.benchmarks.slice(1).map((bm, i) => (
                        <option key={bm.id} value={i + 1}>
                          vs {bm.id} ({bm.iterationsPerScenario}x)
                        </option>
                      ))}
                    </select>
                  )}
                </div>

                {!previous || !prevStd || !stdMetrics ? (
                  <div className="px-5 py-4 text-[12.5px] text-[#6B7280]">
                    Run a second validation suite to compare detection speed and preservation across
                    policy updates.
                  </div>
                ) : (
                  <div className="grid grid-cols-3 divide-x divide-[#E5E7EB] tabular-nums">
                    <div className="px-5 py-4">
                      <p className="text-[11.5px] font-medium text-[#6B7280]">
                        Median MTTD
                      </p>
                      <p className="mt-1 text-[16px] font-semibold text-[#111827]">
                        {stdMetrics.mttdMedianMs} ms
                      </p>
                      <p className="mt-0.5 text-[11.5px] text-[#6B7280]">
                        was {prevStd.mttdMedianMs} ms
                      </p>
                    </div>
                    <div className="px-5 py-4">
                      <p className="text-[11.5px] font-medium text-[#6B7280]">
                        Median MTTC
                      </p>
                      <p className="mt-1 text-[16px] font-semibold text-[#111827]">
                        {stdMetrics.mttcMedianMs} ms
                      </p>
                      <p className="mt-0.5 text-[11.5px] text-[#6B7280]">
                        was {prevStd.mttcMedianMs} ms
                      </p>
                    </div>
                    <div className="px-5 py-4">
                      <p className="text-[11.5px] font-medium text-[#6B7280]">
                        Preserved
                      </p>
                      <p className="mt-1 text-[16px] font-semibold text-[#16A34A]">
                        {stdMetrics.filesPreservedMedianPct}%
                      </p>
                      <p className="mt-0.5 text-[11.5px] text-[#6B7280]">
                        was {prevStd.filesPreservedMedianPct}%
                      </p>
                    </div>
                  </div>
                )}
              </section>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
