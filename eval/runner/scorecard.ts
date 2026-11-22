import type { EvalResults, DetectorSummary, FamilyScorecard } from '../types.ts';

function pct(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

function ci(interval: [number, number]): string {
  return `[${(interval[0] * 100).toFixed(1)}%, ${(interval[1] * 100).toFixed(1)}%]`;
}

function ms(value: number | null): string {
  return value === null ? '—' : `${Math.round(value)} ms`;
}

function pvalue(value: number | null): string {
  if (value === null) return '—';
  if (value < 0.001) return '<0.001';
  return value.toFixed(3);
}

function signed(value: number): string {
  return value > 0 ? `+${value.toFixed(1)}` : value.toFixed(1);
}

function summaryRow(family: string, s: DetectorSummary, isBenign: boolean): string {
  const detection = isBenign ? 'n/a' : pct(s.detectionRate);
  const detectionCi = isBenign ? 'n/a' : ci(s.detectionCi);
  const diff = s.filesLostDiffVsD9
    ? `${signed(s.filesLostDiffVsD9.medianDiff)} [${signed(s.filesLostDiffVsD9.ci[0])}, ${signed(
        s.filesLostDiffVsD9.ci[1],
      )}]`
    : '—';
  return `| ${family} | ${s.detectorId} ${s.detectorName} | ${s.traces} | ${detection} ${detectionCi} | ${pct(
    s.falsePositiveRate,
  )} ${ci(s.falsePositiveCi)} | ${ms(s.medianTimeToDetectMs)} | ${ms(s.p95TimeToDetectMs)} | ${s.medianFilesLost} | ${
    s.worstFilesLost
  } | ${pct(s.recoverablePct / 100)} | ${pvalue(s.mcnemarPValueVsD9)} | ${diff} |`;
}

function familyTable(family: FamilyScorecard, isBenign: boolean): string {
  const header = `| Family | Detector | Traces | Detection rate (95% CI) | FP trace rate (95% CI) | Median TTD | p95 TTD | Median files lost | Worst files lost | Recoverable | McNemar p vs D9 | Median files-lost diff vs D9 [95% CI] |`;
  const divider = `| :--- | :--- | ---: | :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | :--- |`;
  return [header, divider, ...family.summaries.map((s) => summaryRow(family.family, s, isBenign))].join('\n');
}

export function renderScorecard(results: EvalResults, options: { calibrationNotes: string[] }): string {
  const lines: string[] = [];
  lines.push('# DefySwarm Evaluation Lab — Scorecard');
  lines.push('');
  lines.push(
    '> Every number below comes from the stored run named in the footer. Detectors replay label-stripped events; ground truth is used only for scoring. Baselines are reference implementations, not vendor products.',
  );
  lines.push('');
  lines.push('## Headline');
  lines.push('');
  const overallD9 = results.overall.find((s) => s.detectorId === 'D9');
  if (overallD9) {
    lines.push(
      `- **D9 DefySwarm overall detection:** ${pct(overallD9.detectionRate)} ${ci(
        overallD9.detectionCi,
      )} across ${overallD9.attackTraces} attack traces; FP trace rate ${pct(
        overallD9.falsePositiveRate,
      )} ${ci(overallD9.falsePositiveCi)} across ${overallD9.traces} traces.`,
    );
    lines.push(
      `- **D9 median time to detect:** ${ms(overallD9.medianTimeToDetectMs)} (p95 ${ms(
        overallD9.p95TimeToDetectMs,
      )}); median files lost ${overallD9.medianFilesLost}, worst ${overallD9.worstFilesLost}.`,
    );
  }
  lines.push(
    `- **Containment latency used for the primary table:** ${results.containmentLatencyMs} ms (${results.containmentLatencySource}).`,
  );
  lines.push('');
  for (const family of results.scorecard) {
    const isBenign = family.family === 'benign';
    lines.push(`## ${isBenign ? 'Benign workload' : family.family[0].toUpperCase() + family.family.slice(1)}`);
    lines.push('');
    lines.push(familyTable(family, isBenign));
    lines.push('');
    if (isBenign) {
      lines.push(
        'For benign traces the detection-rate column is not applicable; the FP trace rate is the alert rate on workloads that contain no attack.',
      );
      lines.push('');
    }
  }

  lines.push('## Overall (all held-out traces)');
  lines.push('');
  lines.push(
    '| Detector | Traces | Attack traces | Detection rate (95% CI) | FP trace rate (95% CI) | Median TTD | p95 TTD | Median files lost | Worst files lost | Recoverable |',
  );
  lines.push('| :--- | ---: | ---: | :--- | :--- | ---: | ---: | ---: | ---: | ---: |');
  for (const s of results.overall) {
    lines.push(
      `| ${s.detectorId} ${s.detectorName} | ${s.traces} | ${s.attackTraces} | ${pct(s.detectionRate)} ${ci(
        s.detectionCi,
      )} | ${pct(s.falsePositiveRate)} ${ci(s.falsePositiveCi)} | ${ms(s.medianTimeToDetectMs)} | ${ms(
        s.p95TimeToDetectMs,
      )} | ${s.medianFilesLost} | ${s.worstFilesLost} | ${pct(s.recoverablePct / 100)} |`,
    );
  }
  lines.push('');

  lines.push('## Ablations (D9 minus one component)');
  lines.push('');
  lines.push(
    '| Detector | Component removed | Detection rate | FP trace rate | Median files lost | Δ detection vs D9 | Δ FP vs D9 |',
  );
  lines.push('| :--- | :--- | ---: | ---: | ---: | ---: | ---: |');
  for (const row of results.ablations) {
    lines.push(
      `| ${row.detectorId} | ${row.component} | ${pct(row.detectionRate)} | ${pct(
        row.falsePositiveRate,
      )} | ${row.medianFilesLost} | ${signed(row.deltaDetectionVsD9 * 100)} pp | ${signed(
        row.deltaFalsePositiveVsD9 * 100,
      )} pp |`,
    );
  }
  lines.push('');

  lines.push('## Containment-latency sensitivity');
  lines.push('');
  lines.push(
    'Files lost as the post-detection containment latency L is swept. Every detector uses the same L in each row.',
  );
  lines.push('');
  lines.push('| L | Detector | Median files lost | Detection rate |');
  lines.push('| ---: | :--- | ---: | ---: |');
  for (const row of results.sensitivity) {
    lines.push(
      `| ${row.latencyMs} ms | ${row.detectorId} | ${row.medianFilesLost} | ${pct(
        row.detectionRate,
      )} |`,
    );
  }
  lines.push('');

  lines.push('## Limitations');
  lines.push('');
  for (const limitation of results.limitations) lines.push(`- ${limitation}`);
  lines.push('');
  lines.push('## Calibration');
  lines.push('');
  for (const note of options.calibrationNotes) lines.push(`- ${note}`);
  lines.push('');

  lines.push('## Run metadata');
  lines.push('');
  lines.push('```');
  lines.push(`run id: ${results.runId}`);
  lines.push(`date: ${results.generatedAt}`);
  lines.push(`mode: ${results.mode}`);
  lines.push(`run seed: ${results.seed}`);
  lines.push(`generation seed: ${results.generationSeed}`);
  lines.push(`traces used: ${results.tracesUsed} (held-out), tuning traces: ${results.tuningTraces}`);
  lines.push(`path: ${results.environment.path}`);
  lines.push(`platform: ${results.environment.platform}`);
  lines.push(`node: ${results.environment.node}`);
  lines.push(`cpus: ${results.environment.cpus}`);
  lines.push(`memory: ${results.environment.totalMemoryMb} MB`);
  lines.push(`product version: ${results.environment.productVersion}`);
  lines.push(`detector implementation: ${results.environment.detectorImplementation}`);
  lines.push(`containment latency: ${results.containmentLatencyMs} ms (${results.containmentLatencySource})`);
  lines.push(`determinism hash: ${results.determinismHash}`);
  lines.push('```');
  lines.push('');
  lines.push(
    'Baselines are our own reference implementations of common approaches. They are not vendor products and were not supplied by any vendor. Where a baseline wins, the table says so. Where DefySwarm fails, the table says so.',
  );
  lines.push('');
  return lines.join('\n');
}
