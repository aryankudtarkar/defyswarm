#!/usr/bin/env tsx
/**
 * Evaluation Lab CLI.
 *
 * Everything user-facing is behind EVAL_LAB=1. Heavy work runs in this child
 * process so the dev server is never blocked. The safety gate refuses to start
 * while a demo is locked, an incident is open, or a simulator run is active.
 */
import fs from 'node:fs';
import path from 'node:path';
import { EVAL_LAB, RESULTS_DIR, DEFAULT_RUN_SEED } from '../eval/config.ts';
import { assertSafeToRun, checkSafety } from '../eval/safety.ts';
import { buildSpecs, generateTrace, writeGeneratedTraces } from '../eval/generator/generate.ts';
import { runEvaluation, formatRunSummary } from '../eval/runner/run.ts';
import { runLiveValidation } from '../eval/live/validate.ts';
import { recordTraces } from '../eval/recorder/recorder.ts';
import { fitCalibration } from '../eval/recorder/calibrate.ts';

function arg(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`);
  if (index >= 0 && index + 1 < process.argv.length) return process.argv[index + 1];
  return undefined;
}

function flag(name: string): boolean {
  return process.argv.includes(`--${name}`);
}

function requireFlag(): void {
  if (!EVAL_LAB) {
    console.error(
      'The Evaluation Lab is off. Re-run with EVAL_LAB=1 (and VITE_EVAL_LAB=1 for the UI).',
    );
    process.exit(2);
  }
}

async function main(): Promise<void> {
  requireFlag();
  const command = process.argv[2] ?? 'help';
  const seed = Number(arg('seed') ?? DEFAULT_RUN_SEED);

  switch (command) {
    case 'gen': {
      await assertSafeToRun();
      const generationSeed = Number(arg('seed') ?? 20261122);
      const manifest = writeGeneratedTraces(generationSeed);
      console.log(
        `Generated ${manifest.totalTraces} traces (${manifest.tuningTraces} tuning, ${manifest.heldoutTraces} held-out) with seed ${manifest.generationSeed}.`,
      );
      console.log(`Manifest: eval-data/traces/manifest.json`);
      return;
    }
    case 'run': {
      await assertSafeToRun();
      const mode = arg('mode') === 'full' ? 'full' : 'fast';
      if (flag('fresh')) {
        const manifest = JSON.parse(
          fs.readFileSync(path.join('eval-data', 'traces', 'manifest.json'), 'utf8'),
        ) as { generationSeed: number };
        void manifest;
        fs.rmSync(path.join(RESULTS_DIR, 'partial'), { recursive: true, force: true });
      }
      const results = runEvaluation({ mode, seed });
      console.log(formatRunSummary(results));
      return;
    }
    case 'check': {
      await assertSafeToRun();
      const first = runEvaluation({ mode: 'fast', seed });
      const firstHash = first.determinismHash;
      fs.rmSync(path.join(RESULTS_DIR, first.runId), { recursive: true, force: true });
      const second = runEvaluation({ mode: 'fast', seed });
      const secondHash = second.determinismHash;
      if (firstHash !== secondHash) {
        console.error(`Determinism check FAILED: ${firstHash} != ${secondHash}`);
        process.exit(1);
      }
      console.log(`Determinism check passed: ${firstHash}`);
      return;
    }
    case 'record': {
      await assertSafeToRun();
      const count = await recordTraces({ scenarios: arg('scenarios')?.split(',') });
      console.log(`Recorded ${count} trace(s) into eval-data/traces/recorded.`);
      return;
    }
    case 'calibrate': {
      const profile = fitCalibration();
      console.log(
        profile.recordings === 0
          ? 'No recordings found. Calibration stays at defaults; the scorecard states this plainly.'
          : `Calibration fitted to ${profile.recordings} recording(s).`,
      );
      return;
    }
    case 'live': {
      await assertSafeToRun();
      const report = await runLiveValidation({ seed });
      console.log(
        `Live validation: ${report.runs.length} run(s); D9 detected ${report.summary.detectedRuns}/${report.summary.attackRuns} attack runs; median MTTC ${report.summary.mttcMedianMs ?? 'n/a'} ms.`,
      );
      console.log('Report: eval-data/live-validation.json');
      return;
    }
    case 'all': {
      await assertSafeToRun();
      const generationSeed = Number(arg('seed') ?? 20261122);
      const manifest = writeGeneratedTraces(generationSeed);
      console.log(`Generated ${manifest.totalTraces} traces.`);
      const mode = arg('mode') === 'full' ? 'full' : 'fast';
      const results = runEvaluation({ mode, seed });
      console.log(formatRunSummary(results));
      const report = await runLiveValidation({ seed });
      console.log(
        `Live validation: D9 detected ${report.summary.detectedRuns}/${report.summary.attackRuns} attack runs; median MTTC ${report.summary.mttcMedianMs ?? 'n/a'} ms.`,
      );
      return;
    }
    case 'safety': {
      const report = await checkSafety();
      console.log(JSON.stringify(report, null, 2));
      process.exit(report.safe ? 0 : 1);
      return;
    }
    case 'specs': {
      const specs = buildSpecs(Number(arg('seed') ?? 20261122));
      console.log(`${specs.length} specs`);
      for (const spec of specs.slice(0, 5)) {
        const trace = generateTrace(spec);
        console.log(
          `${spec.kind}: ${trace.events.length} events, ${trace.groundTruth.attackFiles.length} attack files`,
        );
      }
      return;
    }
    default:
      console.log(
        [
          'Usage: EVAL_LAB=1 npm run eval -- <command> [options]',
          '',
          'Commands:',
          '  gen [--seed N]                 generate the deterministic trace set',
          '  run [--mode fast|full] [--seed N]',
          '  check [--seed N]               run twice and compare determinism hashes',
          '  record [--scenarios a,b]       record live simulator telemetry',
          '  calibrate                      fit generator calibration from recordings',
          '  live [--seed N]                live validation against the product simulator',
          '  all [--mode fast|full]         gen + run + live',
          '  safety                         print the safety gate result',
          '',
          'Note: this command refuses to run when DEMO_LOCK=1, an incident is open,',
          'or a local DefySwarm server reports an active simulator run.',
        ].join('\n'),
      );
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
