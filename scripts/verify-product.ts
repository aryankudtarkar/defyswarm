#!/usr/bin/env tsx
/**
 * Product regression gate.
 *
 * Builds the product, starts it in production mode from a temp working
 * directory, exercises the shipped simulator, checks that the Evaluation Lab
 * is absent when EVAL_LAB is unset, and compares the invariants with a stored
 * golden baseline.
 *
 * Usage:
 *   npm run verify:product
 *   npm run verify:product -- --update-golden
 *   npm run verify:product -- --no-build
 */
import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { REPO_ROOT } from '../eval/config.ts';
import { api, startProductServer } from '../eval/live/productServer.ts';

const GOLDEN_PATH = path.join(REPO_ROOT, 'tests', 'golden', 'product-baseline.json');

interface SimState {
  running: boolean;
  scenario?: string;
  completedAt?: string;
  assertions: Array<{ id: string; status: string; detail?: string }>;
  summary?: string;
}

interface Bootstrap {
  buckets: Array<{ name: string }>;
  principals: Array<{ id: string; status: string }>;
  canaries: unknown[];
  incidents: Array<{
    id: string;
    status: string;
    mttdMs: number;
    mttcMs?: number;
    filesPreservedPct: number;
    principals: string[];
  }>;
  policy: { mode: string };
  simulator: SimState;
}

interface Report {
  baselineCommit: string;
  bootstrap: {
    bucketCount: number;
    principalCount: number;
    canaryCount: number;
    policyMode: string;
    incidentCount: number;
  };
  benign: {
    incidentCount: number;
    assertionsAllPass: boolean;
  };
  ransomware: {
    detected: boolean;
    contained: boolean;
    filesPreservedPct: number;
    mttdMs: number;
    mttcMs: number | null;
  };
  flagOff: {
    status: number;
    isEvalApi: boolean;
  };
  flagOn: {
    status: number;
    isEvalApi: boolean;
  };
}

function readCommit(): string {
  try {
    return execSync('git rev-parse --short HEAD', { cwd: REPO_ROOT, encoding: 'utf8' }).trim();
  } catch {
    return 'unknown';
  }
}

async function waitForSim(baseUrl: string, timeoutMs = 120_000): Promise<Bootstrap> {
  const deadline = Date.now() + timeoutMs;
  let sawRunning = false;
  while (Date.now() < deadline) {
    const state = await api<Bootstrap>(baseUrl, '/api/bootstrap');
    if (state.simulator.running) sawRunning = true;
    if (sawRunning && !state.simulator.running) return state;
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  throw new Error('Timed out waiting for the simulator.');
}

async function runScenario(baseUrl: string, scenario: string): Promise<Bootstrap> {
  await api(baseUrl, '/api/simulator/reset', { method: 'POST', body: '{}' });
  await api(baseUrl, '/api/simulator/run', {
    method: 'POST',
    body: JSON.stringify({ scenario, bucket: 'finance-prod' }),
  });
  return waitForSim(baseUrl);
}

async function evalStatusProbe(
  baseUrl: string,
): Promise<{ status: number; isEvalApi: boolean }> {
  const response = await fetch(`${baseUrl}/api/eval/status`, {
    signal: AbortSignal.timeout(3000),
  });
  const text = await response.text();
  let isEvalApi = false;
  try {
    const body = JSON.parse(text) as { enabled?: boolean };
    isEvalApi = body.enabled === true;
  } catch {
    isEvalApi = false;
  }
  return { status: response.status, isEvalApi };
}

async function collect(): Promise<Report> {
  const off = await startProductServer();
  let flagOffProbe: { status: number; isEvalApi: boolean };
  let bootstrap: Bootstrap;
  let benign: Bootstrap;
  let ransomware: Bootstrap;
  try {
    bootstrap = await api<Bootstrap>(off.baseUrl, '/api/bootstrap');
    flagOffProbe = await evalStatusProbe(off.baseUrl);
    benign = await runScenario(off.baseUrl, 'benign_bulk');
    ransomware = await runScenario(off.baseUrl, 'standard_ransomware');
  } finally {
    await off.stop();
  }

  const on = await startProductServer({ extraEnv: { EVAL_LAB: '1', VITE_EVAL_LAB: '1' } });
  let flagOnProbe: { status: number; isEvalApi: boolean };
  try {
    flagOnProbe = await evalStatusProbe(on.baseUrl);
  } finally {
    await on.stop();
  }

  const incident = ransomware.incidents[0];
  return {
    baselineCommit: readCommit(),
    bootstrap: {
      bucketCount: bootstrap.buckets.length,
      principalCount: bootstrap.principals.length,
      canaryCount: bootstrap.canaries.length,
      policyMode: bootstrap.policy.mode,
      incidentCount: bootstrap.incidents.length,
    },
    benign: {
      incidentCount: benign.incidents.length,
      assertionsAllPass: benign.simulator.assertions.every((a) => a.status === 'pass'),
    },
    ransomware: {
      detected: Boolean(incident),
      contained: Boolean(incident && ['CONTAINED', 'RESTORED'].includes(incident.status)),
      filesPreservedPct: incident?.filesPreservedPct ?? 0,
      mttdMs: incident?.mttdMs ?? Number.POSITIVE_INFINITY,
      mttcMs: incident?.mttcMs ?? null,
    },
    flagOff: flagOffProbe,
    flagOn: flagOnProbe,
  };
}

function compare(actual: Report, golden: Report): string[] {
  const problems: string[] = [];
  const expect = (label: string, condition: boolean, detail: string) => {
    if (!condition) problems.push(`${label}: ${detail}`);
  };
  expect(
    'bootstrap.bucketCount',
    actual.bootstrap.bucketCount === golden.bootstrap.bucketCount,
    `${actual.bootstrap.bucketCount} != ${golden.bootstrap.bucketCount}`,
  );
  expect(
    'bootstrap.principalCount',
    actual.bootstrap.principalCount === golden.bootstrap.principalCount,
    `${actual.bootstrap.principalCount} != ${golden.bootstrap.principalCount}`,
  );
  expect(
    'bootstrap.canaryCount',
    actual.bootstrap.canaryCount === golden.bootstrap.canaryCount,
    `${actual.bootstrap.canaryCount} != ${golden.bootstrap.canaryCount}`,
  );
  expect(
    'bootstrap.policyMode',
    actual.bootstrap.policyMode === golden.bootstrap.policyMode,
    `${actual.bootstrap.policyMode} != ${golden.bootstrap.policyMode}`,
  );
  expect(
    'benign.incidentCount',
    actual.benign.incidentCount === 0,
    `${actual.benign.incidentCount} incidents`,
  );
  expect(
    'benign.assertionsAllPass',
    actual.benign.assertionsAllPass,
    'at least one simulator assertion failed',
  );
  expect('ransomware.detected', actual.ransomware.detected, 'no incident was created');
  expect('ransomware.contained', actual.ransomware.contained, 'incident was not contained');
  expect(
    'ransomware.filesPreservedPct',
    actual.ransomware.filesPreservedPct >= 90,
    `${actual.ransomware.filesPreservedPct}% < 90%`,
  );
  expect('ransomware.mttdMs', actual.ransomware.mttdMs <= 5000, `${actual.ransomware.mttdMs} ms > 5000 ms`);
  expect(
    'ransomware.mttcMs',
    typeof actual.ransomware.mttcMs === 'number' && actual.ransomware.mttcMs <= 10_000,
    `${actual.ransomware.mttcMs} ms > 10000 ms`,
  );
  expect(
    'flagOff.evalIsApi',
    actual.flagOff.isEvalApi === false,
    'the eval API answered while EVAL_LAB was unset',
  );
  expect(
    'flagOn.evalIsApi',
    actual.flagOn.isEvalApi === true,
    'the eval API did not answer with EVAL_LAB=1',
  );
  expect('flagOn.status', actual.flagOn.status === 200, `${actual.flagOn.status} != 200`);
  return problems;
}

async function main(): Promise<void> {
  const noBuild = process.argv.includes('--no-build');
  const updateGolden = process.argv.includes('--update-golden');

  if (!noBuild) {
    console.log('Building product...');
    execSync('npm run build', { cwd: REPO_ROOT, stdio: 'inherit' });
  }

  console.log('Collecting product invariants...');
  const report = await collect();

  if (updateGolden || !fs.existsSync(GOLDEN_PATH)) {
    fs.mkdirSync(path.dirname(GOLDEN_PATH), { recursive: true });
    fs.writeFileSync(
      GOLDEN_PATH,
      `${JSON.stringify(
        {
          generatedAt: new Date().toISOString(),
          note:
            'Golden product invariants captured from the untouched baseline. Counts are structural; latency and preservation checks are thresholds.',
          ...report,
        },
        null,
        2,
      )}\n`,
      'utf8',
    );
    console.log(`Wrote golden baseline: ${path.relative(REPO_ROOT, GOLDEN_PATH)}`);
    return;
  }

  const golden = JSON.parse(fs.readFileSync(GOLDEN_PATH, 'utf8')) as Report;
  const problems = compare(report, golden);
  console.log(JSON.stringify(report, null, 2));
  if (problems.length > 0) {
    console.error('\nverify:product FAILED');
    for (const problem of problems) console.error(`- ${problem}`);
    process.exit(1);
  }
  console.log('\nverify:product PASSED');
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack ?? error.message : error);
  process.exit(1);
});
