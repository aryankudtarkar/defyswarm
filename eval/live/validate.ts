/**
 * Live validation against the real product.
 *
 * Two paths are measured:
 *   1. The shipped simulator scenarios (benign x4, standard ransomware,
 *      4-principal stealth swarm, recovery verification).
 *   2. A 2-principal swarm driven through the public storage API
 *      (/api/storage/objects/encrypt-test), because the shipped simulator
 *      only emits the 4-principal swarm.
 *
 * Every run starts from a fresh reset on a throwaway server whose working
 * directory is a temp folder. The repository's data/ is never touched.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { LIVE_VALIDATION_PATH, REPO_ROOT } from '../config.ts';
import { median } from '../stats.ts';
import { api, startProductServer } from './productServer.ts';

const SIM_SCENARIOS = [
  'benign_bulk',
  'benign_compressed',
  'benign_rename',
  'benign_backup_sync',
  'standard_ransomware',
  'stealth_ai_swarm',
  'recovery_verification',
] as const;

interface SimAssertion {
  id: string;
  label: string;
  status: string;
  detail?: string;
}

interface Incident {
  id: string;
  status: string;
  mttdMs: number;
  mttcMs?: number;
  filesPreservedPct: number;
  isSwarm: boolean;
  principals: string[];
}

interface Bootstrap {
  simulator: {
    running: boolean;
    scenario?: string;
    startedAt?: string;
    completedAt?: string;
    assertions: SimAssertion[];
    summary?: string;
  };
  incidents: Incident[];
  objects?: unknown[];
}

export interface LiveRun {
  scenario: string;
  path: 'simulator' | 'public-api';
  attack: boolean;
  detected: boolean;
  contained: boolean;
  mttdMs: number | null;
  mttcMs: number | null;
  filesPreservedPct: number | null;
  principals: number;
  isSwarm: boolean;
  falseAlarm: boolean;
  assertions: SimAssertion[];
  incidentId?: string;
  notes?: string;
}

export interface LiveReport {
  generatedAt: string;
  path: 'live';
  productVersion: string;
  environment: { platform: string; node: string; cpus: number };
  runs: LiveRun[];
  summary: {
    runs: number;
    attackRuns: number;
    detectedRuns: number;
    containedRuns: number;
    falseAlarms: number;
    benignRuns: number;
    mttdMedianMs: number | null;
    mttcMedianMs: number | null;
    fourPrincipalSwarmDetected: boolean;
    twoPrincipalSwarmDetected: boolean;
    swarmCorrelationFired: boolean;
    recoveryVerified: boolean;
  };
  gaps: string[];
}

async function waitForCompletion(baseUrl: string, timeoutMs = 120_000): Promise<Bootstrap> {
  const deadline = Date.now() + timeoutMs;
  let sawRunning = false;
  while (Date.now() < deadline) {
    const state = await api<Bootstrap>(baseUrl, '/api/bootstrap');
    if (state.simulator.running) sawRunning = true;
    if (sawRunning && !state.simulator.running) return state;
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  throw new Error('Timed out waiting for the simulator to finish.');
}

async function runSimulatorScenario(baseUrl: string, scenario: string): Promise<LiveRun> {
  await api(baseUrl, '/api/simulator/reset', { method: 'POST', body: '{}' });
  await api(baseUrl, '/api/simulator/run', {
    method: 'POST',
    body: JSON.stringify({ scenario, bucket: 'finance-prod' }),
  });
  const state = await waitForCompletion(baseUrl);
  const attack = !scenario.startsWith('benign_');
  const incident = state.incidents[0];
  const detected = attack ? Boolean(incident) : state.incidents.length > 0;
  return {
    scenario,
    path: 'simulator',
    attack,
    detected: attack ? detected : false,
    contained: attack ? Boolean(incident && ['CONTAINED', 'RESTORED'].includes(incident.status)) : false,
    mttdMs: incident?.mttdMs ?? null,
    mttcMs: incident?.mttcMs ?? null,
    filesPreservedPct: incident?.filesPreservedPct ?? null,
    principals: incident?.principals.length ?? 0,
    isSwarm: Boolean(incident?.isSwarm),
    falseAlarm: attack ? false : state.incidents.length > 0,
    assertions: state.simulator.assertions,
    incidentId: incident?.id,
    notes: state.simulator.summary,
  };
}

async function runTwoPrincipalSwarm(baseUrl: string): Promise<LiveRun> {
  await api(baseUrl, '/api/simulator/reset', { method: 'POST', body: '{}' });
  const listed = await api<{ objects: Array<{ key: string; isCanary?: boolean }> }>(
    baseUrl,
    '/api/storage/objects?bucket=finance-prod',
  );
  const keys = listed.objects
    .filter((object) => !object.isCanary)
    .map((object) => object.key)
    .slice(0, 24);
  if (keys.length < 6) {
    return {
      scenario: 'swarm_2_principal_public_api',
      path: 'public-api',
      attack: true,
      detected: false,
      contained: false,
      mttdMs: null,
      mttcMs: null,
      filesPreservedPct: null,
      principals: 2,
      isSwarm: false,
      falseAlarm: false,
      assertions: [],
      notes: `Only ${keys.length} non-canary objects available; skipped the 2-principal API swarm.`,
    };
  }

  const principals = ['swarm-node-alpha', 'swarm-node-beta'];
  let blockedAt: number | null = null;
  let writes = 0;
  const start = Date.now();
  for (let i = 0; i < 16; i++) {
    const key = keys[i % keys.length];
    const principalId = principals[i % principals.length];
    const response = await fetch(`${baseUrl}/api/storage/objects/encrypt-test`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-defyswarm-role': 'admin' },
      body: JSON.stringify({ bucket: 'finance-prod', key, principalId }),
    });
    if (response.status === 403) {
      blockedAt = Date.now();
      break;
    }
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`encrypt-test failed: HTTP ${response.status} ${text.slice(0, 200)}`);
    }
    writes++;
  }
  const state = await api<Bootstrap>(baseUrl, '/api/bootstrap');
  const incident = state.incidents[0];
  const detected = Boolean(incident);
  return {
    scenario: 'swarm_2_principal_public_api',
    path: 'public-api',
    attack: true,
    detected,
    contained: Boolean(incident && ['CONTAINED', 'RESTORED'].includes(incident.status)),
    mttdMs: incident?.mttdMs ?? null,
    mttcMs:
      incident?.mttcMs ??
      (blockedAt !== null ? blockedAt - start : null),
    filesPreservedPct: incident?.filesPreservedPct ?? null,
    principals: incident?.principals.length ?? 0,
    isSwarm: Boolean(incident?.isSwarm),
    falseAlarm: false,
    assertions: state.simulator.assertions,
    incidentId: incident?.id,
    notes: `${writes} accepted API writes across ${principals.length} principals before ${
      blockedAt ? 'the first 403' : 'completion without a block'
    }.`,
  };
}

function readProductVersion(): string {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8')) as {
      version?: string;
    };
    return pkg.version ?? 'unknown';
  } catch {
    return 'unknown';
  }
}

export async function runLiveValidation(options: { seed?: number; iterations?: number } = {}): Promise<LiveReport> {
  const iterations = Math.max(1, Math.min(5, options.iterations ?? 1));
  const server = await startProductServer();
  const runs: LiveRun[] = [];
  try {
    for (const scenario of SIM_SCENARIOS) {
      const repeats = scenario.startsWith('benign_') ? 1 : iterations;
      for (let i = 0; i < repeats; i++) {
        runs.push(await runSimulatorScenario(server.baseUrl, scenario));
      }
    }
    runs.push(await runTwoPrincipalSwarm(server.baseUrl));
  } finally {
    await server.stop();
  }

  const attackRuns = runs.filter((r) => r.attack);
  const benignRuns = runs.filter((r) => !r.attack);
  const detectedRuns = attackRuns.filter((r) => r.detected).length;
  const containedRuns = attackRuns.filter((r) => r.contained).length;
  const mttds = attackRuns
    .map((r) => r.mttdMs)
    .filter((v): v is number => typeof v === 'number');
  const mttcs = attackRuns
    .map((r) => r.mttcMs)
    .filter((v): v is number => typeof v === 'number');

  const report: LiveReport = {
    generatedAt: new Date().toISOString(),
    path: 'live',
    productVersion: readProductVersion(),
    environment: {
      platform: `${os.platform()} ${os.release()}`,
      node: process.version,
      cpus: os.cpus().length,
    },
    runs,
    summary: {
      runs: runs.length,
      attackRuns: attackRuns.length,
      detectedRuns,
      containedRuns,
      falseAlarms: benignRuns.filter((r) => r.falseAlarm).length,
      benignRuns: benignRuns.length,
      mttdMedianMs: mttds.length > 0 ? median(mttds) : null,
      mttcMedianMs: mttcs.length > 0 ? median(mttcs) : null,
      fourPrincipalSwarmDetected: runs.some(
        (r) => r.scenario === 'stealth_ai_swarm' && r.detected && r.principals === 4,
      ),
      twoPrincipalSwarmDetected: runs.some(
        (r) => r.path === 'public-api' && r.detected && r.principals === 2,
      ),
      swarmCorrelationFired: runs.some((r) => r.isSwarm),
      recoveryVerified: runs.some(
        (r) =>
          r.scenario === 'recovery_verification' &&
          r.assertions.some((a) => a.id === 'sha256' && a.status === 'pass'),
      ),
    },
    gaps: [
      'The shipped simulator only emits a 4-principal swarm. The 2-principal swarm is driven through the public storage API and reported separately.',
      'Live telemetry events do not carry a scenario tag, object version id, size, or source address. Recorded labels therefore come from CLI metadata.',
      'Live MTTC is measured on the product simulator. It is not a network round-trip measurement against a customer environment.',
      'The recovery verification scenario triggers a 1-Click Restore and checks SHA-256 matches; it does not prove vault durability on a free-tier host that can sleep or lose data.',
    ],
  };

  fs.mkdirSync(path.dirname(LIVE_VALIDATION_PATH), { recursive: true });
  fs.writeFileSync(LIVE_VALIDATION_PATH, JSON.stringify(report, null, 2), 'utf8');
  return report;
}
