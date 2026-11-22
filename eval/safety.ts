/**
 * Safety rails for the Evaluation Lab.
 *
 * The lab must never run while a live demo is active. Heavy work runs in a
 * child process and refuses to start when any of these is true:
 *   - DEMO_LOCK=1
 *   - the live ledger holds an incident that is not fully restored
 *   - a local DefySwarm server reports an active simulator run
 */
import fs from 'node:fs';
import path from 'node:path';
import { DEMO_LOCK, EVAL_LAB, REPO_ROOT } from './config.ts';

export class EvalSafetyError extends Error {
  public readonly reasons: string[];
  constructor(reasons: string[]) {
    super(`Evaluation Lab refused to start:\n- ${reasons.join('\n- ')}`);
    this.name = 'EvalSafetyError';
    this.reasons = reasons;
  }
}

export interface SafetyReport {
  safe: boolean;
  reasons: string[];
  checked: {
    evalLab: boolean;
    demoLock: boolean;
    openIncidents: number;
    simulatorActive: boolean | null;
  };
}

function readOpenIncidentCount(): { count: number; error?: string } {
  const ledgerFile = path.join(REPO_ROOT, 'data', 'ledger.json');
  try {
    if (!fs.existsSync(ledgerFile)) return { count: 0 };
    const parsed = JSON.parse(fs.readFileSync(ledgerFile, 'utf8')) as {
      incidents?: Array<{ status?: string }>;
    };
    const incidents = Array.isArray(parsed.incidents) ? parsed.incidents : [];
    const open = incidents.filter(
      (incident) => incident.status === 'ACTIVE' || incident.status === 'CONTAINED',
    );
    return { count: open.length };
  } catch (error) {
    return { count: 0, error: error instanceof Error ? error.message : 'unreadable ledger' };
  }
}

async function probeSimulator(port: number): Promise<boolean | null> {
  try {
    const response = await fetch(`http://127.0.0.1:${port}/api/bootstrap`, {
      signal: AbortSignal.timeout(800),
    });
    if (!response.ok) return null;
    const body = (await response.json()) as { simulator?: { running?: boolean } };
    return Boolean(body?.simulator?.running);
  } catch {
    return null;
  }
}

export async function checkSafety(options: { port?: number } = {}): Promise<SafetyReport> {
  const reasons: string[] = [];
  if (!EVAL_LAB) {
    reasons.push('EVAL_LAB is not 1. The lab is off by default; set EVAL_LAB=1 to enable it.');
  }
  if (DEMO_LOCK) {
    reasons.push('DEMO_LOCK=1 is set. A demo is locked; evaluation runs are blocked.');
  }
  const openIncidents = readOpenIncidentCount();
  if (openIncidents.count > 0) {
    reasons.push(
      `The live ledger has ${openIncidents.count} open incident(s). Restore them before running an evaluation.`,
    );
  }
  const simulatorActive = await probeSimulator(options.port ?? Number(process.env.PORT || 3000));
  if (simulatorActive === true) {
    reasons.push('A DefySwarm server reports an active simulator run. Wait for it to finish.');
  }
  return {
    safe: reasons.length === 0,
    reasons,
    checked: {
      evalLab: EVAL_LAB,
      demoLock: DEMO_LOCK,
      openIncidents: openIncidents.count,
      simulatorActive,
    },
  };
}

export async function assertSafeToRun(options: { port?: number } = {}): Promise<void> {
  const report = await checkSafety(options);
  if (!report.safe) throw new EvalSafetyError(report.reasons);
}
