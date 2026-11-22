/**
 * Flagged Evaluation Lab routes.
 *
 * Mounted only when EVAL_LAB=1. The page is a standalone server-rendered HTML
 * document so the lab adds no routes, timers, or memory to the product UI when
 * the flag is off. Heavy runs are spawned as `npm run eval` child processes;
 * this server never runs detectors in-process.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { Express, Request, Response } from 'express';
import {
  DEMO_LOCK,
  EVAL_DATA_DIR,
  LEDGER_PATH,
  LIVE_VALIDATION_PATH,
  MANIFEST_PATH,
  REPO_ROOT,
  RESULTS_DIR,
} from '../config.ts';
import { checkSafety } from '../safety.ts';

interface ActiveRun {
  id: string;
  mode: string;
  seed: number;
  startedAt: string;
  status: 'running' | 'complete' | 'failed';
  log: string;
  child: ChildProcess;
}

let activeRun: ActiveRun | null = null;

function readJson<T>(file: string): T | null {
  try {
    if (!fs.existsSync(file)) return null;
    return JSON.parse(fs.readFileSync(file, 'utf8')) as T;
  } catch {
    return null;
  }
}

function readText(file: string): string | null {
  try {
    if (!fs.existsSync(file)) return null;
    return fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}

function latestRunDirectory(): string | null {
  const latest = readJson<{ directory?: string }>(path.join(RESULTS_DIR, 'latest.json'));
  if (!latest?.directory) return null;
  const dir = path.join(EVAL_DATA_DIR, latest.directory);
  return fs.existsSync(dir) ? dir : null;
}

function requireAdmin(req: Request): boolean {
  const role = String(req.headers['x-defyswarm-role'] || 'viewer').toLowerCase();
  return role === 'admin' || role === 'operator';
}

export function mountEvalRoutes(app: Express, options: { port: number }): void {
  app.get('/api/eval/status', async (_req: Request, res: Response) => {
    const safety = await checkSafety({ port: options.port });
    res.json({
      enabled: true,
      demoLock: DEMO_LOCK,
      safety,
      activeRun: activeRun
        ? {
            id: activeRun.id,
            mode: activeRun.mode,
            seed: activeRun.seed,
            startedAt: activeRun.startedAt,
            status: activeRun.status,
          }
        : null,
      latestRun: readJson<unknown>(path.join(RESULTS_DIR, 'latest.json')),
      hasTraces: fs.existsSync(MANIFEST_PATH),
      hasLiveValidation: fs.existsSync(LIVE_VALIDATION_PATH),
    });
  });

  app.get('/api/eval/latest', (_req: Request, res: Response) => {
    const dir = latestRunDirectory();
    if (!dir) {
      res.status(404).json({ error: 'No stored evaluation run yet.' });
      return;
    }
    res.json({
      results: readJson<unknown>(path.join(dir, 'results.json')),
      scorecard: readText(path.join(dir, 'scorecard.md')),
      tuning: readJson<unknown>(path.join(dir, 'tuning.json')),
      charts: readJson<unknown>(path.join(dir, 'charts.json')),
      determinism: readJson<unknown>(path.join(dir, 'determinism.json')),
    });
  });

  app.get('/api/eval/live', (_req: Request, res: Response) => {
    res.json(readJson<unknown>(LIVE_VALIDATION_PATH) ?? { error: 'No live validation report yet.' });
  });

  app.get('/api/eval/ledger', (_req: Request, res: Response) => {
    res.json(readJson<unknown>(LEDGER_PATH) ?? { claims: [] });
  });

  app.get('/api/eval/traces', (_req: Request, res: Response) => {
    const manifest = readJson<Record<string, unknown>>(MANIFEST_PATH);
    if (!manifest) {
      res.status(404).json({ error: 'No trace manifest. Run "npm run eval:gen".' });
      return;
    }
    const { traces: _traces, ...summary } = manifest;
    res.json(summary);
  });

  app.post('/api/eval/run', async (req: Request, res: Response) => {
    if (!requireAdmin(req)) {
      res.status(403).json({ error: 'Admin or operator role required.' });
      return;
    }
    if (activeRun && activeRun.status === 'running') {
      res.status(409).json({ error: 'An evaluation run is already active.', run: activeRun.id });
      return;
    }
    const safety = await checkSafety({ port: options.port });
    if (!safety.safe) {
      res.status(409).json({ error: 'Evaluation refused by safety rails.', reasons: safety.reasons });
      return;
    }
    const mode = req.body?.mode === 'full' ? 'full' : 'fast';
    const seed = Number.isFinite(Number(req.body?.seed)) ? Number(req.body.seed) : 424242;
    const id = `run-${Date.now().toString(36)}-${crypto.randomBytes(3).toString('hex')}`;

    const child = spawn(
      'npm',
      ['run', 'eval', '--', 'run', '--mode', mode, '--seed', String(seed)],
      {
        cwd: REPO_ROOT,
        env: { ...process.env, EVAL_LAB: '1' },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    const run: ActiveRun = {
      id,
      mode,
      seed,
      startedAt: new Date().toISOString(),
      status: 'running',
      log: '',
      child,
    };
    activeRun = run;
    const append = (chunk: unknown) => {
      run.log += String(chunk);
      if (run.log.length > 200_000) run.log = run.log.slice(-200_000);
    };
    child.stdout?.on('data', append);
    child.stderr?.on('data', append);
    child.on('exit', (code) => {
      run.status = code === 0 ? 'complete' : 'failed';
      append(`\n[eval child exited with code ${code}]\n`);
    });
    child.on('error', (error) => {
      run.status = 'failed';
      append(`\n[eval child failed: ${error.message}]\n`);
    });

    res.status(202).json({ id, mode, seed, status: 'running' });
  });

  app.get('/api/eval/run/:id', (req: Request, res: Response) => {
    if (!activeRun || activeRun.id !== req.params.id) {
      res.status(404).json({ error: 'Unknown run.' });
      return;
    }
    res.json({
      id: activeRun.id,
      mode: activeRun.mode,
      seed: activeRun.seed,
      startedAt: activeRun.startedAt,
      status: activeRun.status,
      log: activeRun.log.slice(-20_000),
      latestRun: readJson<unknown>(path.join(RESULTS_DIR, 'latest.json')),
    });
  });

  app.get('/eval', (_req: Request, res: Response) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.send(renderEvalPage());
  });
}

function escapeHtml(value: unknown): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderEvalPage(): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>DefySwarm Evaluation Lab</title>
<style>
  :root { color-scheme: light; --ink:#111827; --muted:#6b7280; --line:#e5e7eb; --bg:#f7f8fa; --card:#ffffff; --blue:#1d6cf0; --red:#dc2626; --green:#059669; --amber:#b45309; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--ink); font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
  header { background:#fff; border-bottom:1px solid var(--line); padding:20px 28px; display:flex; flex-wrap:wrap; gap:16px; align-items:center; justify-content:space-between; }
  h1 { font-size:20px; margin:0; letter-spacing:-0.02em; }
  h2 { font-size:15px; margin:0 0 10px; letter-spacing:-0.01em; }
  h3 { font-size:13px; margin:0 0 8px; color:var(--muted); text-transform:uppercase; letter-spacing:0.06em; }
  main { max-width:1240px; margin:0 auto; padding:24px 28px 80px; }
  .muted { color:var(--muted); }
  .small { font-size:12px; }
  .badge { display:inline-flex; align-items:center; gap:6px; border:1px solid var(--line); background:#fff; border-radius:999px; padding:4px 10px; font-size:12px; }
  .dot { width:8px; height:8px; border-radius:50%; background:var(--green); }
  .dot.red { background:var(--red); } .dot.amber { background:var(--amber); }
  .grid { display:grid; gap:14px; }
  .cards { grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:16px; }
  .card .value { font-size:24px; font-weight:650; letter-spacing:-0.03em; margin-top:4px; }
  .card .label { font-size:12px; color:var(--muted); }
  section { margin-top:22px; }
  .panel { background:#fff; border:1px solid var(--line); border-radius:12px; padding:16px; overflow:auto; }
  table { border-collapse:collapse; width:100%; font-size:12px; }
  th, td { text-align:left; padding:7px 9px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { font-weight:600; color:#374151; background:#fafafa; position:sticky; top:0; }
  td.num, th.num { text-align:right; font-variant-numeric:tabular-nums; }
  tr.d9 td { background:#f0f7ff; font-weight:600; }
  .row { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
  button { border:1px solid var(--line); background:#fff; border-radius:8px; padding:8px 12px; font:inherit; font-size:12px; cursor:pointer; }
  button.primary { background:var(--blue); border-color:var(--blue); color:#fff; font-weight:600; }
  button:disabled { opacity:0.5; cursor:not-allowed; }
  pre { white-space:pre-wrap; word-break:break-word; background:#0b1220; color:#dbeafe; border-radius:10px; padding:12px; font-size:11.5px; max-height:340px; overflow:auto; }
  .banner { border:1px solid #fde68a; background:#fffbeb; color:#92400e; border-radius:10px; padding:10px 12px; font-size:12.5px; }
  .banner.red { border-color:#fecaca; background:#fef2f2; color:#991b1b; }
  .bar { height:8px; background:#eef2f7; border-radius:999px; overflow:hidden; }
  .bar > span { display:block; height:100%; background:var(--blue); }
  .chart { display:grid; gap:6px; }
  .chart .line { display:grid; grid-template-columns:140px 1fr 56px; gap:8px; align-items:center; font-size:11.5px; }
  .chart .line span:last-child { text-align:right; font-variant-numeric:tabular-nums; }
  footer { margin-top:28px; color:var(--muted); font-size:12px; }
  a { color:var(--blue); }
  code { background:#f3f4f6; border-radius:4px; padding:1px 5px; font-size:11.5px; }
</style>
</head>
<body>
<header>
  <div>
    <h1>Evaluation Lab</h1>
    <div class="muted small">Isolated benchmark harness. Off by default. Never touches the live store, incidents, policies, principals, or buckets.</div>
  </div>
  <div class="row">
    <span class="badge"><span class="dot" id="flag-dot"></span><span id="flag-text">Checking flag…</span></span>
    <span class="badge"><span class="dot" id="safety-dot"></span><span id="safety-text">Checking safety…</span></span>
  </div>
</header>
<main>
  <div id="banner"></div>

  <section>
    <h2>Run</h2>
    <div class="panel">
      <div class="row">
        <button class="primary" id="run-fast">Run fast</button>
        <button id="run-full">Run full</button>
        <button id="refresh">Refresh</button>
        <span class="muted small" id="run-status">No run started from this page.</span>
      </div>
      <p class="muted small" style="margin:10px 0 0">
        Runs are spawned as <code>npm run eval</code> child processes. A run refuses to start when
        <code>DEMO_LOCK=1</code>, an incident is open, or a simulator is active. Fast mode uses
        ${'`'}20 held-out traces per family${'`'}; full mode uses every held-out trace.
      </p>
    </div>
  </section>

  <section>
    <h2>Latest stored run</h2>
    <div id="meta" class="cards grid"></div>
    <div id="overall" class="panel" style="margin-top:14px"><span class="muted">Loading…</span></div>
  </section>

  <section>
    <h2>Ablations</h2>
    <div id="ablations" class="panel"><span class="muted">Loading…</span></div>
  </section>

  <section>
    <h2>Dose response</h2>
    <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(280px,1fr))">
      <div class="panel"><h3>Files lost vs attack speed (D9)</h3><div id="speed-chart" class="chart"></div></div>
      <div class="panel"><h3>Detection vs principals (D9)</h3><div id="principals-chart" class="chart"></div></div>
      <div class="panel"><h3>Detection vs attack:noise (D9)</h3><div id="ratio-chart" class="chart"></div></div>
    </div>
  </section>

  <section>
    <h2>Live validation</h2>
    <div id="live" class="panel"><span class="muted">Loading…</span></div>
  </section>

  <section>
    <h2>Claims ledger</h2>
    <div id="ledger" class="panel"><span class="muted">Loading…</span></div>
  </section>

  <section>
    <h2>Run log</h2>
    <div class="panel"><pre id="log">No run started from this page.</pre></div>
  </section>

  <footer>
    <p>Every number on this page comes from the stored run identified above. Baselines are our own reference implementations of common approaches, not vendor products. Where a baseline wins, the table says so. Where DefySwarm fails, the table says so.</p>
    <p>This page is served only when <code>EVAL_LAB=1</code>. With the flag off, the route does not exist.</p>
  </footer>
</main>
<script>
const $ = (id) => document.getElementById(id);
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const pct = (v) => v === null || v === undefined ? '—' : (v * 100).toFixed(1) + '%';
const ms = (v) => v === null || v === undefined ? '—' : Math.round(v) + ' ms';
const num = (v) => v === null || v === undefined ? '—' : Number(v).toLocaleString();

function setBadge(dotId, textId, ok, text) {
  const dot = $(dotId); const label = $(textId);
  dot.className = 'dot' + (ok === true ? '' : ok === false ? ' red' : ' amber');
  label.textContent = text;
}

function table(headers, rows) {
  return '<table><thead><tr>' + headers.map((h, i) => '<th class="' + (i === 0 ? '' : 'num') + '">' + esc(h) + '</th>').join('') + '</tr></thead><tbody>' +
    rows.map((r) => '<tr class="' + (r.className || '') + '">' + r.cells.map((c, i) => '<td class="' + (i === 0 ? '' : 'num') + '">' + c + '</td>').join('') + '</tr>').join('') +
    '</tbody></table>';
}

async function loadStatus() {
  try {
    const status = await (await fetch('/api/eval/status')).json();
    setBadge('flag-dot', 'flag-text', status.enabled === true, status.enabled ? 'EVAL_LAB=1' : 'off');
    const safety = status.safety || {};
    setBadge('safety-dot', 'safety-text', safety.safe === true, safety.safe ? 'Safe to run' : (safety.reasons || ['Blocked']).join(' · '));
    if (!safety.safe) {
      $('banner').innerHTML = '<div class="banner red"><strong>Run blocked by safety rails.</strong><br>' + esc((safety.reasons || []).join(' ')) + '</div>';
    } else if (status.demoLock) {
      $('banner').innerHTML = '<div class="banner red"><strong>DEMO_LOCK=1.</strong> Evaluation runs are blocked while a demo is locked.</div>';
    } else {
      $('banner').innerHTML = '<div class="banner">This lab is isolated. It uses its own in-memory product instances and writes only under <code>eval-data/</code>.</div>';
    }
    if (status.activeRun) {
      $('run-status').textContent = 'Run ' + status.activeRun.id + ' is ' + status.activeRun.status + ' (' + status.activeRun.mode + ').';
      poll(status.activeRun.id);
    }
  } catch (error) {
    setBadge('flag-dot', 'flag-text', false, 'status unavailable');
    $('banner').innerHTML = '<div class="banner red">Could not reach /api/eval/status: ' + esc(error.message) + '</div>';
  }
}

function metaCard(label, value, hint) {
  return '<div class="card"><div class="label">' + esc(label) + '</div><div class="value">' + esc(value) + '</div>' + (hint ? '<div class="small muted">' + esc(hint) + '</div>' : '') + '</div>';
}

async function loadLatest() {
  const response = await fetch('/api/eval/latest');
  if (!response.ok) {
    $('overall').innerHTML = '<span class="muted">No stored run yet. Generate traces and run the lab.</span>';
    $('meta').innerHTML = '';
    return;
  }
  const data = await response.json();
  const r = data.results;
  if (!r) { $('overall').innerHTML = '<span class="muted">No stored results.</span>'; return; }
  const d9 = (r.overall || []).find((s) => s.detectorId === 'D9');
  $('meta').innerHTML = [
    metaCard('Run', r.runId, r.mode + ' · seed ' + r.seed),
    metaCard('D9 detection', d9 ? pct(d9.detectionRate) : '—', d9 ? '95% CI ' + pct(d9.detectionCi[0]) + '–' + pct(d9.detectionCi[1]) : ''),
    metaCard('D9 FP trace rate', d9 ? pct(d9.falsePositiveRate) : '—', d9 ? '95% CI ' + pct(d9.falsePositiveCi[0]) + '–' + pct(d9.falsePositiveCi[1]) : ''),
    metaCard('D9 median files lost', d9 ? num(d9.medianFilesLost) : '—', d9 ? 'worst ' + num(d9.worstFilesLost) : ''),
    metaCard('Traces used', num(r.tracesUsed), r.tuningTraces + ' tuning traces'),
    metaCard('Containment latency', ms(r.containmentLatencyMs), r.containmentLatencySource),
  ].join('');
  $('overall').innerHTML = table(
    ['Detector', 'Traces', 'Attack traces', 'Detection (95% CI)', 'FP trace rate', 'Median TTD', 'p95 TTD', 'Median files lost', 'Worst', 'Recoverable'],
    (r.overall || []).map((s) => ({
      className: s.detectorId === 'D9' ? 'd9' : '',
      cells: [
        '<strong>' + esc(s.detectorId) + '</strong> ' + esc(s.detectorName),
        num(s.traces), num(s.attackTraces),
        pct(s.detectionRate) + ' [' + pct(s.detectionCi[0]) + ', ' + pct(s.detectionCi[1]) + ']',
        pct(s.falsePositiveRate),
        ms(s.medianTimeToDetectMs), ms(s.p95TimeToDetectMs),
        num(s.medianFilesLost), num(s.worstFilesLost), pct(s.recoverablePct / 100),
      ],
    })),
  );
  $('ablations').innerHTML = table(
    ['Detector', 'Component removed', 'Detection', 'FP rate', 'Median files lost', 'Δ detection vs D9', 'Δ FP vs D9'],
    (r.ablations || []).map((a) => ({ cells: [
      esc(a.detectorId), esc(a.component), pct(a.detectionRate), pct(a.falsePositiveRate), num(a.medianFilesLost),
      (a.deltaDetectionVsD9 * 100).toFixed(1) + ' pp', (a.deltaFalsePositiveVsD9 * 100).toFixed(1) + ' pp',
    ]})),
  );
  renderCharts(r.doseResponse || {});
}

function renderCharts(dose) {
  const d9Speed = (dose.filesLostVsSpeed || []).filter((x) => x.detectorId === 'D9');
  $('speed-chart').innerHTML = d9Speed.map((x) => chartLine(x.speed, x.medianFilesLost, 24)).join('') || '<span class="muted small">No data.</span>';
  const d9p = (dose.detectionVsPrincipals || []).filter((x) => x.detectorId === 'D9');
  $('principals-chart').innerHTML = d9p.map((x) => chartLine(x.principals + ' principal' + (x.principals === 1 ? '' : 's'), pct(x.detectionRate), 1, true)).join('') || '<span class="muted small">No data.</span>';
  const d9r = (dose.detectionVsAttackToNoise || []).filter((x) => x.detectorId === 'D9');
  $('ratio-chart').innerHTML = d9r.map((x) => chartLine('1:' + x.ratio, pct(x.detectionRate), 1, true)).join('') || '<span class="muted small">No data.</span>';
}

function chartLine(label, value, max, isPct) {
  const raw = isPct ? parseFloat(String(value)) : Number(value);
  const width = max > 0 ? Math.max(0, Math.min(100, (raw / max) * 100)) : 0;
  return '<div class="line"><span>' + esc(label) + '</span><div class="bar"><span style="width:' + width.toFixed(1) + '%"></span></div><span>' + esc(value) + '</span></div>';
}

async function loadLive() {
  const response = await fetch('/api/eval/live');
  const report = await response.json();
  if (!report || !report.summary) { $('live').innerHTML = '<span class="muted">No live validation report yet. Run <code>npm run eval:live</code>.</span>'; return; }
  const s = report.summary;
  $('live').innerHTML =
    '<div class="cards grid" style="margin-bottom:12px">' +
    metaCard('Detected', s.detectedRuns + '/' + s.attackRuns, 'attack runs') +
    metaCard('Contained', s.containedRuns + '/' + s.attackRuns, 'attack runs') +
    metaCard('False alarms', String(s.falseAlarms), s.benignRuns + ' benign runs') +
    metaCard('Median MTTC', ms(s.mttcMedianMs), 'live simulator') +
    metaCard('4-principal swarm', s.fourPrincipalSwarmDetected ? 'detected' : 'missed', '') +
    metaCard('2-principal swarm', s.twoPrincipalSwarmDetected ? 'detected' : 'missed', 'public API path') +
    metaCard('Swarm correlation fired', s.swarmCorrelationFired ? 'yes' : 'no', 'deciding-signal attribution') +
    '</div>' +
    table(['Scenario', 'Path', 'Detected', 'Contained', 'MTTD', 'MTTC', 'Files preserved'], report.runs.map((r) => ({ cells: [
      esc(r.scenario), esc(r.path), r.attack ? (r.detected ? 'yes' : 'no') : (r.falseAlarm ? 'FALSE ALARM' : 'clean'),
      r.attack ? (r.contained ? 'yes' : 'no') : '—', ms(r.mttdMs), ms(r.mttcMs), r.filesPreservedPct === null ? '—' : r.filesPreservedPct.toFixed(1) + '%',
    ]}))) +
    '<p class="muted small" style="margin:12px 0 0">' + report.gaps.map((g) => esc(g)).join('<br>') + '</p>';
}

async function loadLedger() {
  const response = await fetch('/api/eval/ledger');
  const ledger = await response.json();
  const claims = ledger.claims || [];
  if (claims.length === 0) { $('ledger').innerHTML = '<span class="muted">No claims ledger entries.</span>'; return; }
  $('ledger').innerHTML = table(['Claim', 'Verdict', 'Evidence', 'Source'], claims.map((c) => ({ cells: [
    esc(c.claim), '<strong>' + esc(c.verdict) + '</strong>', esc(c.evidence || ''), esc(c.source || ''),
  ]})));
}

function poll(id) {
  const timer = setInterval(async () => {
    try {
      const run = await (await fetch('/api/eval/run/' + encodeURIComponent(id))).json();
      $('run-status').textContent = 'Run ' + run.id + ': ' + run.status + ' (' + run.mode + ').';
      $('log').textContent = run.log || 'Waiting for output…';
      if (run.status !== 'running') {
        clearInterval(timer);
        await loadStatus();
        await loadLatest();
        await loadLive();
      }
    } catch (error) {
      $('run-status').textContent = 'Run status unavailable: ' + error.message;
      clearInterval(timer);
    }
  }, 1500);
}

async function startRun(mode) {
  $('run-fast').disabled = true; $('run-full').disabled = true;
  try {
    const response = await fetch('/api/eval/run', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-defyswarm-role': 'admin' },
      body: JSON.stringify({ mode }),
    });
    const body = await response.json();
    if (!response.ok) {
      $('run-status').textContent = body.error || 'Run refused.';
      $('log').textContent = (body.reasons || []).join('\n') || body.error || 'Run refused.';
      return;
    }
    $('run-status').textContent = 'Run ' + body.id + ' started (' + body.mode + ').';
    $('log').textContent = 'Starting…';
    poll(body.id);
  } catch (error) {
    $('run-status').textContent = 'Could not start run: ' + error.message;
  } finally {
    $('run-fast').disabled = false; $('run-full').disabled = false;
  }
}

$('run-fast').addEventListener('click', () => startRun('fast'));
$('run-full').addEventListener('click', () => startRun('full'));
$('refresh').addEventListener('click', () => { loadStatus(); loadLatest(); loadLive(); loadLedger(); });

loadStatus(); loadLatest(); loadLive(); loadLedger();
</script>
</body>
</html>`;
}

export function evalDataPath(...parts: string[]): string {
  return path.join(EVAL_DATA_DIR, ...parts);
}
