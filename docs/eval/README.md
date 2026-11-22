# DefySwarm Evaluation Lab

An isolated, off-by-default benchmark harness. It asks one question:

> On realistic S3 telemetry, how does the shipped DefySwarm detection engine compare with common legacy approaches on detection rate, time to detect, files lost, recovery, and false positives?

The lab never touches the live store, incidents, policies, principals, or buckets. It uses its own in-memory product instances and writes only under `eval-data/`.

## Documents

| Document | What it covers |
| :--- | :--- |
| [`METHODOLOGY.md`](./METHODOLOGY.md) | Questions, arms, trace set, splits, tuning, scoring, statistics, determinism. |
| [`BASELINES.md`](./BASELINES.md) | Every detector D0–D9f, its real-world analogue, parameters, and ablations. |
| [`TRACE_PROTOCOL.md`](./TRACE_PROTOCOL.md) | Event schema, label separation, generator families, recorder gap and proposed fix. |
| [`LIMITATIONS.md`](./LIMITATIONS.md) | What the lab does not prove, and the honest scope of every claim. |
| [`CLAIMS.md`](./CLAIMS.md) | Claim-by-claim verdicts with stored-run evidence. |
| [`REPRODUCE.md`](./REPRODUCE.md) | Exact commands, flags, outputs, and expected checks. |

## Off by default

The lab is invisible unless `EVAL_LAB=1` is set on the server. The UI nav entry additionally requires `VITE_EVAL_LAB=1` because the Vite config is outside this work's edit scope.

```bash
# product, unchanged
npm run dev

# product + Evaluation Lab API/page
EVAL_LAB=1 VITE_EVAL_LAB=1 npm run dev
# open http://localhost:3000/eval

# heavy runs (child process, safety-gated)
EVAL_LAB=1 npm run eval:gen
EVAL_LAB=1 npm run eval -- run --mode fast
EVAL_LAB=1 npm run eval:live
```

With the flag off there is no `/api/eval/*` API, no `/eval` page, no nav entry, no timers, and no evaluation memory. `npm run verify:product` checks this on every step.

## Safety rails

A heavy run refuses to start when any of these is true:

- `DEMO_LOCK=1`
- the live ledger contains an `ACTIVE` or `CONTAINED` incident
- a local DefySwarm server reports an active simulator run

The check runs in the child process (`eval/safety.ts`) and again in the API route before spawning. A run is never executed in the product request path.

## Stored results

Every number in the scorecard comes from a stored run. The run directory contains:

- `results.json` — all summaries, per-trace evaluations, ablations, sensitivity, dose response
- `scorecard.md` — the human-readable scorecard
- `tuning.json` — the full tuning grid and selected point per detector
- `charts.json` — the dose-response data
- `determinism.json` — the reproducibility hash
- `per-trace.csv`, `ablations.csv`, `sensitivity.csv`
- `partial/` — resumable detector outputs from an interrupted run

`eval-data/results/latest.json` points at the latest run. Results are never hand-edited.

## Headline run

The stored full run is `eval-full-424242-761b9bcc41` (162 held-out traces, 112 attack / 50 benign). The live validation report is `eval-data/live-validation.json` (8 runs). The scorecard and ledger cite both.

At a glance, from the stored run:

- D9 detection: **100%** [96.7%, 100%] of 112 attack traces
- D9 false-positive trace rate: **0%** [0%, 2.3%]
- D9 median files lost: **1** (worst 1)
- D9 median time to detect: **0 ms** in replay; live simulator median MTTD **1 ms**
- Live simulator median MTTC: **48 ms** (p95 312 ms) across 4 attack runs
- Best baseline on the same traces: D3 58.9% detection, median 18 files lost

These are synthetic-replay and simulator numbers. Read [`LIMITATIONS.md`](./LIMITATIONS.md) before quoting them.
