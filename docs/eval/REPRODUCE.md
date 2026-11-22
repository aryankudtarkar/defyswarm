# Reproduce

## Prerequisites

- Node 24+ (the repo runs TypeScript directly through `tsx`)
- Dependencies installed: `npm install --no-audit --no-fund --legacy-peer-deps`
- No live incident open, no simulator running, `DEMO_LOCK` unset

The lab refuses to run if any of those safety conditions fail.

## Generate the trace set

```bash
EVAL_LAB=1 npm run eval:gen
```

Writes `eval-data/traces/generated/*.jsonl` and `eval-data/traces/manifest.json`. The generation seed defaults to `20261122`; override with `-- --seed N`.

## Run the replay scorecard

```bash
# fast: 20 held-out traces per family
EVAL_LAB=1 npm run eval -- run --mode fast

# full: every held-out trace
EVAL_LAB=1 npm run eval -- run --mode full
```

Writes `eval-data/results/<runId>/` and points `eval-data/results/latest.json` at it. The run id is deterministic from the mode, seed, manifest hash, selected tuning parameters, and containment latency.

The runner resumes from `partial/` if interrupted. Delete the run directory to force a clean run.

## Live validation

```bash
npm run build            # live validation needs dist/
EVAL_LAB=1 npm run eval:live
```

Starts a throwaway product server from a temp working directory, runs the four benign scenarios, standard ransomware, the 4-principal stealth swarm, recovery verification, and a 2-principal swarm through the public storage API. Writes `eval-data/live-validation.json`.

The next replay run reads the live MTTC median from this report and uses it as the containment latency. The scorecard prints the source.

## Record and calibrate

```bash
EVAL_LAB=1 npm run eval:record
EVAL_LAB=1 npm run eval:calibrate
```

Recording requires `dist/`. It writes `eval-data/traces/recorded/`. Calibration writes `eval-data/calibration.json`. With no recordings, calibration stays at defaults and the scorecard says so.

## Determinism check

```bash
EVAL_LAB=1 npm run eval:check
```

Runs the fast evaluation twice from a clean state and compares the determinism hash. Expected output: `Determinism check passed: <hash>`.

## Product regression gate

```bash
npm run verify:product
```

Builds the product, starts it in production mode from a temp directory, checks the baseline invariants, runs benign and standard-ransomware scenarios, verifies that the eval API is absent with `EVAL_LAB` unset and present with `EVAL_LAB=1`, and compares against `tests/golden/product-baseline.json`.

Useful variants:

```bash
npm run verify:product -- --no-build
npm run verify:product -- --update-golden
```

`--update-golden` is only for an intentional product baseline change. It rewrites the golden file.

## Unit tests

```bash
npm run test:eval
```

Covers PRNG determinism, statistics (hand-checked Wilson/McNemar/percentile/Cliffs delta), trace scoring, generator determinism, label separation, and the isolation test that every detector leaves `data/` unchanged.

## Everything in one command

```bash
EVAL_LAB=1 npm run eval:all
```

Generates, runs the fast scorecard, and runs live validation.

## The page

```bash
npm run build
EVAL_LAB=1 VITE_EVAL_LAB=1 PORT=3000 npm run dev
# or: EVAL_LAB=1 VITE_EVAL_LAB=1 PORT=3000 npm start
# open http://localhost:3000/eval
```

The page reads stored results only. The Run buttons spawn `npm run eval` as a child process after the same safety check.

## Expected flags

| Variable | Effect |
| :--- | :--- |
| `EVAL_LAB=1` | Server mounts `/api/eval/*` and `/eval` |
| `VITE_EVAL_LAB=1` | UI shows the Evaluation Lab nav entry |
| `DEMO_LOCK=1` | Blocks every lab run, including the page buttons |

With `EVAL_LAB` unset, `/api/eval/status` is not an API endpoint and `/eval` is not served by the lab. `verify:product` asserts this.
