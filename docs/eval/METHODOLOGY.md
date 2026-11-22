# Methodology

## Questions

1. How often does each detector detect a labelled attack trace?
2. How quickly does it detect, and how many real files are lost before containment?
3. How often does it alert on a benign trace?
4. Does recovery work, and what is the recovery-point loss?
5. Which DefySwarm components are load-bearing (ablations)?
6. How do files lost change as post-detection containment latency changes?
7. Does the result reproduce from the same seeds?

## Arms

| Arm | Detector | Real-world analogue |
| :--- | :--- | :--- |
| D0 | Versioning only | S3 versioning with no detection or response |
| D1 | Snapshot/backup only | Scheduled backup and restore |
| D2 | Per-principal behavioural anomaly | Cloud-native S3 threat detection |
| D3 | Per-principal batch rate rule | SIEM/log alarm evaluated in batches |
| D4 | Upload malware/signature scan | Defender-for-Storage-style scanning |
| D5 | Sync-client heuristic | Drive/OneDrive desktop ransomware detection |
| D6 | Extension/ransom-note blacklist | File screening and AV signatures |
| D7 | Fixed-name canary | Obvious canary-token tripwires |
| D8 | Entropy-only threshold | Naive "high entropy means encrypted" rule |
| D9 | Shipped DefySwarm engine | The product, unmodified |
| D9a–D9f | D9 ablations | One component removed at a time |

D0–D8 are our own reference implementations. They are not vendor products and were not supplied by any vendor. D9 imports the shipped `server/detectionEngine.ts` and `server/storageAdapter.ts` read-only and instantiates a fresh in-memory pair per trace.

## Trace set

The generator (`eval/generator/generate.ts`) produces four families:

| Family | Traces (generated) | What it contains |
| :--- | ---: | :--- |
| benign | 63 | Bulk uploads, compressed media, renames, backups, DLP scans, CI overwrites, photo imports, archive extraction, compressed logs |
| ransomware | 70 | 5 attack methods × 3 speeds × 3 principal counts, plus sabotage variants |
| swarm | 42 | 2/4/8 principals, external-KMS/AES/SSE-C, slow and medium |
| mixed | 35 | Attacks hidden inside 1:5, 1:20, 1:100 benign noise |

210 traces total. A deterministic hash of the trace id assigns 30% to tuning and 70% to held-out. Every family is guaranteed at least one trace on each side. Held-out traces are never used to choose detector parameters.

## Attack dimensions

- **Speed:** slow (8 s gaps), medium (1.5 s), fast (180 ms).
- **Principals:** 1, 2, 4, 8.
- **Method:** AES overwrite, `.locked` rename + delete, delete-then-rewrite, SSE-C copy, external-KMS copy.
- **Recon:** naive (touches decoys) or canary-aware (avoids every decoy).
- **Sabotage:** none, suspend versioning, purge versions, 1-day lifecycle.
- **Channel:** API or sync-client.

Each trace has an explicit `attackStartMs`, attacker principals, per-event attack flags, per-event file ids, and the set of real files the attack would destroy. These live in a separate `GroundTruth` object that is never passed to a detector.

## Tuning

Baselines are tuned on the 30% tuning split. D9 uses the shipped `data/policies.yaml` unchanged. For each baseline the grid is searched and the point selected by:

1. highest detection rate subject to `FPR ≤ max(1%, D9's tuning FPR)`;
2. then lowest FPR;
3. then lowest median time to detect.

If no grid point meets the budget, the lowest-FPR point is selected and the miss is recorded in `tuning.json`. The full grid and selected point are stored, so a reader can see whether a baseline was handicapped.

## Scoring

For each trace and detector:

- **Detected:** at least one alert at or after `attackStartMs`.
- **Time to detect (TTD):** first such alert − `attackStartMs`.
- **Time to contain (TTC):** TTD + containment latency `L`. `L` comes from the live validation MTTC median when available, otherwise a fixed 1000 ms default. The source is printed in the scorecard.
- **Files lost:** distinct real files touched by labelled attack events at or before the block time. The same file touched twice counts once.
- **False positive:** any alert on a benign trace, or any alert before `attackStartMs` or from a non-attacker principal on an attack trace.
- **Recoverable:** whether the detector has a recovery mechanism (D1 snapshot, D9 vault, D0 versioning), not whether a specific restore was executed.

The containment model is deliberately simple and identical across arms: detection at time `t` blocks attacker events after `t + L`. It is not a network round-trip measurement.

## Statistics

- 95% Wilson score intervals for detection and false-positive proportions.
- Median and p95 for time to detect.
- Exact two-sided McNemar test for paired detection decisions vs D9.
- Paired bootstrap (2,000 resamples, fixed seed) for the median files-lost difference vs D9.
- Rule of three is used when reporting zero observed events.

All intervals are computed in `eval/stats.ts` and covered by hand-checked unit tests.

## Determinism

The generator, tuning, detector runs, bootstrap, and hashing use seeded PRNGs. No `Math.random` is used in generation or scoring. D9's risk decay reads `Date.now()`; the adapter overrides it with a virtual clock during synchronous ingest so replay is stable.

`npm run eval:check` runs the fast evaluation twice from a clean state and compares the determinism hash. The stored full run's hash is in `determinism.json`.

## Safety

`npm run eval` refuses to run when `DEMO_LOCK=1`, an incident is open in the live ledger, or a local server reports an active simulator. Live validation and verification start a throwaway product server from a temp working directory with a fresh `data/` folder, so the repository's live state is never read or written.
