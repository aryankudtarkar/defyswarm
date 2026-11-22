# Detectors and baselines

All baselines are our own reference implementations in `eval/detectors/baselines.ts`. They model the *shape* of a common approach, not a specific vendor's product. No vendor was involved and no vendor claim is made.

## D0 — Versioning only

- **Models:** S3 versioning with no detection or automated response.
- **Alerts:** none.
- **Recovery:** versioning, if the attacker did not suspend versioning or purge versions. Recovery-point loss 0 ms when intact.
- **What it tests:** whether versioning alone survives the attack.

## D1 — Snapshot / backup only

- **Models:** scheduled backup every N hours and restore from the last snapshot.
- **Alerts:** none.
- **Recovery:** always capable; recovery-point loss = time since the last snapshot boundary.
- **Tuning grid:** 0.25, 1, 4, 12, 24 hours.

## D2 — Per-principal behavioural anomaly

- **Models:** cloud-native S3 threat detection with a per-principal baseline (GuardDuty S3 Protection shape).
- **Signals:** entropy-delta z-score and write-rate z-score against the principal's own history, falling back to a global baseline when history is short.
- **Tuning grid:** z ∈ {3, 3.5, 4}, min history ∈ {5, 10}, window 15 s, min entropy delta ∈ {1.0, 1.5}, min rate ∈ {25, 50}, allowlist.
- **Known weakness:** a principal with no history is hard to score; a slow swarm that stays under each principal's own baseline is invisible.

## D3 — Per-principal batch rate rule

- **Models:** a log/SIEM alarm evaluated in 1, 5, or 15 minute batches by a human analyst.
- **Signals:** per-principal suspicious-write count or total-write count within a batch.
- **Tuning grid:** batch ∈ {1, 5, 15} min, suspicious threshold ∈ {3, 5, 10, 20}, write threshold ∈ {100, 500, 2000}, allowlist.
- **Known weakness:** alerts arrive at the end of the batch, so fast attacks finish first.

## D4 — Upload malware / signature scan

- **Models:** upload malware scanning such as Microsoft Defender for Storage.
- **Signals:** magic-byte destruction, or high entropy on a `.locked` artifact.
- **Tuning grid:** entropy threshold ∈ {7.0, 7.5, 7.8, 7.9, 7.95}.
- **Known weakness:** cannot see delete/rewrite attacks that keep the header valid; sees only the upload path it is wired to.

## D5 — Sync-client ransomware heuristic

- **Models:** endpoint sync clients such as Google Drive for desktop or OneDrive.
- **Signals:** suspicious overwrite observed on the `sync` channel only.
- **Tuning grid:** entropy delta ∈ {0.5, 1.0, 1.5, 2.0}.
- **Threat-model note:** D5 cannot see direct API-key attacks by construction. A low detection rate here is a visibility difference, not a product failure.

## D6 — Extension and ransom-note blacklist

- **Models:** file screening and antivirus signature blacklists.
- **Signals:** `.locked` / `.encrypted` / `.crypt` / `.enc` extensions and ransom-note filenames.
- **Tuning grid:** extension sets of size 1, 2, 4.
- **Known weakness:** any attack method that does not rename is invisible.

## D7 — Naive fixed-name canary

- **Models:** obvious canary-token tripwires (`_DO_NOT_DELETE_CANARY.txt`, etc.).
- **Signals:** a read, write, or delete on a fixed obvious canary key.
- **Tuning grid:** fixed name list plus allowlist.
- **Known weakness:** a canary-aware attacker simply avoids the names.

## D8 — Entropy-only threshold

- **Models:** a naive "high entropy means encrypted" rule.
- **Signals:** write entropy ≥ threshold.
- **Tuning grid:** 7.0, 7.2, 7.4, 7.6, 7.8, 7.9, 7.95.
- **Known weakness:** benign compressed media is high entropy; SSE-C and external-KMS copies keep the original bytes.

## D9 — Shipped DefySwarm

- **Models:** the product itself.
- **Implementation:** imports `DetectionEngine` and `LocalObjectStoreAdapter` read-only, creates a fresh in-memory pair per trace, registers the trace's principals, installs the ten adaptive canaries, and ingests every event with a virtual clock. The live singleton, ledger, and `data/` are never touched.
- **Policy:** shipped `data/policies.yaml`, unchanged. `mode` is forced to `active` so the benchmark measures enforcement.
- **Recovery:** isolated WORM vault; recovery-point loss is the product's measured replication lag (42 ms midpoint).

## D9 ablations

| Arm | Component removed | How it is emulated |
| :--- | :--- | :--- |
| D9a | Adaptive canaries | No canaries installed; `isCanary` forced false |
| D9b | Control-plane sabotage triggers | Only `canary_write` remains in `hard_triggers` |
| D9c | Entropy + magic signals | `entropy`/`prevEntropy` cleared; `magicValid` forced true |
| D9d | Cross-principal swarm correlation | Swarm min principals set to 99 and flagged writes to 9999 |
| D9e | Canary-read / honey-credential escalation | Watchlist threshold raised to 200; canary reads not marked |
| D9f | Vault recovery | Detection unchanged; recovery reports not capable |

Some components cannot be switched off cleanly through `policies.yaml` alone. D9c and D9e are therefore emulated at the event boundary, and D9d through policy thresholds. This is documented rather than hidden: the ablation answers "what if this signal were absent?" not "what does the production switch do?".

## Interpreting the ablations

The stored full run shows:

- Removing entropy/magic (D9c) drops detection to 71.4%. Those signals are load-bearing.
- Removing canaries (D9a), control-plane triggers (D9b), swarm correlation (D9d), or honey-credential escalation (D9e) does **not** drop detection in this trace set. Those ablations are null here. The scorecard reports the null result instead of inventing a contribution.
- Removing vault (D9f) leaves detection at 100% and recoverability at 0%. Recovery is a separate axis from detection.
