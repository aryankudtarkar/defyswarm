# Limitations

The lab is designed to make its own limits legible. Read this before quoting any number.

## The traces are synthetic

Every replay trace comes from the seeded generator in `eval/generator`. The distributions are documented and deterministic, but they are not production telemetry. No customer data, no real S3 bucket, and no production workload was used.

`eval-data/calibration.json` states whether the generator was fitted to recordings. If `recordings` is 0, the scorecard is labelled synthetic. Recorded traces, when present, come from the local simulator, not from production.

## Baselines are reference implementations

D0–D8 are our own implementations of the shape of common approaches. They are not vendor products, were not supplied by any vendor, and do not represent any vendor's tuned configuration. A baseline losing here means "this reference approach, tuned on these traces, lost". It does not mean a specific commercial product would lose.

## D9 is the shipped engine, but not the whole product

D9 imports `server/detectionEngine.ts` and `server/storageAdapter.ts` and runs them with a fresh in-memory store. It does not exercise the HTTP layer, the WebSocket fan-out, alert delivery, the Groq classifier, or an external S3 provider. A detection result is a statement about the engine and store, not about end-to-end deployment behavior.

## The containment model is a simplification

The scorer blocks attacker events after `detection + L`. `L` is the live validation MTTC median when available, otherwise a fixed 1000 ms. It is a post-detection latency, not a network round-trip or IAM propagation measurement. Real containment may be slower or faster, and a failed containment call is not modelled.

Files lost counts distinct real files touched by labelled attack events before the block. It does not model partial writes, overwrite-in-place semantics, or attacker retries after a 403.

## Ablations are partly emulated

`policies.yaml` cannot switch off every component independently. D9c (entropy/magic) and D9e (canary-read escalation) are emulated at the event boundary; D9d is emulated through policy thresholds. The ablations answer "what if this signal were absent?", not "what does the production toggle do?". See [`BASELINES.md`](./BASELINES.md).

Several ablations are null in the stored run: removing canaries, control-plane triggers, swarm correlation, or honey-credential escalation did not lower detection on this trace set. That is reported as a null result, not spun as a contribution.

## Sample size

The full held-out set is 162 traces (112 attack, 50 benign). A 0% false-positive rate on 162 traces has a 95% upper bound of about 2.3%, not 0%. A 100% detection rate on 112 attack traces has a lower bound of about 96.7%. Small family subsets (for example 8 principals) are smaller still; their intervals are wide and shown in the scorecard.

## Live validation is simulator validation

Live validation runs the shipped simulator on a throwaway local server. It measures the product's own scenarios, not a customer environment. The 2-principal swarm is driven through the public storage API because the simulator only emits a 4-principal swarm. The two paths are reported separately.

The live stream does not carry a scenario tag, version id, size, or source address, so recorded labels come from CLI metadata. See [`TRACE_PROTOCOL.md`](./TRACE_PROTOCOL.md).

## Recovery is not durability

The recovery scenario checks SHA-256 parity after a local restore. It does not prove that an external WORM vault survives host loss, provider outage, credential compromise, or a free-tier host that sleeps and loses data. No external Backblaze B2 or MinIO Object Lock bucket was exercised.

Supabase Storage S3 does not provide the S3 Object Lock and versioning semantics the vault relies on. It can be a monitored source, not a vault or version-restore target.

## Security claims are out of scope

The `x-defyswarm-role` header is a client-supplied demo role switch. It is not authentication. The audit log is an append-only local JSON ledger, not tamper-evident storage. The lab did not test authentication, authorization, tenancy isolation, or penetration resistance.

## What the lab does not measure

- Application data-path latency ("zero-latency")
- 64 KB range-sampling behavior against a real S3 endpoint
- Groq classifier accuracy or adversarial robustness
- Alert delivery through ntfy/Discord/Slack
- Multi-tenant isolation
- Cost or throughput at production scale
- Recovery from a real provider outage

Those claims stay unverified in [`CLAIMS.md`](./CLAIMS.md).
