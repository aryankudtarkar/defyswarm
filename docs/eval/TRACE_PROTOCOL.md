# Trace protocol

## Separation of telemetry and labels

A trace is two objects:

- `events: Event[]` — what a detector may read. There is no attack label, no ground-truth file list, and no scenario parameter block on an event.
- `groundTruth: GroundTruth` — what the scorer reads. It is never passed to a detector.

The runner calls `detector.run({ events, params, seed, bucket })`. The unit test `tests/isolation.test.ts` asserts that the context contains no ground-truth fields and that events carry no `attack` or `fileId` fields.

## Event schema

| Field | Meaning |
| :--- | :--- |
| `seq` | Monotonic index within the trace |
| `timeMs` | Milliseconds since trace start |
| `principal` | Identity that issued the operation |
| `operation` | `PutObject`, `CopyObject`, `GetObject`, `DeleteObject`, `DeleteObjectVersion`, `PutBucketVersioning`, `PutBucketLifecycleConfiguration`, `PutObjectLockConfiguration`, `PutBucketLogging` |
| `plane` | `data` or `control` |
| `bucket`, `key`, `sourceKey`, `versionId` | Object address |
| `sizeBytes` | Object size when known |
| `entropy`, `prevEntropy` | Shannon entropy of the payload and the prior version |
| `magicValid`, `magicDetected` | Content-signature inspection |
| `sseAlgorithm`, `kmsKeyId` | Encryption context |
| `sourceAddress` | Optional source address |
| `channel` | `api`, `sync`, or `console` |
| `isCanary` | Whether the key is a deployed decoy |
| `versioningTargetStatus`, `lifecycleExpiryDays`, `versionIdPurged` | Control-plane fields |
| `httpStatus` | Response status |

`GroundTruth` carries the trace id, family, kind, seed, split, bucket, duration, attack start, attacker principals, per-event attack flags, per-event file ids, the set of real attack files, total real files, benign event count, scenario parameters, and the obvious/adaptive canary key lists.

## Generator

`eval/generator/generate.ts` is seeded. The same spec and calibration produce byte-identical traces.

- **Baseline object set:** 39 realistic finance/ops/legal/HR/product files with type-appropriate entropy and size.
- **Adaptive canaries:** ten realistic nested keys such as `finance/2026/Q3/vendor_reconciliation_ledger.xlsx`. None contains the word "canary".
- **Obvious canaries:** three tripwire names for D7.
- **Benign workloads:** bulk uploads, 5,000-file compressed media, rename/move, nightly backup, DLP scan, CI overwrite, photo import, archive extraction, compressed logs.
- **Attacks:** AES overwrite, `.locked` rename + delete, delete-then-rewrite, SSE-C copy, external-KMS copy; with optional recon, versioning suspension, version purge, or 1-day lifecycle.
- **Mixed:** attack events interleaved with benign background at 1:5, 1:20, and 1:100.

## Splits

`hashString(traceId) % 100 < 30` selects the tuning split. The held-out split is everything else. Every family is guaranteed at least one trace on each side. Tuning never reads held-out results.

## Stored format

`eval-data/traces/generated/<traceId>.jsonl`:

```
{"type":"meta","groundTruth":{...}}
{"type":"event","event":{...}}
{"type":"event","event":{...}}
```

`eval-data/traces/manifest.json` stores the generation seed, generator version, per-family counts, and a SHA-256 for every trace file. The runner hashes the manifest into the run id, so a changed trace set cannot silently reuse old results.

## Recorder and the live stream gap

`eval/recorder/recorder.ts` records telemetry from the shipped simulator over `/ws/live` and labels each run from CLI metadata (the scenario it just started). This is a workaround, not a clean design.

The live `TelemetryEvent` stream does **not** carry:

- a scenario tag
- an object version id
- object size
- source address

So a recorder cannot label attack windows or reconstruct file identity from the stream alone. The recorded traces are therefore useful for calibration and for live MTTC, not for ground-truth scoring.

### Smallest additive change to close the gap

Add four optional fields to `TelemetryEvent` and populate them where the server already has the values:

```ts
scenarioTag?: string;     // set by the simulator runner for the duration of a drill
versionId?: string;       // the storage adapter already returns it
sizeBytes?: number;       // the adapter already knows it
sourceAddress?: string;   // the request already carries it
```

This is additive, does not change detection logic, and would let a recorder label and replay a live run without CLI metadata. It was not implemented because product code is read-only in this work.

## Calibration

`eval/recorder/calibrate.ts` fits three knobs from recorded benign traces:

- `sizeScale` — median recorded size / baseline size for known keys
- `interArrivalScale` — median recorded gap / 500 ms
- `benignEntropyShift` — mean recorded entropy minus baseline entropy

With no recordings, the profile stays at defaults and both the scorecard and `eval-data/calibration.json` say so. Recorded traces come from the local simulator, not production telemetry: they calibrate shape, not realism.
