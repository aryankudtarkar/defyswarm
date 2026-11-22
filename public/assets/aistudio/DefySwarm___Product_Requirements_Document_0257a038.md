# DefySwarm — Product Requirements Document

Nov 21, 2026 · @Aryan

## 1. Overview

DefySwarm stops ransomware on cloud object storage in seconds: it detects encryption and version-history sabotage, revokes every compromised credential, and restores clean files in one click from an immutable vault. It is built for MindSprint 2026, problem CYB-03, and every claim it makes is a measured number.

**The problem.** Stolen API keys, OAuth tokens and compromised service accounts let attackers suspend versioning, purge old versions and encrypt thousands of files overnight. AI agent swarms make this harder to catch: they recognise obvious decoys, spread work across many credentials, and use native cloud encryption instead of noisy uploads.

**The product** works in four steps, all run from one web console:

1. **Harden.** Audit each bucket for versioning, vault isolation and live canaries.
2. **Detect.** Score data-plane and control-plane events and correlate them across every principal in a bucket.
3. **Contain.** Revoke keys and attach a deny-all quarantine to every correlated identity.
4. **Recover.** Roll back to the last clean version, verified against a hash manifest.

**Who uses it.** Security on-call (respond and restore), security leads (posture and reports), and judges (run the simulator and read the measured results).

**Success means** the following, with exact targets in section 12:

- a standard attack is stopped with at least 90% of files preserved
- zero false alarms across the benign scenarios
- 100% of restored files match their pre-attack hashes

## 2. Threat model

DefySwarm assumes the attacker already holds valid storage credentials and uses AI agents, so fixed thresholds and obvious decoys fail. Each of four tactics has a specific counter.

| # | Tactic | What the attacker does | DefySwarm counter |
| --- | --- | --- | --- |
| 1 | Semantic canary evasion | Agents read filenames, metadata and content, then skip traps such as `000_passwords_canary.xlsx` or zero-byte files. | Context-matched canaries that copy the tenant's naming, folder depth, size and content, refreshed on a schedule (section 6). An LLM classifier tests them. |
| 2 | Distributed low-and-slow swarm | Work is spread across many stolen keys, rotating IPs and staggered timing to stay under per-user limits. | Bucket-wide correlation across all principals, not per user (section 5). |
| 3 | Pre-encryption recovery sabotage | Suspends versioning, sets expiry to one day, purges versions, or tampers with audit logs and Object Lock before encrypting. | Hard P0 trigger on any such call, plus an immutable vault that production credentials cannot change (section 7). |
| 4 | Native cloud crypto-abuse | Locks data in place with `CopyObject` using SSE-C or attacker-controlled KMS keys, so no high-entropy upload crosses the wire. | Detect SSE-C headers and untrusted KMS key ARNs on copy and multipart calls (section 5). |

Rule engines such as Cloud Custodian enforce configuration policy event by event. DefySwarm adds rate-based, cross-principal detection and data recovery on top of that kind of posture checking.

## 3. Scope and priorities

The hackathon MVP runs on MinIO behind a storage-adapter interface; AWS S3, Google Drive, SharePoint and Azure Blob are production adapters on the roadmap. Measured results are reported per adapter, and MinIO figures are never claimed for AWS.

| Capability | Phase 1: hackathon MVP | Phase 2: production |
| --- | --- | --- |
| Storage target | Local MinIO with versioning and a separate WORM vault bucket | AWS S3 first, then Google Drive, SharePoint/OneDrive, Azure Blob |
| Event ingestion | MinIO bucket notifications (data plane) and audit webhook (control plane) | S3 Event Notifications via EventBridge/SQS, CloudTrail, Google Drive Audit API, Microsoft Graph webhooks |
| Policy and alerts | `policies.yaml`, web console live feed, webhook JSON, forensic JSON export | Multi-account policy fleet; Slack, PagerDuty, SIEM (Splunk, Sentinel) |
| Containment | MinIO admin user disable and a deny-all quarantine policy | AWS IAM `UpdateAccessKey`, deny-all session policy, OAuth and STS token revocation |

| Priority | What must work |
| --- | --- |
| P0: demo must work | Simulator, canary trip, versioning-sabotage trigger, key revocation, vault restore, web console with live attack timeline |
| P1: the scoreboard | Entropy and magic-byte detection, rename/delete burst window, SSE-C detection, cross-principal swarm correlation, dry-run mode, benchmark harness with the Analytics page, benign scenarios |
| P2: if time | LLM-generated canaries and the classifier test, AWS S3 adapter |

## 4. System architecture

DefySwarm's detection, containment and vault sit outside the monitored tenant, so an attacker with full storage admin rights cannot switch them off.

&#91;embedded content: architecture · tenant, control plane, vault and console\]

Events flow from the tenant into the out-of-band control plane. The engine scores them, containment revokes credentials, and restore reads clean versions from the vault and writes them back to the buckets. Replication, canary refresh and rollback run under a service principal that the watcher ignores.

## 5. Detection engine

Detection combines two event streams and four independent signals into one risk score per bucket and per principal. Revocation needs either a hard trigger or corroborating signals.

**Ingestion**

- **Data plane** (target: under one second after the storage server emits the event): `PutObject`, `CopyObject`, `CompleteMultipartUpload`, `DeleteObject` and `GetObject`.
- **Control plane** (near real time): audit events for versioning, lifecycle, Object Lock, logging and IAM changes. The MVP uses the MinIO audit webhook. On AWS this is CloudTrail, which can lag by minutes, so control-plane triggers are always paired with data-plane signals.

**Signals**

| Signal | What it checks | How it avoids false alarms |
| --- | --- | --- |
| Entropy and magic bytes | Samples the first 64 KB of each written object, validates its magic header (`%PDF`, `PK\x03\x04`, `FF D8 FF`, `89 50 4E 47`) and measures the entropy change ΔH against the previous clean version. | Flags a lost header or an entropy jump against the file's own history. New objects with a valid header are not flagged for high entropy alone, so bulk uploads of compressed files stay green. |
| Rename and delete-rewrite burst | Counts paired `DeleteObject` + suspicious `PutObject` (for example `file.pdf` deleted and `file.pdf.locked` created) and in-place overwrites in a 10-second sliding window. | Needs a burst above the configured pair count, not a single rename. |
| Native crypto-abuse | `CopyObject` or `CompleteMultipartUpload` carrying SSE-C headers or a KMS key ARN that is not on the allowlist. | Allowlisted keys and principals are ignored. |
| Canary and sabotage events | Any touch on a canary, and any call that changes versioning, lifecycle, Object Lock or logging (sections 6 and 7). | These calls are rare in normal operation, so they are hard triggers. |

```latex
H = -\sum_{i=0}^{255} p_i \log_2 p_i, \qquad \Delta H = H_{new} - H_{prev}
```

**Cross-principal swarm correlation.** For each bucket, the engine keeps 10-second and 60-second windows of flagged writes, renames and deletes, plus the count of distinct principals contributing. A swarm alert fires when the bucket-wide flagged rate crosses the threshold even though each principal stays under its own, and at least two distinct principals contribute in the same window. Every contributing principal is contained together. In the MVP the threshold is configured; in production it is learned from each bucket's own baseline.

**Risk score.** Scores are kept per principal and per bucket and decay over time. A canary read adds 45 (watchlist, P1). A canary modification, SSE-C copy, rename or delete, or any version-sabotage call, adds 100 (P0 containment). Other signals add smaller, configurable weights in `policies.yaml`; the starting defaults are tuned using the benchmark harness.

## 6. Adaptive canaries

Canaries are decoy files built to look like real business documents, so an agent that skips obvious traps still trips one.

- **Generation.** DefySwarm learns the bucket's conventions (naming patterns, folder depth, size distribution, file types) and generates plausible synthetic content, for example `finance/2026/Q3_vendor_reconciliation.xlsx`. No real data is used.
- **Refresh.** Names, locations and content rotate on a schedule so the pattern never settles. Refresh jobs run from the out-of-band service principal and are excluded from alerts (self-loop protection).
- **Placement.** Canaries are spread across folder depths and weighted toward prefixes tagged `sensitivity=critical`.
- **Allowlist.** Backup, DLP, antivirus and search-indexing principals are allowlisted by identity. Their canary reads are logged but not scored. A canary touch from any other principal always scores. Legitimate scanners are the largest expected source of false alarms, so this list is part of onboarding.

| Canary event | Response | Risk score |
| --- | --- | --- |
| Read (`GetObject`) | P1 watchlist escalation | +45 |
| Modify, overwrite, SSE-C copy, rename or delete | P0 automatic containment | +100 |

**Testing the claim.** An LLM is given a balanced mix of canary and real files and asked to label each one. DefySwarm reports the labelling accuracy on the Canaries page; the goal is accuracy close to chance (50%).

## 7. Version protection and the immutable vault

Version history is protected two ways: sabotage calls trip an instant P0, and clean versions are copied to a vault that production credentials cannot change.

**Sabotage triggers (instant P0).** Any call that does one of the following revokes credentials immediately:

- suspends versioning (`PutBucketVersioning: Suspended`)
- permanently deletes versions (`DeleteObjectVersion`, or `DeleteObjects` with a `VersionId`)
- sets lifecycle expiry of one day or less
- alters audit logging or Object Lock retention

**Vault**

- A separate, security-owned bucket (a separate account or project in production) with Object Lock. Production uses compliance mode; simulation uses governance mode with a short retention so test data can be cleaned up.
- Production credentials, including storage admins, have no delete, overwrite or retention-shortening permission on the vault.
- Delete markers are not replicated.
- **Replication-poisoning guard.** During an active incident, replication pauses for flagged writes, so attacker-written versions never replace clean snapshots.

**Clean-version manifest.** When a version is replicated, DefySwarm records its key, version ID, SHA-256, entropy, magic-header validity and timestamp. A version counts as clean only if it was written before the incident timestamp, passed the entropy and header checks at replication time, and its hash matches the manifest. Restore picks the latest clean version of each object.

**Recovery point.** Replication lag is measured and shown on the Canaries and Vault page. Each restore report states, per object, the gap between its last clean version and the incident, so the data-loss window is explicit.

## 8. Containment and one-click restore

On a P0 trigger or a swarm alert, DefySwarm cuts access first, and only human administrators get an approval gate.

| Principal type | Action | Approval |
| --- | --- | --- |
| Service accounts and access keys | Disable the key (MinIO admin user disable; AWS `UpdateAccessKey: Inactive`) and revoke active sessions | None |
| Assumed roles and swarm principals | Attach a deny-all quarantine policy to every correlated identity, scoped to the session | None |
| Human admin accounts | Quarantine policy plus an approval prompt in the console | None if a hard trigger fired or two or more signals agree; otherwise the on-call approves |

In the MVP the quarantine is a deny-all policy attached to the MinIO user; in production it is an inline deny-all session policy. Buckets tagged `sensitivity=critical` auto-revoke; buckets tagged `sensitivity=sandbox` alert only. Containment time is measured to the attacker's first confirmed `403`, not to the API call returning, because key changes can take a moment to propagate.

**One-click restore** uses the incident ledger and the timestamp of the first malicious event or canary trip:

1. Confirm every swarm principal is contained and hold replication.
2. Remove attacker artifacts: encrypted versions, `.locked` files and delete markers.
3. Promote the latest clean version of each object to `IsLatest`, or copy it back from the vault.
4. Verify each restored file's SHA-256 against the manifest, then report files restored, files unrecoverable and the data-loss window.

**Self-loop protection.** The watcher ignores events from its own out-of-band service principal, so rollback and canary refresh never re-trigger alerts.

## 9. Web console

DefySwarm ships a dark-mode web console where an operator sets the product up, triggers safe tests, watches an attack live, reads the analytics and restores data, without touching the command line. The backend exposes a REST API and a WebSocket stream (`/ws/live`); the front-end framework is an implementation choice.

| Page | Purpose | What it shows and controls |
| --- | --- | --- |
| Live War Room | Watch an attack and respond | Live activity feed (API event, principal, entropy score, magic-byte status); entropy time-series with threshold markers; risk-score gauge; credential panel with ACTIVE and REVOKED badges; cross-principal swarm alerts; attack timeline with MTTD, MTTC, files protected versus impacted |
| Setup | Onboard and configure | Connect storage (endpoint, monitor and vault credentials); register buckets with a sensitivity tag; Auto-Harden checks for versioning, vault and canaries with pass or fail; allowlist editor for CI/CD, backup and DLP principals; `policies.yaml` editor with validation; Dry-Run / Active toggle; alert destinations (webhook, Slack) |
| Simulator | Trigger safe tests | Run any of the four scenarios; blast-radius lock status (target bucket must carry `env=ransomware-sim-only`); live pass or fail for each assertion; Reset Demo |
| Analytics | Prove it works | Benchmark runs: MTTD and MTTC median and p95, files lost, restore accuracy, false-positive rate; detections by signal; run-to-run comparison; export as JSON |
| Incidents | Review and restore | Incident list; per-incident timeline, affected files, principals and risk-score history; 1-Click Restore with a preview of what will change; approve or deny human-admin quarantine; Export Forensic Report (JSON) |
| Canaries and Vault | Inspect the defences | Canary inventory (location, age, last refresh, trips) with Refresh Now; vault retention mode, replication lag and last verification; canary classifier accuracy |
| Usage and Health | Operate the product | Events ingested per minute and ingestion latency; monitored buckets and objects; active canaries; vault size; engine, API and alert-delivery health; audit log of operator actions |

**Behaviour**

- The live feed and gauges update from the WebSocket within one second of an engine event.
- Console state is rebuilt from the incident ledger, so a page refresh loses nothing.
- Roles: viewer (read), operator (trigger, approve, restore) and admin (setup, policy). Every operator action is written to the audit log.
- Destructive actions (Restore, Reset Demo, switching to Active mode) ask for confirmation.
- If ingestion stops or the event stream has a gap, the Health page and War Room show a degraded banner and an alert fires.

## 10. Policy as code

Every threshold, canary setting, allowlist, response tier and action lives in a version-controlled `policies.yaml`, not in code, and the Setup page edits and validates the same file. The values below are starting examples, to be tuned with the benchmark harness.

```yaml
version: 1
mode: active                # active | dry-run
buckets:
  - name: finance-prod
    tags: { sensitivity: critical }
    vault: vault-finance
tiers:
  critical: { response: auto-revoke }
  sandbox:  { response: alert-only }
allowlist:
  principals: [ci-deployer, backup-agent, dlp-scanner]
  kms_keys:   [trusted-kms-key-id]
detection:
  entropy: { sample_bytes: 65536, delta_threshold: 1.5 }
  burst:   { window_seconds: 10, pairs: 5 }
  swarm:   { window_seconds: 60, min_principals: 2, flagged_writes: 20 }
  score:   { watchlist: 45, contain: 100 }
canary:
  count: 20
  refresh_hours: 24
hard_triggers:
  - canary_write
  - versioning_suspend
  - version_purge
  - lifecycle_expiry_1d_or_less
  - object_lock_tamper
actions:
  on_p0: [disable_key, attach_deny_all, alert, pause_replication]
```

The loader rejects unknown keys. In dry-run mode the engine logs every action it would take and takes none.

## 11. Simulation and benchmark harness

A safe simulator drives four scenarios, and the benchmark harness repeats each at least 30 times, so every reported number is a median and a worst case rather than a single lucky run.

**Blast-radius lock.** The simulator refuses to run unless the target bucket carries the tag `env=ransomware-sim-only`. It runs from the Simulator page or the command line.

| # | Scenario | What it does | Pass criteria |
| --- | --- | --- | --- |
| 1 | Benign bulk upload | Uploads 50 realistic `.pdf`, `.jpg`, `.docx`, `.csv` and `.txt` files. Stretch variants: a 5,000-file upload, a bulk rename, a folder of already-compressed files, a backup sync. | Zero alerts; risk score stays green |
| 2 | Standard ransomware | Attempts version sabotage, then runs paced AES-256 encryption with rename and delete. | Attack detected and alerted; attacker key returns `403` mid-attack; at least 90% of files preserved |
| 3 | Stealth AI swarm | Skips canaries and splits slow encryption and SSE-C copies across several keys. | Cross-principal plus entropy and magic-byte detection revokes every swarm key |
| 4 | Recovery verification | Runs one-click restore after scenarios 2 and 3. | 100% of restored files match their pre-attack SHA-256 baselines |

**Captured on every run:** time to detect, time to contain, files encrypted before containment, time to restore, restore accuracy, and alerts raised in benign runs. Results appear on the Analytics page and export as JSON.

**Honest reporting.** Runs where the swarm evades or detection is late are reported, not dropped, together with which signal eventually caught them. The canary classifier test (section 6) runs as a separate script.

## 12. Targets and measured results

These are targets for the benchmark. DefySwarm reports the measured median and p95 over at least 30 runs per scenario, and never presents a target as a result.

| Metric | Definition | Target |
| --- | --- | --- |
| MTTD (mean time to detect) | From the first malicious request reaching storage (server timestamp) to the alert firing | Under 5 s |
| MTTC (mean time to contain) | From the trigger to the attacker's next request returning `403` | Under 10 s |
| Files preserved, standard attack | Share of files not encrypted when containment completes | At least 90% |
| False alarms | Benign runs flagged divided by total benign runs | 0 across the benign scenarios |
| Restore accuracy | Restored files byte-identical (SHA-256) to the pre-attack baseline | 100% |
| Time to restore | From the Restore click to all files verified | Reported, no target |
| Replication lag | Delay before a clean version reaches the vault (the recovery point) | Reported, no target |
| Canary classifier accuracy | LLM labelling of canary versus real files | Close to chance (50%) |

All MVP figures are measured on MinIO. On AWS, CloudTrail control-plane events can arrive minutes after the call, so AWS latencies are measured and reported separately when that adapter ships.

## 13. Non-functional requirements and guardrails

The product must be safe to run, safe to test and hard for an attacker to switch off.

- **Out-of-band control plane.** The detection engine, containment responder, policy store and vault credentials run outside the monitored tenant's blast radius, so an attacker with full storage admin rights cannot disable them. In production, protect the audit trail with an organisation-level trail and service control policies.
- **Dry-run (shadow) mode.** First-class during onboarding: the engine logs the actions it would take and takes none.
- **Allowlists.** Verified CI/CD and backup principals are allowlisted by identity, never by name pattern.
- **Tiered response.** Response depends on the bucket's sensitivity tag, and human admins follow the approval rules in section 8.
- **Self-loop protection.** The watcher ignores events from its own service principal (section 8).
- **Simulator lock.** The simulator only runs against buckets tagged `env=ransomware-sim-only` (section 11).
- **Console security.** Login with viewer, operator and admin roles; every operator action goes to an audit log; secrets live in a secrets store, never in `policies.yaml`; monitor and vault credentials are separate.
- **Privacy.** The engine reads only the first 64 KB of an object, in memory, to compute entropy and check headers. Object content is not stored.
- **Reproducible demo.** One command starts MinIO, the vault, the engine and the console with demo data, and Reset Demo returns it to a clean state.

## 14. Risks and attacker-versus-product cases

The biggest risks are an attacker blinding the product, canaries becoming recognisable, and legitimate tools causing false alarms.

| Risk or attacker move | Impact | Mitigation |
| --- | --- | --- |
| Attacker disables the event feed (EventBridge rule, CloudTrail, MinIO notification config) | Detection goes blind | Feed and engine live in the out-of-band account; heartbeat and stream-gap alarm; organisation-level trail and service control policies in production |
| Attacker reaches the vault credentials | Backups at risk | Vault credentials never exist in the monitored tenant; Object Lock blocks delete and overwrite even with valid credentials |
| Canary refresh leaks the naming pattern | Canaries become recognisable | Rotate names, depth and content; no fixed prefixes; classifier test (section 6) |
| Legitimate scanner touches a canary | False alarm | Identity allowlist; allowlisted reads are logged but not scored |
| A single signal locks out a human admin | Outage | Tiered response; approval prompt unless a hard trigger or two or more signals agree |
| Slow attack stays under every threshold | Missed attack | Bucket-wide windows, canaries and sabotage triggers together; evading runs are reported honestly in the benchmark |
| CloudTrail lag on AWS | Sabotage detected late | Pair control-plane triggers with data-plane signals; report AWS latency separately |
| Replication lag | Gap between last clean copy and incident | Measure it; state the gap in every restore report |
| Poisoned version reaches the vault | Bad restore | Manifest check; replication pause during an incident |
| Demo fails live | Lost pitch | One-command stack, Reset Demo, and a recorded fallback run |

**Open items to verify early.** Whether MinIO's notification payload exposes SSE-C headers (SSE-C also requires TLS on MinIO); if not, detect it from the audit log. Whether MinIO's audit webhook covers every bucket-configuration call listed in section 7.

## 15. Build plan and demo

Build the benchmark harness early, because the pitch depends on the numbers it produces. Build in this order:

1. MinIO, vault bucket and versioning in one compose file, plus the simulator with its blast-radius lock.
2. Event ingestion (notifications and audit webhook) and the incident ledger.
3. Hard triggers end to end: canary trip and versioning sabotage lead to key revocation. This completes P0 detection and containment.
4. Vault replication, the manifest and one-click restore.
5. Web console: War Room feed and timeline first, then Setup, Simulator and Incidents.
6. P1 signals: entropy and magic bytes, burst window, SSE-C detection, swarm correlation, dry-run mode.
7. Benchmark harness and the Analytics page.
8. P2: canary generator and classifier test, AWS S3 adapter.

**Live demo flow**

1. Setup page: run Auto-Harden and show every check passing.
2. Simulator: run the benign bulk upload and show the risk score staying green.
3. Run the standard attack: the timeline lights up, the key is revoked, and the KPIs show MTTD, MTTC and files preserved.
4. Run the stealth swarm: every swarm key is revoked.
5. Incidents page: click 1-Click Restore and show the hashes matching.
6. Analytics page: show the scoreboard from the 30-run benchmark.

## 16. Production roadmap

After the hackathon, DefySwarm moves from a MinIO MVP to a multi-cloud product, starting with AWS S3.

1. **AWS S3 adapter.** S3 Event Notifications through EventBridge and SQS, CloudTrail for control-plane events, IAM key disable and deny-all session policies, Object Lock in compliance mode, and KMS and SSE-C detection. AWS latencies are benchmarked and published separately.
2. **More storage targets.** Google Drive (Audit API), SharePoint and OneDrive (Microsoft Graph webhooks), and Azure Blob.
3. **Fleet operation.** Multi-account policy management, per-bucket learned baselines for swarm correlation, and OAuth and STS token revocation.
4. **Integrations.** Slack, PagerDuty and SIEM export (Splunk, Sentinel), and a hosted multi-tenant console.

Cloud Custodian and similar governance tools remain complementary: they check posture (versioning on, Object Lock on, trail enabled) while DefySwarm handles the live attack.
