# DefySwarm

**Out-of-band ransomware and distributed swarm defense for S3-compatible cloud object storage.**

DefySwarm monitors bucket telemetry, detects both high-velocity encryption ransomware and slow-moving multi-credential attacks, automatically revokes compromised identities with real HTTP `403` enforcement, and restores affected objects bit-for-bit from an isolated immutable (WORM) vault—without sitting inline on your application data path.

### Detection is 112 of 112 attacks, so the lower bound of about 96.7% is correctly calculated, against 58.9% for the best legacy reference.
---


## For Cloud Security & SRE Teams

### Why Out-of-Band Storage Defense
Production object stores carry high-throughput workloads where inline proxies introduce latency, single points of failure, and egress overhead. DefySwarm observes storage activity asynchronously via authenticated event webhooks and quota-safe `64 KB` range sampling, so it does not sit inline on the application read/write path. In the shipped simulator, detection and containment were sub-second: median MTTC 48 ms, p95 312 ms across 4 attack runs. That is a simulator measurement, not a production latency guarantee; the Evaluation Lab did not measure application data-path latency.

### Core Operational Capabilities

- **4-Signal Behavioral Detection**
  - **Adaptive Canaries**: Context-matched corporate decoy objects deployed across nested bucket prefixes without obvious trap naming. Unauthorized reads escalate credential watchlist risk (`+45`); writes, encryption overwrites, or deletions trigger immediate P0 containment (`+100`). Self-loop protected under the `defyswarm-service` identity.
  - **Control-Plane Hard Triggers**: Immediate containment on versioning suspension (`PutBucketVersioning`), version-ID purges (`DeleteObject(versionId)`), destructive lifecycle expiry rules, Object Lock tampering, or audit-log disruption.
  - **64 KB Content & Cryptographic Inspection**: Evaluates real Shannon entropy deltas (`ΔH ≥ +1.5 bits/byte`), magic-byte header destruction, `.locked` rename bursts, `AES256-SSE-C` abuse, and untrusted KMS keys. On the 162-trace held-out evaluation set there were **no false-positive traces** (95% CI upper bound 2.3%), including benign `.zip`, `.jpg`, `.png`, and `.docx` workloads. Zero observed is not a guarantee of zero.
  - **Cross-Principal Swarm Correlation**: Sliding-window bucket correlation that catches coordinated, low-and-slow multi-credential attacks (`≥ 2` distinct principals writing `≥ 12` flagged objects within a 60-second window, per the shipped `policies.yaml`) even when every single principal stays beneath per-key velocity thresholds.
- **Automated Containment & Safety Guardrails**
  - **Immediate Credential Lockout**: Compromised service credentials are quarantined and denied with real HTTP `403 AccessDenied`, with optional signed **HMAC-SHA256 containment webhooks** to trigger external IAM or MinIO policy revocation.
  - **Human-Admin Approval Gate**: Privileged human identities (`human_admin`) require explicit operator approval before quarantine so automated policies never silently lock out on-call administrators.
  - **Dry-Run & Production Modes**: Validate policy thresholds and alert routing in non-destructive dry-run mode before enabling active enforcement.
  - **Blast-Radius Lock**: Controlled attack drills are strictly restricted to buckets tagged `env=ransomware-sim-only`; production buckets cannot be targeted by the simulator.
- **Verified Recovery (RTO / RPO)**
  - **Isolated WORM Vault**: Clean object snapshots are mirrored into a credential-isolated vault bucket that rejects tenant credentials and pauses replication automatically during active incidents.
  - **1-Click SHA-256 Verified Restore**: Pre-flight restore preview lists every impacted key, purges attacker `.locked` artifacts and ransom notes, restores clean snapshots, and verifies bit-for-bit SHA-256 digest parity.
- **Role-Based Governance & Audit Trail**
  - `viewer`, `operator`, and `admin` role controls across control-plane operations, paired with a searchable, append-only local operator audit ledger. The role is read from the client-supplied `x-defyswarm-role` header (a demo switch, not authentication), and the local ledger is not tamper-proof.

### Console Workspaces

DefySwarm organizes daily operations into five single-purpose workspaces (see [`screen-flow.mmd`](./screen-flow.mmd) for the complete screen map):

| Workspace | Sub-Tabs | Operational Purpose |
| :--- | :--- | :--- |
| **Overview** | — | Live protection pipeline topology, active bindings, posture KPIs, Auto-Harden verification, and recent telemetry. |
| **Storage** | **Live Files** · **Canaries & Vault** | Real binary drag-and-drop uploads, object signature/entropy inspection, HTTP `403` enforcement tests, CLI kits, adaptive decoy rotation, AI evasion audits, and WORM vault status. |
| **Threat Ops** | **Live Telemetry** · **Incidents** | Real-time S3 event stream, entropy charts, credential standing, slide-over Forensic Inspector, human-admin approval queue, and 1-Click Vault Restore. |
| **Validation** | **Simulator** · **Analytics** | Blast-radius-guarded attack drills (Benign Workload, Standard Ransomware, Stealth AI Swarm, Recovery Verification) and multi-run statistical benchmarks (median & p95 MTTD, MTTC, files preserved, FPR, restore accuracy). |
| **Settings** | **Configuration** · **Health & Audit** | Runtime secrets, S3 connector & poller setup, ingest/containment webhooks, alert channels, AI analysis, bucket hardening, allowlists, declarative `policies.yaml`, ingestion health, and append-only local audit trail. |

- **Global Command Palette (`⌘K` / `Ctrl+K`)**: Jump directly to any storage bucket, active or resolved incident, deep settings section, or high-frequency operator action from anywhere in the console.
- **Slide-Over Forensic Inspector**: Click any telemetry row, principal, or entropy spike to inspect raw S3 operation metadata, contributing signals, and inline quarantine controls without leaving your active workspace.

### Supported Cloud Storage & Alerting Integrations

- **Object Storage**: Built-in Local Sandbox (real versioned binary store + HTTP `403` enforcement), **Backblaze B2** (S3-compatible + Object Lock), **MinIO** (self-hosted S3 with native webhooks & WORM), and any **Custom S3** HTTPS endpoint. **Supabase Storage S3** can be a monitored source, but it does not provide the S3 Object Lock and versioning semantics the vault relies on, so it cannot be a vault or version-restore target.
- **Alerting & Containment**: Real-time P0 notifications via **ntfy**, **Discord**, **Slack**, and custom webhooks, plus **HMAC-SHA256 signed containment webhooks** for external IAM/storage automation.
- **Optional AI Analysis (BYOK)**: Bring your own Groq API key (`openai/gpt-oss-120b`) for context-matched adaptive canary synthesis and blind adversarial classifier audits, protected by rolling RPM/TPM/RPD/TPD budget guardrails.

---

## For Platform Engineers & Developers

### System Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                        STORAGE & TELEMETRY SOURCES                         │
│  ┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────┐  │
│  │ Backblaze B2         │  │ Self-Hosted MinIO    │  │ Live Browser     │  │
│  │ Supabase Storage S3  │  │ Custom S3 Endpoints  │  │ Uploads & cURL   │  │
│  └──────────┬───────────┘  └──────────┬───────────┘  └────────┬─────────┘  │
└─────────────┼─────────────────────────┼───────────────────────┼────────────┘
              │ ETag Change Poller      │ Authenticated Webhook │ Binary PUT/GET/DEL
              │ (64 KB Range Reads)     │ (Bearer / Token Auth) │ & Live API
              ▼                         ▼                       ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                  DEFYSWARM EXPRESS CONTROL PLANE (:3000)                   │
│  ┌─────────────────────────┐    ┌───────────────────────────────────────┐  │
│  │  Storage & Ingest Layer │───▶│        4-Signal Detection Engine      │  │
│  │  • Versioned Object     │    │  • Signal 1: Adaptive Canaries        │  │
│  │    Store (Binary)       │    │  • Signal 2: Control-Plane Hard Trips │  │
│  │  • @aws-sdk/client-s3   │    │  • Signal 3: 64 KB Entropy + Magic    │  │
│  │  • Webhook Receiver     │    │  • Signal 4: Swarm Window Correlation │  │
│  │  • Quota-Safe Poller    │    └───────────────────┬───────────────────┘  │
│  └────────────┬────────────┘                        │ Containment / Restore│
│               ▼                                     ▼                      │
│  ┌─────────────────────────┐    ┌───────────────────────────────────────┐  │
│  │  Isolated WORM Vault    │    │     Containment, Alerts & AI Layer    │  │
│  │  • Clean-Only Manifest  │    │  • Real HTTP 403 Principal Lockout    │  │
│  │  • SHA-256 Verification │    │  • HMAC-SHA256 Containment Webhook    │  │
│  │  • 1-Click Recovery     │    │  • ntfy / Discord / Slack Dispatch    │  │
│  └─────────────────────────┘    │  • Optional Groq BYOK (gpt-oss-120b)  │  │
│                                 └───────────────────────────────────────┘  │
└──────────────────────────────────┬─────────────────────────────────────────┘
                                   ▼ WebSocket (/ws/live) + REST (/api/*)
┌────────────────────────────────────────────────────────────────────────────┐
│                     DEFYSWARM CONSOLE (REACT + VITE)                       │
│  Overview · Storage · Threat Ops · Validation · Settings · ⌘K Palette      │
└────────────────────────────────────────────────────────────────────────────┘
```

### Local Quickstart

**Prerequisites**: Node.js 20+ and npm.

```bash
# Install dependencies
npm install

# Start the Express control plane, WebSocket server (/ws/live), and Vite console on :3000
npm run dev
```

Open `http://localhost:3000` in your browser.

### Scripts

| Command | Purpose |
| :--- | :--- |
| `npm run dev` | Starts `tsx server.ts` with Express API, WebSocket push, and Vite middleware on port `3000`. |
| `npm run lint` | Runs strict TypeScript type-checking (`tsc --noEmit`). |
| `npm run build` | Builds the production Vite frontend bundle into `dist/`. |
| `npm start` | Runs the production server (`node server.ts`). |
| `npm run test:eval` | Runs the Evaluation Lab unit tests (`node:test` via `tsx`). |
| `npm run verify:product` | Builds, starts an isolated product server, and checks the stored golden invariants. |
| `EVAL_LAB=1 npm run eval` | Runs the off-by-default Evaluation Lab CLI (see below). |

### Configuration & Secrets

All credentials are optional at startup and can be configured at runtime under **Settings → Configuration**. Secrets are held strictly in server memory and are never persisted into `policies.yaml` or browser storage. See [`.env.example`](./.env.example):

| Variable | Required | Description |
| :--- | :---: | :--- |
| `DEFYSWARM_INGEST_TOKEN` | Optional | Fixed token for authenticating external S3/MinIO webhooks and CLI uploads. Auto-generated cryptographically in memory if omitted. |
| `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY` | Optional | Monitor credentials for Backblaze B2, Supabase Storage S3, MinIO, or Custom S3. |
| `S3_VAULT_ACCESS_KEY_ID` / `S3_VAULT_SECRET_ACCESS_KEY` | Optional | Isolated credentials for the WORM vault bucket. |
| `GROQ_API_KEY` | Optional | Groq BYOK key (`gsk_...`) for adaptive canary synthesis and blind classifier audits. |
| `APP_URL` | Optional | Public origin used when generating CLI and webhook integration snippets. |

#### Policy-as-Code (`policies.yaml`)
Detection thresholds, enforcement mode (`dry-run` or `production`), swarm window parameters, and allowlisted principals/KMS keys are validated by a strict YAML schema parser that rejects unknown keys and out-of-range thresholds before committing changes.

### Core API Surface

Role-protected endpoints inspect the `x-defyswarm-role` header (`viewer`, `operator`, or `admin`). **This header is a client-supplied demo role switch, not authentication.** Any client can set it, and the server defaults to `admin` when it is absent. Do not expose this server to untrusted clients. External ingestion endpoints authenticate via `X-DefySwarm-Token` or `Authorization: Bearer <token>`.

| Method & Path | Role / Auth | Purpose |
| :--- | :--- | :--- |
| `GET /api/bootstrap` | Public | Hydrates full console state (buckets, principals, incidents, telemetry, vault, policy, health, audit log). |
| `WS /ws/live` | Public | Real-time push stream for telemetry events, incidents, benchmark progress, and heartbeats. |
| `GET /api/storage/objects` | Public | Lists objects in the selected bucket with entropy, magic-byte signature, and vault status. |
| `POST /api/storage/objects` | Token / Role | Binary object upload with real-time 4-signal inspection and HTTP `403` enforcement for revoked principals. |
| `POST /api/ingest/s3-event` | Ingest Token | Authenticated S3/MinIO event webhook receiver. |
| `POST /api/ingest/poll-now` | Operator / Admin | Triggers an immediate quota-safe S3 ETag change poll. |
| `POST /api/principals/:id/status` | Operator / Admin | Revokes or restores a monitored identity (`ACTIVE` / `REVOKED`). |
| `GET /api/incidents/:id/restore-preview` | Public | Computes pre-flight SHA-256 restore plan and attacker artifact cleanup list. |
| `POST /api/incidents/:id/restore` | Operator / Admin | Executes 1-Click WORM vault restore and verifies SHA-256 digests. |
| `POST /api/incidents/:id/approve-admin` | Operator / Admin | Approves or denies pending quarantine for `human_admin` identities. |
| `POST /api/simulator/run` | Operator / Admin | Runs a blast-radius-guarded attack or benign workload drill. |
| `POST /api/benchmarks/run` | Operator / Admin | Executes the multi-run detection & recovery statistical benchmark suite. |
| `PUT /api/policy` | Admin | Validates and applies declarative `policies.yaml` changes. |
| `POST /api/buckets/:name/harden` | Operator / Admin | Runs Auto-Harden verification (versioning, WORM vault, audit, canaries). |
| `POST /api/canaries/generate` | Operator / Admin | Synthesizes and deploys adaptive decoy objects. |
| `POST /api/canaries/classify` | Operator / Admin | Runs a blind adversarial LLM classifier audit on mixed corporate and canary files. |

### Evaluation Lab (off by default)

The repo ships an isolated benchmark harness that compares the shipped detection engine with reference implementations of common legacy approaches. It is invisible unless `EVAL_LAB=1`; the nav entry additionally needs `VITE_EVAL_LAB=1` because the Vite config is outside the lab's edit scope.

```bash
# product, unchanged
npm run dev

# product + lab API/page
EVAL_LAB=1 VITE_EVAL_LAB=1 npm run dev
# open http://localhost:3000/eval

# heavy runs (child process, safety-gated)
EVAL_LAB=1 npm run eval:gen
EVAL_LAB=1 npm run eval -- run --mode full
EVAL_LAB=1 npm run eval:live
```

A run refuses to start when `DEMO_LOCK=1`, a live incident is open, or a simulator is active. The lab uses its own in-memory product instances and writes only under `eval-data/`; it never touches the live store, incidents, policies, principals, or buckets.



