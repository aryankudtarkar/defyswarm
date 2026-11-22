# DefySwarm: ICP-First Product Documentation, Zero-Pulse Status & Apple-Style Shimmer Skeletons

## Summary
This plan executes three sequential upgrades to elevate DefySwarm's operational clarity and perceived performance:
1. **Complete Product README Rewrite (First)**: Replace the outdated developer-centric README with a structured, production-grade document tailored **ICP-first for Cloud Security and SRE teams**, followed by a concise **developer-second** engineering reference.
2. **Pulsating Dot Removal**: Eliminate all pulsating/pinging indicator animations across the console and replace the sidebar live connection indicator with a calm, **text-only status label**.
3. **Immediate App Shell & Apple-Style Shimmer Skeletons**: Render the persistent console shell (sidebar, top header, contextual sub-tab bar) immediately on load and display geometry-matched, Apple-style shimmer skeletons across all 9 views (5 workspaces) during control-plane initialization and async storage bucket fetches.

---

## User Review & Critical Decisions
The following design decisions were confirmed prior to planning and govern this implementation:

| Decision Area | Confirmed Choice | Impact |
| :--- | :--- | :--- |
| **README Top-Half Audience** | Cloud Security and SRE teams | Leads with operational posture, out-of-band detection signals, containment SLAs, recovery workflows, and console navigation before developer setup. |
| **Initial Loading Framing** | Render app shell immediately with workspace skeletons | Removes the full-viewport blocking spinner so operators see navigation, workspace context, and exact layout structure from frame one. |
| **Live Connection Indicator** | Text-only status label with no dot | Removes both the pulsing ring and status dot in the sidebar footer, leaving a crisp, low-noise text status (`Connected` / `Reconnecting`). |

---

## 1. Overview & Core Concept

### Step 1: ICP-First, Developer-Second README Rewrite
Before touching interface code, the root README will be rewritten from scratch to reflect DefySwarm's real architecture and consolidated 5-workspace console design—removing legacy dark-theme references, outdated 9-tab descriptions, and internal build progress logs.

- **Top Half — For Cloud Security & SRE Teams**:
  - **Product Positioning**: Out-of-band cloud object storage defense against high-velocity ransomware and distributed multi-credential swarm attacks, operating with zero inline data-path latency.
  - **Operational Guarantees & Detection Model**: Clear breakdown of the 4-signal scoring engine (Shannon entropy surge, adaptive canary tripwires, destructive velocity anomalies, and cross-principal swarm correlation), automated HTTP 403 credential revocation, isolated WORM vaulting, SHA-256 verified 1-Click Restore, and blast-radius / human-approval guardrails.
  - **Console Operating Model**: Concise guide to the 5 consolidated workspaces (`Overview`, `Storage`, `Threat Ops`, `Validation`, `Settings`), the `⌘K` Command Palette for instant navigation across buckets, incidents, and settings, and the slide-over Forensic Inspector.
  - **Supported Integrations**: Cloud storage providers (Backblaze B2, Supabase Storage S3, MinIO, Custom S3, built-in local sandbox) and outbound alerting/containment hooks (ntfy, Discord, Slack, HMAC-SHA256 signed webhooks).
- **Bottom Half — For Platform Engineers & Developers**:
  - **System Architecture**: Clean ASCII data-flow diagram from storage ingest through the detection engine, vault/containment layer, and real-time console.
  - **Local Quickstart & Scripts**: Minimal commands for local startup, type-checking, and production builds.
  - **Configuration & Policy-as-Code**: Runtime environment variables, memory-only secret posture, and declarative YAML policy rules.
  - **API & Screen-Flow Reference**: Core REST endpoints, live WebSocket telemetry stream, and pointer to the Mermaid screen-flow diagram.

### Step 2: Quiet Status Discipline (No Pulsating Dots)
High-craft infrastructure consoles avoid distracting perpetual animations that create false urgency during steady-state operations. All `ping` and `pulse` dot animations will be removed across the application. In the sidebar footer, the real-time telemetry channel status will appear as a clean text-only label (`Connected` in quiet neutral ink when healthy; `Reconnecting` in muted amber when degraded), with zero dot or animated halo.

### Step 3: Apple-Style Shimmer Skeletons Across All Workspaces
Rather than stalling operators behind a centered full-screen loading card while initial control-plane state fetches, DefySwarm will immediately mount the persistent console frame and populate the active workspace viewport with subtle, geometry-matched shimmer skeletons that smoothly cross-fade into hydrated live views.

---

## 2. User Experience & Visual Design

### Shimmer Aesthetic & Motion Craft
- **Surface Palette**: Aligned with DefySwarm's light hairline canvas (`#FFFFFF` cards on `#F8F9FA` workspace background with `1px solid #E5E7EB` hairlines). Skeleton blocks use a cool-neutral base (`#F1F3F5`) swept by a gentle translucent sheen (`#F8FAFC` → `#FFFFFF` → `#F8FAFC`).
- **Sweep Physics**: Smooth linear-gradient horizontal sweep (`1.5s`, eased timing) rather than harsh opacity blinking, keeping visual contrast calm and refined.
- **Reduced-Motion Accessibility**: Under `prefers-reduced-motion: reduce`, the sweep animation pauses and renders a clean, static `#F1F3F5` placeholder surface.
- **Hydration Cross-Fade**: Skeletons and live workspace content participate in the console's existing view transition container so hydration resolves via a subtle cross-fade with zero vertical layout shift.

### Per-Workspace Skeleton Coverage (All 9 Views + Async Storage Lists)
Each skeleton mirrors the real screen's structural rhythm, column proportions, and card heights so content settles into place without jumping:

1. **Overview**: Page header + contextual action buttons, system posture strip, 3-column topology graph (ingest sources → defense engine → bound endpoints), 8/4 metrics sparkline & protected endpoints split, and recent telemetry table rows.
2. **Storage — Live Files**: Header & bucket controls bar, 4-cell bucket posture strip, and 7/5 split featuring the upload dropzone + object table rows on the left and the Object Inspector detail pane on the right.
3. **Storage — Canaries & Vault**: Header & canary action controls, 4-cell vault/canary posture strip, and split canary inventory table + AI classifier audit card.
4. **Threat Ops — Live Telemetry**: Header, 4-column telemetry KPI strip, 8/4 entropy chart & risk gauge split, 6/6 monitored credentials & event timeline split, and full-width live activity table rows.
5. **Threat Ops — Incidents**: Header & filter bar, 8/4 containment coverage summary strip, and 4/8 master-detail incident queue + forensic detail skeleton.
6. **Validation — Simulator**: Header & scenario controls, blast-radius safety guardrail strip, 2×2 attack drill cards grid, and verification checklist panel.
7. **Validation — Analytics**: Header, benchmark KPI strip, and scenario comparison chart & breakdown table cards.
8. **Settings — Configuration**: Header & enforcement mode segmented bar, main configuration cards column paired with the sticky right-hand section anchor rail.
9. **Settings — Health & Audit**: Header, runtime health & quota progress cards, and full-width immutable audit log table rows.
10. **Async Bucket Table Loading**: When switching storage buckets or refreshing object listings inside **Live Files**, the object table renders matching `40px` shimmer rows instead of a plain text loading line.

---

## 3. Key Product Decisions & Trade-Offs

- **ICP-First, Developer-Second Documentation Split**: Prioritizing Cloud Security and SRE outcomes in the top half ensures stakeholders immediately grasp risk reduction, containment automation, and recovery guarantees before encountering setup commands—without sacrificing technical depth for engineers below the fold.
- **Immediate Persistent Shell vs. Full-Screen Loader**: Mounting the sidebar, top bar, and sub-tab bar immediately gives operators spatial orientation and allows switching target workspaces even before bootstrap finishes. Trade-off: top-bar dynamic badges (enforcement mode, active bucket count) must safely display compact shimmer pills while control-plane state is null.
- **Custom CSS Shimmer Sweep vs. Utility Opacity Pulse**: A dedicated gradient sweep produces the crisp, tactile feel of native macOS/Apple interfaces and avoids the distracting "blinking" feel of standard opacity pulsing—while remaining lightweight pure CSS with zero runtime JS overhead.
- **Text-Only Connection Label vs. Static Dot**: Removing the dot entirely eliminates visual noise in the sidebar footer and avoids competing with semantic severity markers inside telemetry tables and incident queues.

---

## 4. Technical Architecture & Data Strategy

```
                   Control-Plane Bootstrap & WebSocket
                                   │
          ┌────────────────────────┴────────────────────────┐
          ▼                                                 ▼
   loading === true                                  loading === false
          │                                                 │
          ▼                                                 ▼
 ┌───────────────────────────────────────────────────────────────────┐
 │                   Persistent Console App Shell                    │
 │  Sidebar (5 Workspaces + Text-Only Status) │ Topbar │ Sub-Tab Bar │
 └───────────────────────────────────────────────────────────────────┘
          │                                                 │
          ▼                                                 ▼
 ┌─────────────────────────┐   Smooth Cross-Fade   ┌─────────────────────────┐
 │ Workspace Skeleton      │ ────────────────────▶ │ Hydrated Workspace View │
 │ Router (9 Screen Specs) │                       │ (Live State & Actions)  │
 └─────────────────────────┘                       └─────────────────────────┘
                                                            │
                                                            ▼ (Bucket switch)
                                                   ┌─────────────────────────┐
                                                   │ Inline Table-Row        │
                                                   │ Shimmer Skeletons       │
                                                   └─────────────────────────┘
```

### Data & Rendering Strategy
- **Zero Backend Changes**: All loading states derive directly from existing control-plane bootstrap hydration (`loading`) and live object listing fetch state (`loadingList`).
- **Null-Safe Shell Hydration**: Header indicators and top-bar status controls tolerate null control-plane state during initial fetch, rendering subtle fixed-width shimmer chips until hydrated without causing horizontal header jitter.
- **Composable Shimmer Primitives**: A small set of pure-CSS shimmer primitives (text lines, headings, metric tiles, badges, buttons, and table rows) powers all 9 workspace skeletons consistently, guaranteeing uniform rhythm and effortless maintenance as views evolve.
- **Verification**: After implementation, verify zero remaining pulsing/ping animations across the codebase and run full static type-checking and production build verification.
