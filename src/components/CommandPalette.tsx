import React, { useEffect, useMemo, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import {
  AlertOctagon,
  AlertTriangle,
  BarChart3,
  Bell,
  Code2,
  CornerDownLeft,
  Database,
  FlaskConical,
  HardDrive,
  HeartPulse,
  KeyRound,
  LayoutGrid,
  Lock,
  Play,
  Radio,
  RefreshCw,
  RotateCcw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  UserCheck,
  UserCog,
  Vault,
  Webhook,
  X,
} from 'lucide-react';
import { type WorkspaceId, type WorkspaceSubTabMap, useConsole } from '../context/ConsoleContext.tsx';
import type { IncidentRecord, Role, StorageProviderPreset } from '../shared/types.ts';

type PaletteScope = 'all' | 'buckets' | 'incidents' | 'settings' | 'actions';

type CommandGroup =
  | 'Active Incidents'
  | 'Storage Buckets'
  | 'Settings & Configuration'
  | 'Workspaces'
  | 'Resolved Incidents'
  | 'Live Actions'
  | 'Switch Role';

interface CommandEntry {
  id: string;
  scope: Exclude<PaletteScope, 'all'>;
  group: CommandGroup;
  title: string;
  titleMono?: boolean;
  codeTag?: string;
  subtitle?: string;
  meta?: string;
  statusTone?: 'critical' | 'warning' | 'healthy' | 'neutral';
  keywords: string;
  icon: React.FC<{ className?: string }>;
  run: () => void | Promise<void>;
}

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
}

const SCOPES: Array<{ id: PaletteScope; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'buckets', label: 'Buckets' },
  { id: 'incidents', label: 'Incidents' },
  { id: 'settings', label: 'Settings' },
  { id: 'actions', label: 'Actions' },
];

const APPLE_SPRING = { type: 'spring' as const, stiffness: 520, damping: 38, mass: 0.7 };

function formatIncidentStatus(status: IncidentRecord['status']): string {
  switch (status) {
    case 'ACTIVE':
      return 'Active';
    case 'CONTAINED':
      return 'Contained';
    case 'DRY_RUN_LOGGED':
      return 'Dry-Run';
    case 'RESTORED':
      return 'Restored';
  }
}

function formatProviderName(provider?: StorageProviderPreset): string {
  switch (provider) {
    case 'backblaze-b2':
      return 'Backblaze B2';
    case 'supabase-s3':
      return 'Supabase S3';
    case 'minio':
      return 'MinIO';
    case 'custom-s3':
      return 'Custom S3';
    default:
      return 'Local Sandbox';
  }
}

function capitalizeWord(str: string): string {
  if (!str) return str;
  return str.charAt(0).toUpperCase() + str.slice(1);
}

function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function HighlightMatch({ text, tokens }: { text: string; tokens: string[] }) {
  if (tokens.length === 0) return <>{text}</>;
  const pattern = new RegExp(`(${tokens.map(escapeRegExp).join('|')})`, 'gi');
  const parts = text.split(pattern);
  return (
    <>
      {parts.map((part, idx) => {
        const isMatch = tokens.some((t) => part.toLowerCase() === t);
        if (!isMatch) return <React.Fragment key={idx}>{part}</React.Fragment>;
        return (
          <mark
            key={idx}
            className="rounded-[3px] bg-[#DBEAFE]/90 px-0.5 font-semibold text-[#1D4ED8]"
          >
            {part}
          </mark>
        );
      })}
    </>
  );
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({ open, onClose }) => {
  const {
    state,
    navigateTo,
    openBucket,
    openSettingsSection,
    setSelectedIncidentId,
    role,
    setRole,
    apiFetch,
    pushToast,
    requestConfirm,
  } = useConsole();

  const [query, setQuery] = useState('');
  const [scope, setScope] = useState<PaletteScope>('all');
  const [selectedIdx, setSelectedIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const itemRefs = useRef<Array<HTMLButtonElement | null>>([]);

  const activeBucket = state?.storage.productionBucket || state?.buckets[0]?.name || 'finance-prod';

  const navigate = <W extends WorkspaceId>(workspace: W, subTab?: WorkspaceSubTabMap[W]) => {
    navigateTo(workspace, subTab);
    onClose();
  };

  const openSettings = (sectionId: string) => {
    openSettingsSection(sectionId);
    onClose();
  };

  const commands = useMemo<CommandEntry[]>(() => {
    const allIncidents = state?.incidents ?? [];
    const openIncidents = allIncidents.filter(
      (i) => i.status === 'ACTIVE' || i.status === 'CONTAINED' || i.status === 'DRY_RUN_LOGGED',
    );
    const resolvedIncidents = allIncidents.filter((i) => i.status === 'RESTORED');

    const mapIncident = (
      inc: IncidentRecord,
      group: 'Active Incidents' | 'Resolved Incidents',
    ): CommandEntry => {
      const tone: CommandEntry['statusTone'] =
        inc.status === 'ACTIVE' || inc.status === 'CONTAINED'
          ? 'critical'
          : inc.status === 'DRY_RUN_LOGGED'
            ? 'warning'
            : 'healthy';
      return {
        id: `inc-${inc.id}`,
        scope: 'incidents',
        group,
        codeTag: inc.id,
        title: inc.title,
        subtitle: `${inc.bucket} · ${inc.principals.length} principal${inc.principals.length === 1 ? '' : 's'} · MTTD ${inc.mttdMs}ms`,
        meta: `${inc.severity} · ${formatIncidentStatus(inc.status)}`,
        statusTone: tone,
        keywords: `incident threat ${inc.id} ${inc.title} ${inc.bucket} ${inc.status} ${inc.severity} ${inc.scenario} ${inc.principals.join(' ')} ${inc.signals.join(' ')}`,
        icon: AlertOctagon,
        run: () => {
          setSelectedIncidentId(inc.id);
          navigateTo('threat-ops', 'incidents');
          onClose();
        },
      };
    };

    const activeIncidentItems = openIncidents.map((inc) => mapIncident(inc, 'Active Incidents'));
    const resolvedIncidentItems = resolvedIncidents.map((inc) =>
      mapIncident(inc, 'Resolved Incidents'),
    );

    const bucketItems: CommandEntry[] = (state?.buckets ?? []).map((b) => {
      const sensitivity = capitalizeWord(
        b.tags?.sensitivity || (b.tags?.env === 'ransomware-sim-only' ? 'Sandbox' : 'Production'),
      );
      const allGuards = b.versioningEnabled && b.objectLockEnabled && b.auditLoggingEnabled;
      const adapterName = b.adapter === 'minio' ? formatProviderName(state?.storage.provider) : 'Local Sandbox';
      return {
        id: `bucket-${b.name}`,
        scope: 'buckets',
        group: 'Storage Buckets',
        title: b.name,
        titleMono: true,
        subtitle: `${b.objectCount} objects · ${b.canaryCount} canaries · Vault ${b.vault} · ${adapterName}`,
        meta: `${sensitivity} · ${allGuards ? 'Hardened' : 'Needs Review'}`,
        statusTone: allGuards ? 'healthy' : 'warning',
        keywords: `bucket storage s3 files objects ${b.name} ${b.vault} ${b.adapter} ${adapterName} ${Object.entries(
          b.tags || {},
        )
          .map(([k, v]) => `${k}=${v}`)
          .join(' ')}`,
        icon: Database,
        run: () => {
          openBucket(b.name);
          onClose();
        },
      };
    });

    const settingsItems: CommandEntry[] = [
      {
        id: 'set-vars',
        scope: 'settings',
        group: 'Settings & Configuration',
        title: 'Variables & Secrets',
        subtitle: 'Runtime credentials, masked keys & environment bindings',
        meta: 'Bindings',
        keywords: 'settings variables secrets env keys tokens groq s3',
        icon: KeyRound,
        run: () => openSettings('variables-secrets'),
      },
      {
        id: 'set-storage',
        scope: 'settings',
        group: 'Settings & Configuration',
        title: 'Storage Connector',
        subtitle: 'Backblaze B2, Supabase Storage, MinIO, Custom S3 & poller',
        meta: formatProviderName(state?.storage.provider),
        statusTone: state?.storage.minioConnected ? 'healthy' : 'neutral',
        keywords:
          'settings storage connector s3 backblaze b2 supabase minio endpoint region poller bucket custom-s3',
        icon: Server,
        run: () => openSettings('storage-connector'),
      },
      {
        id: 'set-webhooks',
        scope: 'settings',
        group: 'Settings & Configuration',
        title: 'Webhooks & Containment',
        subtitle: 'Ingest Bearer token & HMAC-SHA256 signed revocation webhook',
        meta: state?.ingest.containmentWebhookEnabled ? 'Armed' : 'Ingest Ready',
        statusTone: state?.ingest.containmentWebhookEnabled ? 'healthy' : 'neutral',
        keywords: 'settings webhooks containment ingest token hmac s3-event callback',
        icon: Webhook,
        run: () => openSettings('webhooks-containment'),
      },
      {
        id: 'set-alerts',
        scope: 'settings',
        group: 'Settings & Configuration',
        title: 'Alert Channels',
        subtitle: 'Outbound P0 notifications via ntfy, Discord, Slack & webhooks',
        meta: state?.alerts.enabled ? 'Armed' : 'Disabled',
        statusTone: state?.alerts.enabled ? 'healthy' : 'neutral',
        keywords: 'settings alerts notify notifications ntfy discord slack webhook p0',
        icon: Bell,
        run: () => openSettings('alert-channels'),
      },
      {
        id: 'set-ai',
        scope: 'settings',
        group: 'Settings & Configuration',
        title: 'AI Threat Analysis',
        subtitle: 'API key, reasoning effort, quota pacing & canary batch size',
        meta: state?.groq.configured ? 'Connected' : 'Not Configured',
        statusTone: state?.groq.configured ? 'healthy' : 'warning',
        keywords: 'settings ai groq llm model api key byok reasoning canary classifier',
        icon: Sparkles,
        run: () => openSettings('groq-ai'),
      },
      {
        id: 'set-buckets',
        scope: 'settings',
        group: 'Settings & Configuration',
        title: 'Buckets & Hardening',
        subtitle: 'Register protected buckets & run 4-check Auto-Harden',
        meta: `${state?.buckets.length ?? 0} Buckets`,
        keywords: 'settings buckets register hardening versioning worm audit',
        icon: ShieldCheck,
        run: () => openSettings('buckets-hardening'),
      },
      {
        id: 'set-allowlist',
        scope: 'settings',
        group: 'Settings & Configuration',
        title: 'Identity Allowlists',
        subtitle: 'Trusted backup service accounts & approved KMS key ARNs',
        meta: `${state?.policy.allowlist.principals.length ?? 0} Principals`,
        keywords: 'settings allowlist principals kms keys exempt backup trusted',
        icon: UserCheck,
        run: () => openSettings('allowlists'),
      },
      {
        id: 'set-policy',
        scope: 'settings',
        group: 'Settings & Configuration',
        title: 'Policy as Code',
        codeTag: 'policies.yaml',
        subtitle: 'Edit detection thresholds, entropy delta, swarm rules & triggers',
        meta: state?.policy.mode === 'active' ? 'Active' : 'Dry-Run',
        statusTone: state?.policy.mode === 'active' ? 'healthy' : 'warning',
        keywords:
          'settings policy policies.yaml yaml code rules detection thresholds entropy swarm mode dry-run',
        icon: Code2,
        run: () => openSettings('policy-yaml'),
      },
      {
        id: 'set-health',
        scope: 'settings',
        group: 'Settings & Configuration',
        title: 'Health & Audit Trail',
        subtitle: 'Control-plane latency, AI quota usage, stream checks & audit log',
        meta: 'Diagnostics',
        keywords: 'settings health audit log trail usage quotas stream gap uptime heartbeat',
        icon: HeartPulse,
        run: () => navigate('settings', 'health-audit'),
      },
      {
        id: 'set-danger',
        scope: 'settings',
        group: 'Settings & Configuration',
        title: 'Danger Zone',
        subtitle: 'Clear runtime credentials or reset sandbox baseline',
        meta: 'Destructive',
        statusTone: 'critical',
        keywords: 'settings danger zone reset clear credentials wipe',
        icon: AlertTriangle,
        run: () => openSettings('danger-zone'),
      },
    ];

    const workspaceItems: CommandEntry[] = [
      {
        id: 'nav-ov',
        scope: 'actions',
        group: 'Workspaces',
        title: 'Overview',
        subtitle: 'Protection topology, bindings, live metrics & recent activity',
        keywords: 'workspace overview home topology graph metrics bindings',
        icon: LayoutGrid,
        run: () => navigate('overview'),
      },
      {
        id: 'nav-store',
        scope: 'buckets',
        group: 'Workspaces',
        title: 'Storage › Live Files',
        subtitle: 'Browse bucket objects, upload files, download & CLI kit',
        keywords: 'workspace storage live files upload real files curl s3 objects',
        icon: HardDrive,
        run: () => navigate('storage', 'live-files'),
      },
      {
        id: 'nav-can',
        scope: 'buckets',
        group: 'Workspaces',
        title: 'Storage › Canaries & Vault',
        subtitle: 'Adaptive decoy files, AI classifier audit & WORM snapshots',
        keywords: 'workspace storage canaries vault worm decoys snapshots immutable',
        icon: Vault,
        run: () => navigate('storage', 'canaries-vault'),
      },
      {
        id: 'nav-war',
        scope: 'incidents',
        group: 'Workspaces',
        title: 'Threat Ops › Live Telemetry',
        subtitle: 'Real-time event feed, Shannon entropy chart & credential standing',
        keywords: 'workspace threat ops telemetry live feed war room entropy risk observability',
        icon: Radio,
        run: () => navigate('threat-ops', 'telemetry'),
      },
      {
        id: 'nav-inc',
        scope: 'incidents',
        group: 'Workspaces',
        title: 'Threat Ops › Incidents',
        subtitle: 'Forensic queue, admin approvals & 1-Click Vault Restore',
        meta: openIncidents.length > 0 ? `${openIncidents.length} Open` : 'Clear',
        statusTone: openIncidents.length > 0 ? 'critical' : 'healthy',
        keywords: 'workspace threat ops incidents issues restore rollback forensics vault',
        icon: AlertOctagon,
        run: () => navigate('threat-ops', 'incidents'),
      },
      {
        id: 'nav-sim',
        scope: 'actions',
        group: 'Workspaces',
        title: 'Validation › Simulator',
        subtitle: 'Execute safe ransomware, swarm & recovery verification drills',
        keywords: 'workspace validation simulator attack test benign swarm ransomware drill',
        icon: FlaskConical,
        run: () => navigate('validation', 'simulator'),
      },
      {
        id: 'nav-ana',
        scope: 'actions',
        group: 'Workspaces',
        title: 'Validation › Analytics',
        subtitle: 'Detection speed (MTTD/MTTC), preservation rate & benchmarks',
        keywords: 'workspace validation analytics mttd mttc p95 metrics benchmarks',
        icon: BarChart3,
        run: () => navigate('validation', 'analytics'),
      },
    ];

    const actionItems: CommandEntry[] = [
      {
        id: 'act-harden',
        scope: 'actions',
        group: 'Live Actions',
        title: `Run Auto-Harden`,
        codeTag: activeBucket,
        subtitle: 'Verify Versioning, WORM Vault, Audit Logging & Canaries',
        meta: '4 Checks',
        keywords: `action auto harden posture verify ${activeBucket} versioning vault canaries audit`,
        icon: ShieldCheck,
        run: async () => {
          onClose();
          try {
            await apiFetch(`/api/buckets/${encodeURIComponent(activeBucket)}/harden`, {
              method: 'POST',
            });
            pushToast({
              title: `Auto-Harden Complete: ${activeBucket}`,
              detail: 'All 4 protection posture checks verified.',
              tone: 'success',
            });
          } catch (err) {
            pushToast({
              title: 'Auto-Harden failed',
              detail: err instanceof Error ? err.message : 'Error',
              tone: 'error',
            });
          }
        },
      },
      {
        id: 'act-std',
        scope: 'actions',
        group: 'Live Actions',
        title: 'Run Sabotage & Encryption Drill',
        subtitle: `Simulates versioning sabotage + AES-256 burst on ${activeBucket}`,
        meta: 'Ransomware',
        statusTone: 'critical',
        keywords: 'action run attack standard ransomware encryption sabotage drill',
        icon: ShieldAlert,
        run: async () => {
          onClose();
          navigateTo('threat-ops', 'telemetry');
          try {
            await apiFetch('/api/simulator/run', {
              method: 'POST',
              body: JSON.stringify({ scenario: 'standard_ransomware', bucket: activeBucket }),
            });
            pushToast({
              title: 'Ransomware drill started',
              detail: 'Streaming live events to Live Telemetry.',
              tone: 'info',
            });
          } catch (err) {
            pushToast({
              title: 'Unable to start drill',
              detail: err instanceof Error ? err.message : 'Error',
              tone: 'error',
            });
          }
        },
      },
      {
        id: 'act-swarm',
        scope: 'actions',
        group: 'Live Actions',
        title: 'Run Distributed Key Swarm Drill',
        subtitle: 'Coordinated slow-burn SSE-C & overwrite attack across 4 principals',
        meta: '4 Principals',
        statusTone: 'warning',
        keywords: 'action run stealth ai swarm sse-c correlation drill',
        icon: ShieldAlert,
        run: async () => {
          onClose();
          navigateTo('threat-ops', 'telemetry');
          try {
            await apiFetch('/api/simulator/run', {
              method: 'POST',
              body: JSON.stringify({ scenario: 'stealth_ai_swarm', bucket: activeBucket }),
            });
            pushToast({
              title: 'Distributed swarm drill started',
              detail: '4 assumed-role principals active.',
              tone: 'info',
            });
          } catch (err) {
            pushToast({
              title: 'Unable to start drill',
              detail: err instanceof Error ? err.message : 'Error',
              tone: 'error',
            });
          }
        },
      },
      {
        id: 'act-benign',
        scope: 'actions',
        group: 'Live Actions',
        title: 'Run Benign Backup Surge',
        subtitle: 'Verifies zero false-positive revocations across 50 business files',
        meta: '50 Files',
        keywords: 'action run benign bulk upload false positive check',
        icon: Play,
        run: async () => {
          onClose();
          navigateTo('threat-ops', 'telemetry');
          try {
            await apiFetch('/api/simulator/run', {
              method: 'POST',
              body: JSON.stringify({ scenario: 'benign_bulk', bucket: activeBucket }),
            });
            pushToast({
              title: 'Benign workload started',
              detail: 'Uploading 50 verified business files.',
              tone: 'info',
            });
          } catch (err) {
            pushToast({
              title: 'Unable to start workload',
              detail: err instanceof Error ? err.message : 'Error',
              tone: 'error',
            });
          }
        },
      },
      {
        id: 'act-canaries',
        scope: 'actions',
        group: 'Live Actions',
        title: 'Refresh Adaptive Canaries',
        subtitle: `Rotate realistic decoy files in ${activeBucket} without self-loop alerts`,
        meta: 'Safe Rotate',
        keywords: 'action refresh rotate canaries decoys',
        icon: RefreshCw,
        run: async () => {
          onClose();
          try {
            await apiFetch('/api/canaries/refresh', {
              method: 'POST',
              body: JSON.stringify({ bucket: activeBucket }),
            });
            pushToast({
              title: 'Canaries Rotated',
              detail: 'Refreshed under defyswarm-service (0 alerts).',
              tone: 'success',
            });
          } catch (err) {
            pushToast({
              title: 'Refresh failed',
              detail: err instanceof Error ? err.message : 'Error',
              tone: 'error',
            });
          }
        },
      },
      {
        id: 'act-reset',
        scope: 'actions',
        group: 'Live Actions',
        title: 'Reset Sandbox Baseline',
        subtitle: 'Restore default objects, principals, vault manifest & policies.yaml',
        meta: 'Confirm',
        statusTone: 'critical',
        keywords: 'action reset sandbox clean baseline restore',
        icon: RotateCcw,
        run: () => {
          onClose();
          requestConfirm({
            title: 'Reset Sandbox Baseline?',
            message:
              'Restores baseline objects, returns all principals to Active standing, clears recent incidents and events, and resets policies.yaml.',
            confirmLabel: 'Reset Sandbox',
            destructive: true,
            onConfirm: async () => {
              await apiFetch('/api/simulator/reset', { method: 'POST' });
              pushToast({ title: 'Sandbox reset complete', tone: 'success' });
            },
          });
        },
      },
    ];

    const roleItems: CommandEntry[] = (['admin', 'operator', 'viewer'] as Role[]).map((r) => ({
      id: `role-${r}`,
      scope: 'actions',
      group: 'Switch Role',
      title: `Switch Role to ${capitalizeWord(r)}`,
      subtitle:
        r === 'admin'
          ? 'Full policy, credential, and quarantine permissions'
          : r === 'operator'
            ? 'Incident containment, vault restore, and drill execution'
            : 'Read-only telemetry and forensic inspection',
      meta: role === r ? 'Active' : undefined,
      statusTone: role === r ? 'healthy' : 'neutral',
      keywords: `role rbac switch permission ${r}`,
      icon: r === 'admin' ? Lock : UserCog,
      run: () => {
        setRole(r);
        pushToast({ title: `Active role: ${capitalizeWord(r)}`, tone: 'info' });
        onClose();
      },
    }));

    return [
      ...activeIncidentItems,
      ...bucketItems,
      ...settingsItems,
      ...workspaceItems,
      ...resolvedIncidentItems,
      ...actionItems,
      ...roleItems,
    ];
  }, [
    state?.incidents,
    state?.buckets,
    state?.storage.provider,
    state?.storage.minioConnected,
    state?.ingest.containmentWebhookEnabled,
    state?.alerts.enabled,
    state?.groq.configured,
    state?.policy.allowlist.principals.length,
    state?.policy.mode,
    activeBucket,
    role,
    apiFetch,
    pushToast,
    requestConfirm,
    navigateTo,
    openBucket,
    openSettingsSection,
    setSelectedIncidentId,
    setRole,
    onClose,
  ]);

  const scopeCounts = useMemo(
    () => ({
      buckets: state?.buckets.length ?? 0,
      incidents: state?.incidents.length ?? 0,
    }),
    [state?.buckets.length, state?.incidents.length],
  );

  const activeIncidentCount = useMemo(
    () =>
      (state?.incidents ?? []).filter((i) => i.status === 'ACTIVE' || i.status === 'CONTAINED')
        .length,
    [state?.incidents],
  );

  const queryTokens = useMemo(
    () =>
      query
        .trim()
        .toLowerCase()
        .split(/\s+/)
        .filter(Boolean),
    [query],
  );

  const filtered = useMemo(() => {
    return commands.filter((c) => {
      if (scope !== 'all' && c.scope !== scope) return false;
      if (queryTokens.length === 0) return true;
      const haystack = `${c.codeTag || ''} ${c.title} ${c.subtitle || ''} ${c.meta || ''} ${c.group} ${c.keywords}`.toLowerCase();
      return queryTokens.every((tok) => haystack.includes(tok));
    });
  }, [commands, scope, queryTokens]);

  useEffect(() => {
    if (open) {
      setQuery('');
      setScope('all');
      setSelectedIdx(0);
      setTimeout(() => inputRef.current?.focus(), 20);
    }
  }, [open]);

  useEffect(() => {
    setSelectedIdx(0);
  }, [query, scope]);

  useEffect(() => {
    const el = itemRefs.current[selectedIdx];
    if (el) {
      el.scrollIntoView({ block: 'nearest' });
    }
  }, [selectedIdx, filtered.length]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      } else if (e.key === 'Tab') {
        e.preventDefault();
        setScope((prev) => {
          const idx = SCOPES.findIndex((s) => s.id === prev);
          const nextIdx = e.shiftKey
            ? (idx - 1 + SCOPES.length) % SCOPES.length
            : (idx + 1) % SCOPES.length;
          return SCOPES[nextIdx].id;
        });
      } else if (e.key === 'ArrowDown' || (e.ctrlKey && e.key.toLowerCase() === 'n')) {
        e.preventDefault();
        setSelectedIdx((prev) => (filtered.length === 0 ? 0 : (prev + 1) % filtered.length));
      } else if (e.key === 'ArrowUp' || (e.ctrlKey && e.key.toLowerCase() === 'p')) {
        e.preventDefault();
        setSelectedIdx((prev) =>
          filtered.length === 0 ? 0 : (prev - 1 + filtered.length) % filtered.length,
        );
      } else if (e.key === 'Enter' && filtered[selectedIdx]) {
        e.preventDefault();
        void filtered[selectedIdx].run();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, filtered, selectedIdx, onClose]);

  const grouped = useMemo(() => {
    const map = new Map<CommandGroup, Array<{ item: CommandEntry; flatIdx: number }>>();
    filtered.forEach((item, flatIdx) => {
      const list = map.get(item.group) ?? [];
      list.push({ item, flatIdx });
      map.set(item.group, list);
    });
    return Array.from(map.entries());
  }, [filtered]);

  itemRefs.current = [];

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.14 }}
          className="fixed inset-0 z-50 flex items-start justify-center bg-[#0F172A]/28 px-4 pt-[10vh] backdrop-blur-[3px]"
          onClick={onClose}
        >
          <motion.div
            role="dialog"
            aria-modal="true"
            aria-label="Global command palette"
            initial={{ opacity: 0, scale: 0.98, y: -10 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.985, y: -6 }}
            transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }}
            className="w-full max-w-[640px] overflow-hidden rounded-[14px] bg-white/[0.98] shadow-[0_24px_64px_-12px_rgba(15,23,42,0.22),0_4px_16px_-4px_rgba(15,23,42,0.08),0_0_0_1px_rgba(15,23,42,0.08)] backdrop-blur-xl"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Frameless Search Header */}
            <div className="flex h-[52px] items-center gap-3 border-b border-[#EEF0F2] px-4">
              <Search
                className={`h-4 w-4 shrink-0 transition-colors ${
                  query ? 'text-[#111827]' : 'text-[#9CA3AF]'
                }`}
              />
              <input
                ref={inputRef}
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search buckets, incidents, settings, or actions…"
                className="focus-ring-none w-full border-0 bg-transparent text-[14.5px] font-normal tracking-[-0.012em] text-[#111827] placeholder:text-[#9CA3AF]"
              />
              {query && (
                <button
                  type="button"
                  onClick={() => {
                    setQuery('');
                    inputRef.current?.focus();
                  }}
                  aria-label="Clear search query"
                  className="rounded-[6px] p-1 text-[#9CA3AF] transition-colors hover:bg-[#F3F4F6] hover:text-[#111827]"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              )}
              <kbd className="inline-flex h-[22px] items-center rounded-[6px] border border-[#E5E7EB] bg-[#F9FAFB] px-1.5 font-mono text-[10.5px] font-medium text-[#6B7280]">
                Esc
              </kbd>
            </div>

            {/* Quiet Hairline Scope Tab Bar */}
            <div className="flex h-[38px] items-center justify-between gap-3 border-b border-[#EEF0F2] bg-[#FAFAFB]/80 px-4">
              <div
                className="flex h-full items-center gap-4 overflow-x-auto"
                role="tablist"
                aria-label="Search scope"
              >
                {SCOPES.map((s) => {
                  const active = scope === s.id;
                  const count =
                    s.id === 'buckets'
                      ? scopeCounts.buckets
                      : s.id === 'incidents'
                        ? scopeCounts.incidents
                        : undefined;
                  return (
                    <button
                      key={s.id}
                      type="button"
                      role="tab"
                      aria-selected={active}
                      onClick={() => {
                        setScope(s.id);
                        inputRef.current?.focus();
                      }}
                      className={`focus-ring-none relative flex h-full items-center gap-1.5 text-[12px] font-medium transition-colors whitespace-nowrap shrink-0 ${
                        active ? 'text-[#111827]' : 'text-[#6B7280] hover:text-[#111827]'
                      }`}
                    >
                      <span>{s.label}</span>
                      {count !== undefined && (
                        <span
                          className={`font-mono text-[11px] tabular-nums ${
                            s.id === 'incidents' && activeIncidentCount > 0
                              ? 'font-semibold text-[#DC2626]'
                              : active
                                ? 'text-[#4B5563]'
                                : 'text-[#9CA3AF]'
                          }`}
                        >
                          {count}
                        </span>
                      )}
                      {active && (
                        <motion.span
                          layoutId="palette-scope-underline"
                          transition={APPLE_SPRING}
                          className="absolute inset-x-0 bottom-0 h-[2px] rounded-full bg-[#111827]"
                        />
                      )}
                    </button>
                  );
                })}
              </div>
              <span className="hidden text-[11px] text-[#9CA3AF] tabular-nums sm:inline whitespace-nowrap">
                {filtered.length} {filtered.length === 1 ? 'item' : 'items'}
              </span>
            </div>

            {/* Scannable Command List */}
            <div className="max-h-[416px] overflow-y-auto px-2 py-2">
              {grouped.length === 0 ? (
                <div className="py-12 px-6 text-center">
                  <p className="text-[13.5px] font-medium text-[#111827]">
                    No results for &ldquo;{query}&rdquo;
                    {scope !== 'all'
                      ? ` in ${SCOPES.find((s) => s.id === scope)?.label}`
                      : ''}
                  </p>
                  <p className="mt-1.5 text-[12px] text-[#6B7280]">
                    Try a bucket name like <span className="font-mono text-[#374151]">finance-prod</span>, an incident ID, or a settings keyword such as <span className="font-mono text-[#374151]">yaml</span> or <span className="font-mono text-[#374151]">webhook</span>.
                  </p>
                  {scope !== 'all' && (
                    <button
                      type="button"
                      onClick={() => setScope('all')}
                      className="mt-3.5 inline-flex h-[30px] items-center rounded-[7px] border border-[#E5E7EB] bg-white px-3 text-[12px] font-medium text-[#374151] transition-colors hover:bg-[#F9FAFB] hover:text-[#111827]"
                    >
                      Search across all scopes
                    </button>
                  )}
                </div>
              ) : (
                grouped.map(([groupName, entries], groupIdx) => (
                  <div key={groupName} className={groupIdx === 0 ? '' : 'mt-3'}>
                    <div className="px-2.5 pb-1.5 pt-1 text-[11px] font-medium tracking-[0.01em] text-[#6B7280]">
                      {groupName}
                    </div>
                    <div className="space-y-0.5">
                      {entries.map(({ item, flatIdx }) => {
                        const Icon = item.icon;
                        const isSelected = flatIdx === selectedIdx;
                        const toneDot =
                          item.statusTone === 'critical'
                            ? 'bg-[#DC2626]'
                            : item.statusTone === 'warning'
                              ? 'bg-[#D97706]'
                              : item.statusTone === 'healthy'
                                ? 'bg-[#16A34A]'
                                : null;

                        const iconColor =
                          item.statusTone === 'critical'
                            ? 'text-[#DC2626]'
                            : item.statusTone === 'warning'
                              ? 'text-[#D97706]'
                              : isSelected
                                ? 'text-[#1D6CF0]'
                                : 'text-[#6B7280]';

                        return (
                          <button
                            key={item.id}
                            ref={(el) => {
                              itemRefs.current[flatIdx] = el;
                            }}
                            type="button"
                            onMouseEnter={() => setSelectedIdx(flatIdx)}
                            onClick={() => void item.run()}
                            className={`focus-ring-none relative flex w-full items-center justify-between gap-3 rounded-[9px] px-2.5 py-2 text-left transition-colors ${
                              isSelected
                                ? 'bg-[#F3F5F8] shadow-[inset_0_0_0_1px_rgba(15,23,42,0.06)]'
                                : 'hover:bg-[#F9FAFB]'
                            }`}
                          >
                            {/* Subtle left active focus indicator */}
                            {isSelected && (
                              <span
                                aria-hidden="true"
                                className="absolute left-0 top-2 bottom-2 w-[2.5px] rounded-r-full bg-[#1D6CF0]"
                              />
                            )}

                            <div className="flex items-center gap-3 min-w-0">
                              <span
                                className={`flex h-[30px] w-[30px] shrink-0 items-center justify-center rounded-[8px] border transition-colors ${
                                  isSelected
                                    ? 'border-[#DCE3EC] bg-white shadow-[0_1px_2px_rgba(15,23,42,0.05)]'
                                    : 'border-[#ECEEF2] bg-[#F9FAFB]'
                                }`}
                              >
                                <Icon className={`h-[15px] w-[15px] ${iconColor}`} />
                              </span>

                              <div className="min-w-0">
                                <div className="flex items-center gap-2 min-w-0">
                                  <span
                                    className={`truncate text-[13px] ${
                                      item.titleMono
                                        ? 'font-mono font-semibold text-[#111827]'
                                        : 'font-medium text-[#111827]'
                                    }`}
                                  >
                                    <HighlightMatch text={item.title} tokens={queryTokens} />
                                  </span>
                                  {item.codeTag && (
                                    <span className="shrink-0 rounded-[5px] border border-[#E5E7EB] bg-[#F9FAFB] px-1.5 py-0.5 font-mono text-[10.5px] font-medium text-[#4B5563]">
                                      <HighlightMatch text={item.codeTag} tokens={queryTokens} />
                                    </span>
                                  )}
                                </div>
                                {item.subtitle && (
                                  <p className="mt-0.5 truncate text-[11.5px] text-[#6B7280]">
                                    <HighlightMatch text={item.subtitle} tokens={queryTokens} />
                                  </p>
                                )}
                              </div>
                            </div>

                            <div className="flex items-center gap-2.5 shrink-0">
                              {item.meta && (
                                <span className="inline-flex items-center gap-1.5 text-[11.5px] font-medium text-[#4B5563] whitespace-nowrap">
                                  {toneDot && (
                                    <span className={`h-1.5 w-1.5 rounded-full ${toneDot}`} />
                                  )}
                                  <span>{item.meta}</span>
                                </span>
                              )}
                              {isSelected && (
                                <span
                                  aria-hidden="true"
                                  className="inline-flex h-[22px] w-[22px] items-center justify-center rounded-[6px] border border-[#DCE3EC] bg-white text-[#6B7280] shadow-[0_1px_0_rgba(15,23,42,0.04)]"
                                >
                                  <CornerDownLeft className="h-3 w-3" />
                                </span>
                              )}
                            </div>
                          </button>
                        );
                      })}
                    </div>
                  </div>
                ))
              )}
            </div>

            {/* Minimal Keyboard Legend Footer */}
            <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[#EEF0F2] bg-[#FAFAFB] px-4 py-2 text-[11px] text-[#6B7280]">
              <div className="flex items-center gap-3.5">
                <span className="inline-flex items-center gap-1.5">
                  <kbd className="inline-flex h-[18px] items-center rounded-[4px] border border-[#E5E7EB] bg-white px-1 font-mono text-[10px] text-[#4B5563]">
                    ↑↓
                  </kbd>
                  <span>Navigate</span>
                </span>
                <span className="inline-flex items-center gap-1.5">
                  <kbd className="inline-flex h-[18px] items-center rounded-[4px] border border-[#E5E7EB] bg-white px-1 font-mono text-[10px] text-[#4B5563]">
                    ↵
                  </kbd>
                  <span>Open</span>
                </span>
                <span className="inline-flex items-center gap-1.5">
                  <kbd className="inline-flex h-[18px] items-center rounded-[4px] border border-[#E5E7EB] bg-white px-1.5 font-mono text-[10px] text-[#4B5563]">
                    Tab
                  </kbd>
                  <span>Switch scope</span>
                </span>
              </div>
              <span className="text-[11px] text-[#6B7280]">
                Role: <span className="font-medium text-[#374151]">{capitalizeWord(role)}</span>
              </span>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};
