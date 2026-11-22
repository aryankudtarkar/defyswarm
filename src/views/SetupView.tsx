import React, { useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  Bell,
  CheckCircle2,
  Copy,
  Eye,
  EyeOff,
  KeyRound,
  Lock,
  Pencil,
  Plus,
  RefreshCw,
  RotateCw,
  Save,
  Send,
  Server,
  ShieldCheck,
  Trash2,
  Webhook,
  XCircle,
} from 'lucide-react';
import { useConsole } from '../context/ConsoleContext.tsx';
import type { AutoHardenResult, StorageProviderPreset } from '../shared/types.ts';

const PROVIDER_PRESETS: Record<
  StorageProviderPreset,
  {
    label: string;
    tierNote: string;
    endpoint: string;
    region: string;
    forcePathStyle: boolean;
  }
> = {
  local: {
    label: 'Local Sandbox',
    tierNote: 'Built-in object store with live uploads and enforcement',
    endpoint: '',
    region: 'us-east-1',
    forcePathStyle: true,
  },
  'backblaze-b2': {
    label: 'Backblaze B2',
    tierNote: 'S3-compatible private buckets with Object Lock support',
    endpoint: 'https://s3.us-west-004.backblazeb2.com',
    region: 'us-west-004',
    forcePathStyle: false,
  },
  'supabase-s3': {
    label: 'Supabase Storage',
    tierNote: 'S3-compatible object storage for Supabase projects',
    endpoint: 'https://<project-ref>.storage.supabase.co/storage/v1/s3',
    region: 'us-east-1',
    forcePathStyle: true,
  },
  minio: {
    label: 'MinIO',
    tierNote: 'Self-hosted S3-compatible storage with native webhooks and WORM',
    endpoint: 'https://minio.yourdomain.com:9000',
    region: 'us-east-1',
    forcePathStyle: true,
  },
  'custom-s3': {
    label: 'Custom S3',
    tierNote: 'Any S3-compatible HTTPS endpoint',
    endpoint: 'https://s3.example.com',
    region: 'us-east-1',
    forcePathStyle: true,
  },
};

interface AnchorItem {
  id: string;
  label: string;
  danger?: boolean;
}

const SETTINGS_ANCHORS: AnchorItem[] = [
  { id: 'variables-secrets', label: 'Variables & Secrets' },
  { id: 'storage-connector', label: 'Storage Connector' },
  { id: 'webhooks-containment', label: 'Webhooks & Containment' },
  { id: 'alert-channels', label: 'Alert Channels' },
  { id: 'groq-ai', label: 'AI Analysis' },
  { id: 'buckets-hardening', label: 'Buckets & Hardening' },
  { id: 'allowlists', label: 'Identity Allowlists' },
  { id: 'policy-yaml', label: 'Policy as Code' },
  { id: 'danger-zone', label: 'Danger zone', danger: true },
];

export const SetupView: React.FC = () => {
  const {
    state,
    apiFetch,
    pushToast,
    requestConfirm,
    settingsAnchor,
    clearSettingsAnchor,
    refreshBootstrap,
  } = useConsole();

  const [activeAnchor, setActiveAnchor] = useState<string>('variables-secrets');

  // Groq BYOK state
  const [groqKeyInput, setGroqKeyInput] = useState('');
  const [reasoningEffort, setReasoningEffort] = useState<'low' | 'medium'>('low');
  const [batchSize, setBatchSize] = useState(6);
  const [groqBusy, setGroqBusy] = useState(false);

  // Zero-Card Storage Adapter + Quota-Safe Poller state
  const [provider, setProvider] = useState<StorageProviderPreset>('local');
  const [s3Endpoint, setS3Endpoint] = useState('https://s3.us-west-004.backblazeb2.com');
  const [s3Region, setS3Region] = useState('us-west-004');
  const [forcePathStyle, setForcePathStyle] = useState(false);
  const [productionBucket, setProductionBucket] = useState('finance-prod');
  const [vaultBucket, setVaultBucket] = useState('');
  const [monitorAccessKeyId, setMonitorAccessKeyId] = useState('');
  const [monitorSecretAccessKey, setMonitorSecretAccessKey] = useState('');
  const [vaultAccessKeyId, setVaultAccessKeyId] = useState('');
  const [vaultSecretAccessKey, setVaultSecretAccessKey] = useState('');
  const [pollingEnabled, setPollingEnabled] = useState(false);
  const [pollingIntervalSec, setPollingIntervalSec] = useState(60);
  const [storageBusy, setStorageBusy] = useState(false);
  const [pollBusy, setPollBusy] = useState(false);

  // Authenticated Ingest & Signed Containment Webhook state
  const [revealedToken, setRevealedToken] = useState<string | null>(null);
  const [ingestBusy, setIngestBusy] = useState(false);
  const [containmentUrl, setContainmentUrl] = useState('');
  const [containmentEnabled, setContainmentEnabled] = useState(false);

  // Bucket registration & Auto-Harden
  const [newBucketName, setNewBucketName] = useState('');
  const [newBucketSensitivity, setNewBucketSensitivity] = useState<'critical' | 'sandbox'>(
    'critical',
  );
  const [newBucketSimOnly, setNewBucketSimOnly] = useState(true);
  const [hardenResults, setHardenResults] = useState<Record<string, AutoHardenResult>>({});

  // Allowlist state
  const [newPrincipal, setNewPrincipal] = useState('');
  const [newKmsKey, setNewKmsKey] = useState('');

  // policies.yaml editor
  const [yamlDraft, setYamlDraft] = useState('');
  const [yamlErrors, setYamlErrors] = useState<string[]>([]);
  const [savingYaml, setSavingYaml] = useState(false);

  // Free Zero-Card Alert Destinations
  const [ntfyTopic, setNtfyTopic] = useState('');
  const [discordUrl, setDiscordUrl] = useState('');
  const [slackUrl, setSlackUrl] = useState('');
  const [webhookUrl, setWebhookUrl] = useState('');
  const [alertsEnabled, setAlertsEnabled] = useState(false);
  const [alertBusy, setAlertBusy] = useState(false);

  // Danger zone busy state
  const [dangerBusy, setDangerBusy] = useState(false);

  // Hydrate editable form controls once on initial load so 5s WebSocket heartbeats
  // never overwrite in-progress provider selection or typed credentials/settings.
  const hydratedRef = useRef(false);
  const lastServerYamlRef = useRef<string | null>(null);

  useEffect(() => {
    if (!state) return;

    if (!hydratedRef.current) {
      hydratedRef.current = true;
      setReasoningEffort(state.groq.reasoningEffort);
      setBatchSize(state.groq.canaryBatchSize);

      setProvider(state.storage.provider || 'local');
      setS3Endpoint(state.storage.minioEndpoint || PROVIDER_PRESETS['backblaze-b2'].endpoint);
      setS3Region(state.storage.minioRegion || 'us-west-004');
      setForcePathStyle(Boolean(state.storage.forcePathStyle));
      setProductionBucket(state.storage.productionBucket || 'finance-prod');
      setVaultBucket(state.storage.vaultBucket || '');
      setPollingEnabled(Boolean(state.storage.pollingEnabled));
      setPollingIntervalSec(state.storage.pollingIntervalSec || 60);

      if (state.ingest) {
        setContainmentUrl(state.ingest.containmentWebhookUrl || '');
        setContainmentEnabled(Boolean(state.ingest.containmentWebhookEnabled));
      }

      setNtfyTopic(state.alerts.ntfyTopic || '');
      setDiscordUrl(state.alerts.discordWebhookUrl || '');
      setSlackUrl(state.alerts.slackWebhookUrl || '');
      setWebhookUrl(state.alerts.webhookUrl || '');
      setAlertsEnabled(Boolean(state.alerts.enabled));
    }

    if (lastServerYamlRef.current !== state.policyYaml) {
      lastServerYamlRef.current = state.policyYaml;
      setYamlDraft(state.policyYaml);
    }
  }, [state]);

  // Smooth jump when deep-linked from Overview or top action bar
  useEffect(() => {
    if (!settingsAnchor) return;
    const targetId = settingsAnchor;
    setActiveAnchor(targetId);
    const timer = setTimeout(() => {
      const el = document.getElementById(targetId);
      if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
      clearSettingsAnchor();
    }, 60);
    return () => clearTimeout(timer);
  }, [settingsAnchor, clearSettingsAnchor]);

  // Scroll-spy for the sticky right-hand anchor rail
  useEffect(() => {
    const sections = SETTINGS_ANCHORS.map((a) => document.getElementById(a.id)).filter(
      (el): el is HTMLElement => Boolean(el),
    );
    if (sections.length === 0) return;

    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible[0]?.target.id) {
          setActiveAnchor(visible[0].target.id);
        }
      },
      { rootMargin: '-12% 0px -65% 0px', threshold: 0.05 },
    );

    sections.forEach((sec) => observer.observe(sec));
    return () => observer.disconnect();
  }, [state?.buckets.length]);

  if (!state) return null;

  const scrollToSection = (id: string) => {
    setActiveAnchor(id);
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  const webhookEndpointUrl =
    typeof window !== 'undefined'
      ? `${window.location.origin}/api/ingest/s3-event`
      : 'http://localhost:3000/api/ingest/s3-event';

  const copyText = (text: string, label: string) => {
    void navigator.clipboard.writeText(text).then(() => {
      pushToast({ title: `${label} copied`, tone: 'info' });
    });
  };

  const selectProviderPreset = (next: StorageProviderPreset) => {
    setProvider(next);
    if (next !== 'local') {
      const preset = PROVIDER_PRESETS[next];
      setS3Endpoint(preset.endpoint);
      setS3Region(preset.region);
      setForcePathStyle(preset.forcePathStyle);
    }
  };

  const handleModeToggle = (targetMode: 'active' | 'dry-run') => {
    if (targetMode === state.policy.mode) return;
    if (targetMode === 'active') {
      requestConfirm({
        title: 'Switch to Active Containment Mode?',
        message:
          'In Active mode, DefySwarm automatically revokes compromised credentials and attaches deny-all quarantine policies on P0 triggers and swarm alerts.',
        confirmLabel: 'Enable Active Mode',
        destructive: true,
        onConfirm: async () => {
          await apiFetch('/api/policy/mode', {
            method: 'POST',
            body: JSON.stringify({ mode: 'active' }),
          });
          pushToast({
            title: 'Active Mode Enabled',
            detail: 'Automatic credential revocation and quarantine enforcement active.',
            tone: 'success',
          });
        },
      });
    } else {
      void apiFetch('/api/policy/mode', {
        method: 'POST',
        body: JSON.stringify({ mode: 'dry-run' }),
      })
        .then(() =>
          pushToast({
            title: 'Dry-Run (Shadow) Mode Enabled',
            detail: 'Containment actions will be logged without revoking keys.',
            tone: 'warning',
          }),
        )
        .catch((err) =>
          pushToast({
            title: 'Permission denied',
            detail: err instanceof Error ? err.message : 'Admin role required.',
            tone: 'error',
          }),
        );
    }
  };

  const saveGroqSettings = async (clearKey = false) => {
    setGroqBusy(true);
    try {
      await apiFetch('/api/settings/llm', {
        method: 'POST',
        body: JSON.stringify({
          apiKey: clearKey ? undefined : groqKeyInput.trim() || undefined,
          clearKey,
          reasoningEffort,
          canaryBatchSize: batchSize,
          onboardingCompleted: true,
        }),
      });
      setGroqKeyInput('');
      pushToast({
        title: clearKey ? 'AI API Key Cleared' : 'AI Analysis Settings Saved',
        detail: clearKey
          ? 'Removed key from active session memory.'
          : `Reasoning: ${reasoningEffort} · Canary batch size: ${batchSize}.`,
        tone: 'success',
      });
    } catch (err) {
      pushToast({
        title: 'Could not save AI settings',
        detail: err instanceof Error ? err.message : 'Error',
        tone: 'error',
      });
    } finally {
      setGroqBusy(false);
    }
  };

  const testGroqConnection = async () => {
    setGroqBusy(true);
    try {
      const res = await apiFetch<{ message: string }>('/api/settings/llm/test', {
        method: 'POST',
        body: JSON.stringify({ apiKey: groqKeyInput.trim() || undefined }),
      });
      pushToast({
        title: 'AI Connection Verified',
        detail: res.message,
        tone: 'success',
      });
    } catch (err) {
      pushToast({
        title: 'AI Verification Failed',
        detail: err instanceof Error ? err.message : 'Connection failed.',
        tone: 'error',
      });
    } finally {
      setGroqBusy(false);
    }
  };

  const handleSaveStorage = async (clearCreds = false) => {
    setStorageBusy(true);
    try {
      const res = await apiFetch<{
        storage: { minioConnected: boolean; lastConnectionMessage?: string };
      }>('/api/settings/storage', {
        method: 'POST',
        body: JSON.stringify({
          activeAdapter: provider === 'local' ? 'local' : 'minio',
          provider,
          minioEndpoint: provider === 'local' ? undefined : s3Endpoint.trim(),
          minioRegion: s3Region.trim() || 'us-east-1',
          forcePathStyle,
          productionBucket: productionBucket.trim() || 'finance-prod',
          vaultBucket: vaultBucket.trim(),
          monitorAccessKeyId: clearCreds ? undefined : monitorAccessKeyId.trim() || undefined,
          monitorSecretAccessKey: clearCreds ? undefined : monitorSecretAccessKey.trim() || undefined,
          vaultAccessKeyId: clearCreds ? undefined : vaultAccessKeyId.trim() || undefined,
          vaultSecretAccessKey: clearCreds ? undefined : vaultSecretAccessKey.trim() || undefined,
          clearMonitorCreds: clearCreds,
          clearVaultCreds: clearCreds,
          pollingEnabled: provider === 'local' ? false : pollingEnabled,
          pollingIntervalSec,
        }),
      });
      setMonitorAccessKeyId('');
      setMonitorSecretAccessKey('');
      setVaultAccessKeyId('');
      setVaultSecretAccessKey('');
      pushToast({
        title: clearCreds
          ? 'S3 Credentials Cleared'
          : res.storage.minioConnected || provider === 'local'
            ? 'Storage Adapter Verified'
            : 'Connection Failed — Fallback Active',
        detail: res.storage.lastConnectionMessage,
        tone: res.storage.minioConnected || provider === 'local' ? 'success' : 'warning',
      });
    } catch (err) {
      pushToast({
        title: 'Storage update failed',
        detail: err instanceof Error ? err.message : 'Error',
        tone: 'error',
      });
    } finally {
      setStorageBusy(false);
    }
  };

  const handlePollNow = async () => {
    setPollBusy(true);
    try {
      const res = await apiFetch<{ changedCount: number; apiCallsToday: number }>(
        '/api/ingest/poll-now',
        { method: 'POST' },
      );
      pushToast({
        title: 'External S3 Sync Complete',
        detail: `${res.changedCount} changed object(s) inspected · ${res.apiCallsToday} API calls today.`,
        tone: res.changedCount > 0 ? 'warning' : 'success',
      });
    } catch (err) {
      pushToast({
        title: 'Sync failed',
        detail: err instanceof Error ? err.message : 'Connect an external S3 bucket first.',
        tone: 'error',
      });
    } finally {
      setPollBusy(false);
    }
  };

  const handleRevealToken = async () => {
    if (revealedToken) {
      setRevealedToken(null);
      return;
    }
    setIngestBusy(true);
    try {
      const res = await apiFetch<{ token: string }>('/api/settings/ingest/reveal', {
        method: 'POST',
      });
      setRevealedToken(res.token);
    } catch (err) {
      pushToast({
        title: 'Admin role required',
        detail: err instanceof Error ? err.message : 'Switch to Admin to reveal token.',
        tone: 'error',
      });
    } finally {
      setIngestBusy(false);
    }
  };

  const handleRotateToken = async () => {
    setIngestBusy(true);
    try {
      const res = await apiFetch<{ token: string }>('/api/settings/ingest/rotate', {
        method: 'POST',
      });
      setRevealedToken(res.token);
      pushToast({
        title: 'Ingest Token Rotated',
        detail: 'Update your MinIO webhook and CLI scripts with the new secret.',
        tone: 'success',
      });
    } catch (err) {
      pushToast({
        title: 'Rotate failed',
        detail: err instanceof Error ? err.message : 'Admin role required.',
        tone: 'error',
      });
    } finally {
      setIngestBusy(false);
    }
  };

  const handleTestWebhook = async () => {
    setIngestBusy(true);
    try {
      const res = await apiFetch<{ processed: number }>('/api/settings/ingest/test', {
        method: 'POST',
        body: JSON.stringify({ bucket: productionBucket || 'finance-prod' }),
      });
      pushToast({
        title: 'Webhook Pipeline Verified',
        detail: `Processed ${res.processed} synthetic S3:ObjectCreated event into Observability.`,
        tone: 'success',
      });
    } catch (err) {
      pushToast({
        title: 'Webhook self-test failed',
        detail: err instanceof Error ? err.message : 'Error',
        tone: 'error',
      });
    } finally {
      setIngestBusy(false);
    }
  };

  const handleSaveContainment = async () => {
    setIngestBusy(true);
    try {
      await apiFetch('/api/settings/containment', {
        method: 'POST',
        body: JSON.stringify({
          containmentWebhookUrl: containmentUrl.trim(),
          containmentWebhookEnabled: containmentEnabled,
        }),
      });
      pushToast({
        title: 'Signed Containment Webhook Saved',
        detail: containmentEnabled
          ? 'P0 revocations will dispatch HMAC-SHA256 signed actions.'
          : 'Saved in disabled state.',
        tone: 'success',
      });
    } catch (err) {
      pushToast({
        title: 'Containment URL rejected',
        detail: err instanceof Error ? err.message : 'Error',
        tone: 'error',
      });
    } finally {
      setIngestBusy(false);
    }
  };

  const handleRegisterBucket = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newBucketName.trim()) return;
    try {
      await apiFetch('/api/buckets', {
        method: 'POST',
        body: JSON.stringify({
          name: newBucketName.trim(),
          sensitivity: newBucketSensitivity,
          simOnly: newBucketSimOnly,
          vault: 'vault-finance',
        }),
      });
      setNewBucketName('');
      pushToast({
        title: 'Bucket Registered',
        detail: `Added ${newBucketName.trim()} to policies.yaml.`,
        tone: 'success',
      });
    } catch (err) {
      pushToast({
        title: 'Could not register bucket',
        detail: err instanceof Error ? err.message : 'Error',
        tone: 'error',
      });
    }
  };

  const handleAutoHarden = async (bucketName: string) => {
    try {
      const res = await apiFetch<AutoHardenResult>(`/api/buckets/${bucketName}/harden`, {
        method: 'POST',
      });
      setHardenResults((prev) => ({ ...prev, [bucketName]: res }));
      pushToast({
        title: `Auto-Harden: ${bucketName}`,
        detail: res.allPassed
          ? 'All 4 posture checks passed (Versioning, WORM Vault, Audit, Canaries).'
          : 'Some checks require attention.',
        tone: res.allPassed ? 'success' : 'warning',
      });
    } catch (err) {
      pushToast({
        title: 'Auto-Harden failed',
        detail: err instanceof Error ? err.message : 'Error',
        tone: 'error',
      });
    }
  };

  const updateAllowlist = async (principals: string[], kmsKeys: string[]) => {
    try {
      await apiFetch('/api/policy/allowlist', {
        method: 'POST',
        body: JSON.stringify({ principals, kmsKeys }),
      });
      pushToast({ title: 'Allowlist Updated', tone: 'success' });
    } catch (err) {
      pushToast({
        title: 'Allowlist update denied',
        detail: err instanceof Error ? err.message : 'Admin role required.',
        tone: 'error',
      });
    }
  };

  const handleSavePolicyYaml = async () => {
    setSavingYaml(true);
    setYamlErrors([]);
    try {
      await apiFetch('/api/policy', {
        method: 'PUT',
        body: JSON.stringify({ yaml: yamlDraft }),
      });
      pushToast({
        title: 'policies.yaml Validated & Saved',
        detail: 'Strict schema check passed with 0 unknown keys.',
        tone: 'success',
      });
    } catch (err) {
      const details = (err as Error & { details?: string[] }).details;
      setYamlErrors(
        details && details.length > 0
          ? details
          : [err instanceof Error ? err.message : 'Invalid YAML'],
      );
    } finally {
      setSavingYaml(false);
    }
  };

  const handleSaveAlerts = async () => {
    setAlertBusy(true);
    try {
      await apiFetch('/api/settings/alerts', {
        method: 'POST',
        body: JSON.stringify({
          ntfyTopic: ntfyTopic.trim(),
          discordWebhookUrl: discordUrl.trim(),
          slackWebhookUrl: slackUrl.trim(),
          webhookUrl: webhookUrl.trim(),
          enabled: alertsEnabled,
        }),
      });
      pushToast({
        title: 'Alert Destinations Saved',
        detail: alertsEnabled ? 'Outbound P0 alerts armed.' : 'Saved in disabled state.',
        tone: 'success',
      });
    } catch (err) {
      pushToast({
        title: 'Alert configuration rejected',
        detail: err instanceof Error ? err.message : 'Error',
        tone: 'error',
      });
    } finally {
      setAlertBusy(false);
    }
  };

  const handleSendTestAlert = async () => {
    setAlertBusy(true);
    try {
      const res = await apiFetch<{ delivered: number; channels: string[] }>(
        '/api/settings/alerts/test',
        { method: 'POST' },
      );
      pushToast({
        title: `Test Alert Sent (${res.delivered})`,
        detail: `Delivered to: ${res.channels.join(', ')}.`,
        tone: 'success',
      });
    } catch (err) {
      pushToast({
        title: 'Test Alert Failed',
        detail: err instanceof Error ? err.message : 'Save an ntfy topic or webhook URL first.',
        tone: 'error',
      });
    } finally {
      setAlertBusy(false);
    }
  };

  const handleClearAllSecrets = () => {
    requestConfirm({
      title: 'Clear Integration Credentials?',
      message:
        'This immediately removes your AI provider key and external S3 monitor/vault credentials from active session memory and reverts storage to Local Sandbox.',
      confirmLabel: 'Clear Credentials',
      destructive: true,
      onConfirm: async () => {
        setDangerBusy(true);
        try {
          await apiFetch('/api/settings/llm', {
            method: 'POST',
            body: JSON.stringify({ clearKey: true }),
          });
          await apiFetch('/api/settings/storage', {
            method: 'POST',
            body: JSON.stringify({
              activeAdapter: 'local',
              provider: 'local',
              clearMonitorCreds: true,
              clearVaultCreds: true,
              pollingEnabled: false,
            }),
          });
          setProvider('local');
          setPollingEnabled(false);
          pushToast({
            title: 'Integration Credentials Cleared',
            detail: 'AI provider and external S3 credentials removed from session memory.',
            tone: 'success',
          });
        } finally {
          setDangerBusy(false);
        }
      },
    });
  };

  const handleResetDemo = () => {
    requestConfirm({
      title: 'Reset DefySwarm Workspace?',
      message:
        'Resets all local buckets, principals, telemetry events, incidents, and vault snapshots back to a clean baseline state.',
      confirmLabel: 'Reset Workspace',
      destructive: true,
      onConfirm: async () => {
        setDangerBusy(true);
        try {
          await apiFetch('/api/simulator/reset', { method: 'POST' });
          await refreshBootstrap();
          pushToast({
            title: 'Workspace Reset Complete',
            detail: 'Clean buckets, principals, and vault manifests restored.',
            tone: 'success',
          });
        } finally {
          setDangerBusy(false);
        }
      },
    });
  };

  const q = state.groq.quota;
  const activePresetMeta = PROVIDER_PRESETS[provider];

  const envRows: Array<{
    type: 'Secret' | 'Variable';
    name: string;
    configured?: boolean;
    value?: string;
    sectionId: string;
    onClear?: () => void;
    onRotate?: () => void;
  }> = [
    {
      type: 'Secret',
      name: 'GROQ_API_KEY',
      configured: state.groq.configured,
      sectionId: 'groq-ai',
      onClear:
        state.groq.configured && state.groq.source === 'byok'
          ? () => void saveGroqSettings(true)
          : undefined,
    },
    {
      type: 'Secret',
      name: 'S3_ACCESS_KEY_ID',
      configured: state.storage.minioMonitorConfigured,
      sectionId: 'storage-connector',
      onClear: state.storage.minioMonitorConfigured ? () => void handleSaveStorage(true) : undefined,
    },
    {
      type: 'Secret',
      name: 'S3_SECRET_ACCESS_KEY',
      configured: state.storage.minioMonitorConfigured,
      sectionId: 'storage-connector',
      onClear: state.storage.minioMonitorConfigured ? () => void handleSaveStorage(true) : undefined,
    },
    {
      type: 'Secret',
      name: 'S3_VAULT_ACCESS_KEY_ID',
      configured: state.storage.minioVaultConfigured,
      sectionId: 'storage-connector',
    },
    {
      type: 'Secret',
      name: 'DEFYSWARM_INGEST_TOKEN',
      configured: Boolean(state.ingest?.tokenMasked),
      sectionId: 'webhooks-containment',
      onRotate: () => void handleRotateToken(),
    },
    {
      type: 'Variable',
      name: 'STORAGE_PROVIDER',
      value: state.storage.provider || 'local',
      sectionId: 'storage-connector',
    },
    {
      type: 'Variable',
      name: 'S3_PRODUCTION_BUCKET',
      value: state.storage.productionBucket || 'finance-prod',
      sectionId: 'storage-connector',
    },
    {
      type: 'Variable',
      name: 'LLM_MODEL',
      value: state.groq.model,
      sectionId: 'groq-ai',
    },
    {
      type: 'Variable',
      name: 'NTFY_TOPIC',
      value: state.alerts.ntfyTopic || '— (not set)',
      sectionId: 'alert-channels',
    },
    {
      type: 'Variable',
      name: 'ENFORCEMENT_MODE',
      value: state.policy.mode,
      sectionId: 'policy-yaml',
    },
  ];

  return (
    <div className="mx-auto max-w-[1380px] px-4 py-6 sm:px-6">
      {/* Top Page Title & Enforcement Mode Switcher */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#E5E7EB] pb-5">
        <div>
          <h1 className="type-page-title">
            Settings
          </h1>
          <p className="mt-1.5 text-[13px] text-[#6B7280]">
            Manage runtime variables, S3 storage bindings, webhooks, alert destinations, AI
            analysis, and <span className="font-mono text-[12px] text-[#374151]">policies.yaml</span>.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <span className="text-[12px] font-medium text-[#6B7280]">Enforcement</span>
          <div className="flex items-center rounded-[8px] border border-[#E5E7EB]/80 bg-[#F2F4F7] p-0.5">
            <button
              type="button"
              onClick={() => handleModeToggle('dry-run')}
              className={`rounded-[6px] px-2.5 py-1 text-[12px] font-medium transition-colors whitespace-nowrap shrink-0 ${
                state.policy.mode === 'dry-run'
                  ? 'segmented-thumb-shadow bg-white text-[#B45309]'
                  : 'text-[#6B7280] hover:text-[#111827]'
              }`}
            >
              Dry-Run (Shadow)
            </button>
            <button
              type="button"
              onClick={() => handleModeToggle('active')}
              className={`rounded-[6px] px-2.5 py-1 text-[12px] font-medium transition-colors whitespace-nowrap shrink-0 ${
                state.policy.mode === 'active'
                  ? 'segmented-thumb-shadow bg-white text-[#15803D]'
                  : 'text-[#6B7280] hover:text-[#111827]'
              }`}
            >
              Active Containment
            </button>
          </div>
        </div>
      </div>

      {/* Main Content + Sticky Right Anchor Rail */}
      <div className="mt-6 lg:grid lg:grid-cols-[minmax(0,1fr)_208px] lg:gap-8">
        <div className="space-y-6">
          {/* 1. Variables & Secrets Table */}
          <section
            id="variables-secrets"
            className="surface-card scroll-mt-16 overflow-hidden"
          >
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#E5E7EB] bg-[#F8F9FA] px-5 py-3">
              <div>
                <h2 className="type-section text-[14.5px]">Variables and Secrets</h2>
                <p className="mt-0.5 text-[12px] text-[#6B7280]">
                  Credentials are held in ephemeral runtime memory and are never written to disk or
                  browser storage.
                </p>
              </div>
              <button
                type="button"
                onClick={() => scrollToSection('storage-connector')}
                className="inline-flex h-[30px] items-center gap-1.5 rounded-[7px] border border-[#D1D5DB] bg-white px-3 text-[12px] font-medium text-[#374151] transition-colors hover:bg-[#F8F9FA] whitespace-nowrap shrink-0"
              >
                <Plus className="h-3.5 w-3.5" />
                Add or edit binding
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full min-w-[580px] border-collapse text-left text-[12.5px]">
                <thead className="kumo-table-head">
                  <tr className="h-[36px] type-caption text-[#6B7280]">
                    <th className="w-[110px] pl-5 pr-3 font-medium">Type</th>
                    <th className="w-[240px] pr-3 font-medium">Name</th>
                    <th className="pr-3 font-medium">Value</th>
                    <th className="w-[92px] pr-5 text-right font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#EEF0F2]">
                  {envRows.map((row, idx) => (
                    <tr
                      key={row.name}
                      className={`h-[40px] transition-colors hover:bg-[#F4F6F9] ${
                        idx % 2 === 1 ? 'bg-[#FAFBFD]' : 'bg-white'
                      }`}
                    >
                      <td className="pl-5 pr-3 text-[12px] text-[#4B5563]">
                        <span className="inline-flex items-center gap-1.5">
                          {row.type === 'Secret' ? (
                            <Lock className="h-3 w-3 text-[#6B7280]" />
                          ) : (
                            <span className="inline-block h-1.5 w-1.5 rounded-full bg-[#1D6CF0]" />
                          )}
                          {row.type}
                        </span>
                      </td>
                      <td className="pr-3 font-mono text-[12px] font-medium text-[#111827]">
                        {row.name}
                      </td>
                      <td className="pr-3 text-[12px]">
                        {row.type === 'Secret' ? (
                          row.configured ? (
                            <span className="italic text-[#6B7280]">Value encrypted</span>
                          ) : (
                            <span className="text-[#9CA3AF]">Not configured</span>
                          )
                        ) : (
                          <span className="font-mono text-[#374151]">{row.value}</span>
                        )}
                      </td>
                      <td className="pr-5 text-right">
                        <div className="inline-flex items-center justify-end gap-1">
                          <button
                            type="button"
                            onClick={() => scrollToSection(row.sectionId)}
                            className="rounded p-1.5 text-[#6B7280] hover:bg-[#E5E7EB]/60 hover:text-[#111827]"
                            title={`Edit ${row.name}`}
                            aria-label={`Edit ${row.name}`}
                          >
                            <Pencil className="h-3.5 w-3.5" />
                          </button>
                          {row.onRotate && (
                            <button
                              type="button"
                              onClick={row.onRotate}
                              className="rounded p-1.5 text-[#6B7280] hover:bg-[#E5E7EB]/60 hover:text-[#1D6CF0]"
                              title={`Rotate ${row.name}`}
                              aria-label={`Rotate ${row.name}`}
                            >
                              <RotateCw className="h-3.5 w-3.5" />
                            </button>
                          )}
                          {row.onClear && (
                            <button
                              type="button"
                              onClick={row.onClear}
                              className="rounded p-1.5 text-[#6B7280] hover:bg-[#FEF2F2] hover:text-[#DC2626]"
                              title={`Clear ${row.name}`}
                              aria-label={`Clear ${row.name}`}
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          {/* 2. Storage Connector */}
          <section
            id="storage-connector"
            className="surface-card scroll-mt-16 overflow-hidden"
          >
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#E5E7EB] bg-[#F8F9FA] px-5 py-3">
              <div className="flex items-center gap-2">
                <Server className="h-4 w-4 text-[#1D6CF0]" />
                <h2 className="type-section text-[14.5px]">
                  Storage Connector
                </h2>
              </div>
              <span
                className={`inline-flex items-center gap-1.5 text-[12px] font-medium ${
                  state.storage.minioConnected || state.storage.provider === 'local'
                    ? 'text-[#15803D]'
                    : 'text-[#B45309]'
                }`}
              >
                <span
                  className={`h-1.5 w-1.5 rounded-full ${
                    state.storage.minioConnected || state.storage.provider === 'local'
                      ? 'bg-[#16A34A]'
                      : 'bg-[#D97706]'
                  }`}
                />
                {PROVIDER_PRESETS[state.storage.provider]?.label ?? state.storage.provider} ·{' '}
                {state.storage.minioConnected ? 'Connected' : 'Local'}
              </span>
            </div>

            <div className="space-y-4 p-5">
              <p className="text-[12.5px] text-[#4B5563]">{state.storage.lastConnectionMessage}</p>

              {/* Provider Preset Selector */}
              <div>
                <label className="block text-[12px] font-medium text-[#374151]">
                  Storage Provider
                </label>
                <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-5">
                  {(Object.keys(PROVIDER_PRESETS) as StorageProviderPreset[]).map((key) => (
                    <button
                      key={key}
                      type="button"
                      onClick={() => selectProviderPreset(key)}
                      className={`rounded-[7px] border px-2.5 py-2 text-center type-control text-[12px] transition-colors ${
                        provider === key
                          ? 'border-[#1D6CF0] bg-[#EFF6FF] font-semibold text-[#1D6CF0]'
                          : 'border-[#E5E7EB] bg-white text-[#4B5563] hover:border-[#D1D5DB] hover:bg-[#F8F9FA] hover:text-[#111827]'
                      }`}
                    >
                      {PROVIDER_PRESETS[key].label}
                    </button>
                  ))}
                </div>
                <p className="mt-2 text-[12px] text-[#4B5563]">
                  {activePresetMeta.tierNote}
                </p>
              </div>

              {provider !== 'local' && (
                <div className="space-y-3.5 border-t border-[#E5E7EB] pt-4">
                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                    <div className="sm:col-span-2">
                      <label className="block text-[11.5px] font-medium text-[#374151]">
                        S3 Endpoint URL (HTTPS)
                      </label>
                      <input
                        type="url"
                        value={s3Endpoint}
                        onChange={(e) => setS3Endpoint(e.target.value)}
                        placeholder={activePresetMeta.endpoint}
                        className="mt-1 h-[34px] w-full rounded-md border border-[#D1D5DB] bg-white px-3 font-mono text-[12px] text-[#111827] placeholder:text-[#9CA3AF] focus:border-[#1D6CF0] focus:outline-none"
                      />
                    </div>
                    <div>
                      <label className="block text-[11.5px] font-medium text-[#374151]">
                        Region
                      </label>
                      <input
                        type="text"
                        value={s3Region}
                        onChange={(e) => setS3Region(e.target.value)}
                        placeholder="us-west-004"
                        className="mt-1 h-[34px] w-full rounded-md border border-[#D1D5DB] bg-white px-3 font-mono text-[12px] text-[#111827] placeholder:text-[#9CA3AF] focus:border-[#1D6CF0] focus:outline-none"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                    <div>
                      <label className="block text-[11.5px] font-medium text-[#374151]">
                        Production Bucket Name
                      </label>
                      <input
                        type="text"
                        value={productionBucket}
                        onChange={(e) => setProductionBucket(e.target.value)}
                        placeholder="my-b2-or-supabase-bucket"
                        className="mt-1 h-[34px] w-full rounded-md border border-[#D1D5DB] bg-white px-3 font-mono text-[12px] text-[#111827] placeholder:text-[#9CA3AF] focus:border-[#1D6CF0] focus:outline-none"
                      />
                    </div>
                    <div>
                      <label className="block text-[11.5px] font-medium text-[#374151]">
                        WORM Vault Bucket (Optional)
                      </label>
                      <input
                        type="text"
                        value={vaultBucket}
                        onChange={(e) => setVaultBucket(e.target.value)}
                        placeholder="my-worm-vault-bucket"
                        className="mt-1 h-[34px] w-full rounded-md border border-[#D1D5DB] bg-white px-3 font-mono text-[12px] text-[#111827] placeholder:text-[#9CA3AF] focus:border-[#1D6CF0] focus:outline-none"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                    <div>
                      <label className="block text-[11.5px] font-medium text-[#374151]">
                        Monitor Access Key ID{' '}
                        {state.storage.minioMonitorConfigured && (
                          <span className="text-[11.5px] text-[#16A34A]">(Configured)</span>
                        )}
                      </label>
                      <input
                        type="text"
                        autoComplete="off"
                        value={monitorAccessKeyId}
                        onChange={(e) => setMonitorAccessKeyId(e.target.value)}
                        placeholder={
                          state.storage.minioMonitorConfigured
                            ? '•••••••• (configured)'
                            : 'keyID / access key'
                        }
                        className="mt-1 h-[34px] w-full rounded-md border border-[#D1D5DB] bg-white px-3 font-mono text-[12px] text-[#111827] placeholder:text-[#9CA3AF] focus:border-[#1D6CF0] focus:outline-none"
                      />
                    </div>
                    <div>
                      <label className="block text-[11.5px] font-medium text-[#374151]">
                        Monitor Secret Access Key
                      </label>
                      <input
                        type="password"
                        autoComplete="off"
                        value={monitorSecretAccessKey}
                        onChange={(e) => setMonitorSecretAccessKey(e.target.value)}
                        placeholder={
                          state.storage.minioMonitorConfigured
                            ? '•••••••• (configured)'
                            : 'applicationKey / secret'
                        }
                        className="mt-1 h-[34px] w-full rounded-md border border-[#D1D5DB] bg-white px-3 font-mono text-[12px] text-[#111827] placeholder:text-[#9CA3AF] focus:border-[#1D6CF0] focus:outline-none"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                    <div>
                      <label className="block text-[11.5px] font-medium text-[#374151]">
                        Isolated Vault Key ID (Optional){' '}
                        {state.storage.minioVaultConfigured && (
                          <span className="text-[11.5px] text-[#16A34A]">(Configured)</span>
                        )}
                      </label>
                      <input
                        type="text"
                        autoComplete="off"
                        value={vaultAccessKeyId}
                        onChange={(e) => setVaultAccessKeyId(e.target.value)}
                        placeholder="Separate vault keyID"
                        className="mt-1 h-[34px] w-full rounded-md border border-[#D1D5DB] bg-white px-3 font-mono text-[12px] text-[#111827] placeholder:text-[#9CA3AF] focus:border-[#1D6CF0] focus:outline-none"
                      />
                    </div>
                    <div>
                      <label className="block text-[11.5px] font-medium text-[#374151]">
                        Isolated Vault Secret Key
                      </label>
                      <input
                        type="password"
                        autoComplete="off"
                        value={vaultSecretAccessKey}
                        onChange={(e) => setVaultSecretAccessKey(e.target.value)}
                        placeholder="Separate vault secret"
                        className="mt-1 h-[34px] w-full rounded-md border border-[#D1D5DB] bg-white px-3 font-mono text-[12px] text-[#111827] placeholder:text-[#9CA3AF] focus:border-[#1D6CF0] focus:outline-none"
                      />
                    </div>
                  </div>

                  {/* Change Poller & Path Style Strip */}
                  <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-[#E5E7EB] bg-[#F9FAFB] px-3.5 py-2.5">
                    <div className="flex flex-wrap items-center gap-4">
                      <label className="flex items-center gap-2 text-[12px] font-medium text-[#111827]">
                        <input
                          type="checkbox"
                          checked={pollingEnabled}
                          onChange={(e) => setPollingEnabled(e.target.checked)}
                          className="accent-[#1D6CF0]"
                        />
                        Bucket Change Poller
                      </label>
                      <select
                        value={pollingIntervalSec}
                        onChange={(e) => setPollingIntervalSec(Number(e.target.value))}
                        className="h-[28px] rounded border border-[#D1D5DB] bg-white px-2 text-[12px] text-[#111827] tabular-nums"
                      >
                        <option value={30}>30s</option>
                        <option value={60}>60s (Recommended)</option>
                        <option value={300}>300s (Low Frequency)</option>
                      </select>
                      <label className="flex items-center gap-2 text-[12px] text-[#4B5563]">
                        <input
                          type="checkbox"
                          checked={forcePathStyle}
                          onChange={(e) => setForcePathStyle(e.target.checked)}
                          className="accent-[#1D6CF0]"
                        />
                        Force Path-Style
                      </label>
                    </div>

                    <div className="flex items-center gap-2.5 text-[12px] text-[#6B7280] tabular-nums">
                      <span>Calls today: {state.storage.apiCallsToday ?? 0}</span>
                      {state.storage.minioConnected && (
                        <button
                          type="button"
                          disabled={pollBusy}
                          onClick={handlePollNow}
                          className="inline-flex h-[26px] items-center gap-1 rounded border border-[#D1D5DB] bg-white px-2.5 text-[11.5px] font-medium text-[#374151] hover:bg-[#F9FAFB]"
                        >
                          <RefreshCw className={`h-3 w-3 ${pollBusy ? 'animate-spin' : ''}`} />
                          Sync Now
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              )}

              <div className="flex flex-wrap items-center justify-end gap-2 pt-1">
                {(state.storage.minioMonitorConfigured || state.storage.minioVaultConfigured) && (
                  <button
                    type="button"
                    disabled={storageBusy}
                    onClick={() => handleSaveStorage(true)}
                    className="h-[32px] rounded-md border border-[#FECACA] bg-[#FEF2F2] px-3 text-[12.5px] font-medium text-[#DC2626] hover:bg-[#FEE2E2] transition-colors"
                  >
                    Clear S3 Credentials
                  </button>
                )}
                <button
                  type="button"
                  disabled={storageBusy}
                  onClick={() => handleSaveStorage(false)}
                  className="h-[32px] rounded-md bg-[#1D6CF0] px-4 text-[12.5px] font-medium text-white hover:bg-[#1558D6] transition-colors disabled:opacity-50"
                >
                  {storageBusy
                    ? 'Verifying S3 Bucket…'
                    : provider === 'local'
                      ? 'Use Local Sandbox'
                      : 'Verify & Connect Bucket'}
                </button>
              </div>
            </div>
          </section>

          {/* 3. Webhooks & Containment */}
          <section
            id="webhooks-containment"
            className="scroll-mt-6 overflow-hidden rounded-lg border border-[#E5E7EB] bg-white"
          >
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#E5E7EB] bg-[#F9FAFB] px-5 py-3">
              <div className="flex items-center gap-2">
                <Webhook className="h-4 w-4 text-[#1D6CF0]" />
                <h2 className="text-[14px] font-semibold text-[#111827]">
                  Webhooks &amp; Containment
                </h2>
              </div>
              <span className="text-[12px] text-[#6B7280] tabular-nums">
                {state.ingest?.webhookEventsReceived ?? 0} webhooks ·{' '}
                {state.ingest?.directUploadsProcessed ?? 0} uploads ·{' '}
                {state.ingest?.polledDiffsDetected ?? 0} polled
              </span>
            </div>

            <div className="space-y-4 p-5">
              <div>
                <label className="block text-[11.5px] font-medium text-[#374151]">
                  S3 / MinIO Event Webhook URL
                </label>
                <div className="mt-1 flex items-center gap-2">
                  <input
                    type="text"
                    readOnly
                    value={webhookEndpointUrl}
                    className="h-[34px] flex-1 rounded-md border border-[#E5E7EB] bg-[#F9FAFB] px-3 font-mono text-[12px] text-[#111827]"
                  />
                  <button
                    type="button"
                    onClick={() => copyText(webhookEndpointUrl, 'Webhook URL')}
                    className="inline-flex h-[34px] items-center gap-1.5 rounded-md border border-[#D1D5DB] bg-white px-3 text-[12px] font-medium text-[#374151] hover:bg-[#F9FAFB]"
                  >
                    <Copy className="h-3.5 w-3.5" />
                    Copy
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-[11.5px] font-medium text-[#374151]">
                  Ingest Bearer / HMAC Secret
                </label>
                <div className="mt-1 flex flex-wrap items-center gap-2">
                  <div className="flex h-[34px] min-w-[180px] flex-1 items-center truncate rounded-md border border-[#E5E7EB] bg-[#F9FAFB] px-3 font-mono text-[12px] text-[#111827]">
                    {revealedToken || state.ingest?.tokenMasked || '••••••••'}
                  </div>
                  <button
                    type="button"
                    disabled={ingestBusy}
                    onClick={handleRevealToken}
                    className="inline-flex h-[34px] items-center gap-1.5 rounded-md border border-[#D1D5DB] bg-white px-3 text-[12px] font-medium text-[#374151] hover:bg-[#F9FAFB]"
                  >
                    {revealedToken ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                    {revealedToken ? 'Hide' : 'Reveal'}
                  </button>
                  {revealedToken && (
                    <button
                      type="button"
                      onClick={() => copyText(revealedToken, 'Ingest Token')}
                      className="inline-flex h-[34px] items-center gap-1 rounded-md border border-[#D1D5DB] bg-white px-2.5 text-[12px] text-[#374151] hover:bg-[#F9FAFB]"
                      aria-label="Copy Ingest Token"
                    >
                      <Copy className="h-3.5 w-3.5" />
                    </button>
                  )}
                  <button
                    type="button"
                    disabled={ingestBusy}
                    onClick={handleRotateToken}
                    className="inline-flex h-[34px] items-center gap-1.5 rounded-md border border-[#D1D5DB] bg-white px-3 text-[12px] font-medium text-[#374151] hover:bg-[#F9FAFB]"
                  >
                    <RotateCw className="h-3.5 w-3.5" />
                    Rotate
                  </button>
                  <button
                    type="button"
                    disabled={ingestBusy}
                    onClick={handleTestWebhook}
                    className="inline-flex h-[34px] items-center gap-1.5 rounded-md border border-[#BFDBFE] bg-[#EFF6FF] px-3 text-[12px] font-medium text-[#1D6CF0] hover:bg-[#DBEAFE]"
                  >
                    <Send className="h-3.5 w-3.5" />
                    Test Webhook
                  </button>
                </div>
              </div>

              <div className="border-t border-[#E5E7EB] pt-4">
                <label className="block text-[11.5px] font-medium text-[#374151]">
                  Signed External Containment Webhook (HMAC-SHA256)
                </label>
                <p className="mt-0.5 text-[12px] text-[#6B7280]">
                  Fires signed <span className="font-mono text-[#374151]">REVOKE_PRINCIPAL</span>{' '}
                  payloads on P0 containment (e.g. to run MinIO{' '}
                  <span className="font-mono text-[#374151]">mc admin policy</span> scripts).
                </p>
                <div className="mt-2 flex flex-wrap items-center gap-2.5">
                  <input
                    type="url"
                    value={containmentUrl}
                    onChange={(e) => setContainmentUrl(e.target.value)}
                    placeholder="https://your-containment-hook.example.com/revoke"
                    className="h-[34px] min-w-[220px] flex-1 rounded-md border border-[#D1D5DB] bg-white px-3 font-mono text-[12px] text-[#111827] placeholder:text-[#9CA3AF] focus:border-[#1D6CF0] focus:outline-none"
                  />
                  <label className="flex items-center gap-1.5 text-[12.5px] text-[#374151]">
                    <input
                      type="checkbox"
                      checked={containmentEnabled}
                      onChange={(e) => setContainmentEnabled(e.target.checked)}
                      className="accent-[#1D6CF0]"
                    />
                    Armed
                  </label>
                  <button
                    type="button"
                    disabled={ingestBusy}
                    onClick={handleSaveContainment}
                    className="h-[34px] rounded-md border border-[#D1D5DB] bg-white px-3.5 text-[12.5px] font-medium text-[#374151] hover:bg-[#F9FAFB]"
                  >
                    Save Hook
                  </button>
                </div>
              </div>
            </div>
          </section>

          {/* 4. Alert Destinations */}
          <section
            id="alert-channels"
            className="scroll-mt-6 overflow-hidden rounded-lg border border-[#E5E7EB] bg-white"
          >
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#E5E7EB] bg-[#F9FAFB] px-5 py-3">
              <div className="flex items-center gap-2">
                <Bell className="h-4 w-4 text-[#1D6CF0]" />
                <h2 className="text-[14px] font-semibold text-[#111827]">
                  Alert Destinations
                </h2>
              </div>
              <span className="text-[12px] text-[#6B7280] tabular-nums">
                {alertsEnabled ? 'Armed' : 'Disabled'} · {state.alerts.deliveredCount} delivered
              </span>
            </div>

            <div className="space-y-3.5 p-5">
              <div>
                <label className="block text-[11.5px] font-medium text-[#374151]">
                  ntfy Push Topic
                </label>
                <div className="mt-1 flex items-center gap-2">
                  <span className="font-mono text-[12px] text-[#6B7280]">https://ntfy.sh/</span>
                  <input
                    type="text"
                    value={ntfyTopic}
                    onChange={(e) => setNtfyTopic(e.target.value)}
                    placeholder="defyswarm-ops-your-secret-topic"
                    className="h-[34px] flex-1 rounded-md border border-[#D1D5DB] bg-white px-3 font-mono text-[12px] text-[#111827] placeholder:text-[#9CA3AF] focus:border-[#1D6CF0] focus:outline-none"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div>
                  <label className="block text-[11.5px] font-medium text-[#374151]">
                    Discord Webhook URL
                  </label>
                  <input
                    type="url"
                    value={discordUrl}
                    onChange={(e) => setDiscordUrl(e.target.value)}
                    placeholder="https://discord.com/api/webhooks/..."
                    className="mt-1 h-[34px] w-full rounded-md border border-[#D1D5DB] bg-white px-3 font-mono text-[12px] text-[#111827] placeholder:text-[#9CA3AF] focus:border-[#1D6CF0] focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-[11.5px] font-medium text-[#374151]">
                    Slack Webhook URL
                  </label>
                  <input
                    type="url"
                    value={slackUrl}
                    onChange={(e) => setSlackUrl(e.target.value)}
                    placeholder="https://hooks.slack.com/services/..."
                    className="mt-1 h-[34px] w-full rounded-md border border-[#D1D5DB] bg-white px-3 font-mono text-[12px] text-[#111827] placeholder:text-[#9CA3AF] focus:border-[#1D6CF0] focus:outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="block text-[11.5px] font-medium text-[#374151]">
                  Custom SIEM / JSON Webhook URL (Optional)
                </label>
                <input
                  type="url"
                  value={webhookUrl}
                  onChange={(e) => setWebhookUrl(e.target.value)}
                  placeholder="https://siem.example.com/ingest"
                  className="mt-1 h-[34px] w-full rounded-md border border-[#D1D5DB] bg-white px-3 font-mono text-[12px] text-[#111827] placeholder:text-[#9CA3AF] focus:border-[#1D6CF0] focus:outline-none"
                />
              </div>

              <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
                <label className="flex items-center gap-2 text-[12.5px] text-[#374151]">
                  <input
                    type="checkbox"
                    checked={alertsEnabled}
                    onChange={(e) => setAlertsEnabled(e.target.checked)}
                    className="accent-[#1D6CF0]"
                  />
                  Enable real-time P0 &amp; swarm alerts
                </label>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    disabled={alertBusy}
                    onClick={handleSendTestAlert}
                    className="inline-flex h-[32px] items-center gap-1.5 rounded-md border border-[#D1D5DB] bg-white px-3 text-[12px] font-medium text-[#374151] hover:bg-[#F9FAFB]"
                  >
                    <Send className="h-3.5 w-3.5" />
                    Send Test Alert
                  </button>
                  <button
                    type="button"
                    disabled={alertBusy}
                    onClick={handleSaveAlerts}
                    className="h-[32px] rounded-md bg-[#1D6CF0] px-3.5 text-[12px] font-medium text-white hover:bg-[#1558D6]"
                  >
                    Save Alerts
                  </button>
                </div>
              </div>
            </div>
          </section>

          {/* 5. AI Threat Analysis */}
          <section
            id="groq-ai"
            className="scroll-mt-6 overflow-hidden rounded-lg border border-[#E5E7EB] bg-white"
          >
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#E5E7EB] bg-[#F9FAFB] px-5 py-3">
              <div className="flex items-center gap-2">
                <KeyRound className="h-4 w-4 text-[#1D6CF0]" />
                <h2 className="text-[14px] font-semibold text-[#111827]">
                  AI Threat Analysis
                </h2>
              </div>
              <div className="flex items-center gap-2.5 text-[12px] tabular-nums">
                <span className={state.groq.configured ? 'font-medium text-[#16A34A]' : 'font-medium text-[#D97706]'}>
                  {state.groq.configured ? (
                    <>
                      Connected · <span className="font-mono text-[11.5px]">{state.groq.maskedKey}</span>
                    </>
                  ) : (
                    'Not Configured'
                  )}
                </span>
                {q.cooldownSecondsRemaining > 0 && (
                  <span className="text-[#D97706]">Cooldown: {q.cooldownSecondsRemaining}s</span>
                )}
              </div>
            </div>

            {/* 4-Cell Rate-Limit Telemetry Bar */}
            <div className="grid grid-cols-2 divide-y divide-[#E5E7EB] border-b border-[#E5E7EB] bg-[#F9FAFB]/50 sm:grid-cols-4 sm:divide-y-0 sm:divide-x tabular-nums">
              {[
                { label: 'Requests / min', used: q.rpmUsed, limit: q.rpmLimit },
                { label: 'Tokens / min', used: q.tpmUsed, limit: q.tpmLimit },
                { label: 'Requests / day', used: q.rpdUsed, limit: q.rpdLimit },
                { label: 'Tokens / day', used: q.tpdUsed, limit: q.tpdLimit },
              ].map((m) => {
                const pct = Math.min(100, Math.round((m.used / m.limit) * 100));
                return (
                  <div key={m.label} className="px-4 py-3">
                    <div className="flex items-center justify-between text-[11.5px] text-[#6B7280]">
                      <span className="font-medium">{m.label}</span>
                      <span>{pct}%</span>
                    </div>
                    <p className="mt-1 text-[13.5px] font-semibold text-[#111827]">
                      {m.used.toLocaleString()} / {m.limit.toLocaleString()}
                    </p>
                    <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-[#E5E7EB]">
                      <div
                        className={`h-full rounded-full ${
                          pct > 80 ? 'bg-[#DC2626]' : pct > 55 ? 'bg-[#D97706]' : 'bg-[#1D6CF0]'
                        }`}
                        style={{ width: `${Math.max(pct, 2)}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="p-5">
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
                <div className="lg:col-span-6">
                  <label
                    htmlFor="setup-groq-key"
                    className="block text-[11.5px] font-medium text-[#374151]"
                  >
                    AI Provider API Key (Groq)
                  </label>
                  <div className="relative mt-1">
                    <input
                      id="setup-groq-key"
                      type="password"
                      autoComplete="off"
                      value={groqKeyInput}
                      onChange={(e) => setGroqKeyInput(e.target.value)}
                      placeholder={
                        state.groq.configured ? '•••••••• (enter new key to rotate)' : 'gsk_...'
                      }
                      className="h-[34px] w-full rounded-md border border-[#D1D5DB] bg-white px-3 pr-8 font-mono text-[12px] text-[#111827] placeholder:text-[#9CA3AF] focus:border-[#1D6CF0] focus:outline-none"
                    />
                    <Lock className="pointer-events-none absolute right-2.5 top-2.5 h-3.5 w-3.5 text-[#9CA3AF]" />
                  </div>
                </div>

                <div className="lg:col-span-3">
                  <label
                    htmlFor="groq-reasoning"
                    className="block text-[11.5px] font-medium text-[#374151]"
                  >
                    Reasoning Depth
                  </label>
                  <select
                    id="groq-reasoning"
                    value={reasoningEffort}
                    onChange={(e) => setReasoningEffort(e.target.value as 'low' | 'medium')}
                    className="mt-1 h-[34px] w-full rounded-md border border-[#D1D5DB] bg-white px-2.5 text-[12px] text-[#111827] focus:border-[#1D6CF0] focus:outline-none"
                  >
                    <option value="low">Low (Recommended · Fast)</option>
                    <option value="medium">Medium (Deeper Analysis)</option>
                  </select>
                </div>

                <div className="lg:col-span-3">
                  <label
                    htmlFor="groq-batch"
                    className="block text-[11.5px] font-medium text-[#374151]"
                  >
                    Canary Batch Size (3–8)
                  </label>
                  <input
                    id="groq-batch"
                    type="number"
                    min={3}
                    max={8}
                    value={batchSize}
                    onChange={(e) => setBatchSize(Number(e.target.value))}
                    className="mt-1 h-[34px] w-full rounded-md border border-[#D1D5DB] bg-white px-3 text-[12.5px] text-[#111827] tabular-nums focus:border-[#1D6CF0] focus:outline-none"
                  />
                </div>
              </div>

              <div className="mt-4 flex flex-wrap items-center justify-end gap-2">
                {state.groq.configured && state.groq.source === 'byok' && (
                  <button
                    type="button"
                    disabled={groqBusy}
                    onClick={() => saveGroqSettings(true)}
                    className="h-[32px] rounded-md border border-[#FECACA] bg-[#FEF2F2] px-3 text-[12px] font-medium text-[#DC2626] hover:bg-[#FEE2E2] transition-colors"
                  >
                    Clear Key
                  </button>
                )}
                <button
                  type="button"
                  disabled={groqBusy}
                  onClick={testGroqConnection}
                  className="h-[32px] rounded-md border border-[#D1D5DB] bg-white px-3.5 text-[12px] font-medium text-[#374151] hover:bg-[#F9FAFB] transition-colors"
                >
                  Test Connection
                </button>
                <button
                  type="button"
                  disabled={groqBusy}
                  onClick={() => saveGroqSettings(false)}
                  className="h-[32px] rounded-md bg-[#1D6CF0] px-3.5 text-[12px] font-medium text-white hover:bg-[#1558D6] transition-colors"
                >
                  Save Configuration
                </button>
              </div>
            </div>
          </section>

          {/* 6. Monitored Buckets & Auto-Harden */}
          <section
            id="buckets-hardening"
            className="scroll-mt-6 overflow-hidden rounded-lg border border-[#E5E7EB] bg-white"
          >
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#E5E7EB] bg-[#F9FAFB] px-5 py-3">
              <h2 className="text-[14px] font-semibold text-[#111827] tabular-nums">
                Monitored Buckets &amp; Auto-Harden ({state.buckets.length})
              </h2>
              <span className="text-[12px] text-[#6B7280]">
                Versioning · WORM Vault · Audit · Canaries
              </span>
            </div>

            <div className="divide-y divide-[#E5E7EB]">
              {state.buckets.map((b) => {
                const hr = hardenResults[b.name];
                return (
                  <div key={b.name} className="px-5 py-3.5 hover:bg-[#F9FAFB]/60 transition-colors">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div>
                        <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
                          <span className="font-mono text-[13px] font-semibold text-[#111827]">
                            {b.name}
                          </span>
                          <span className="text-[12px] text-[#6B7280]">
                            · {b.tags.sensitivity} · {b.tags.env}
                          </span>
                        </div>
                        <p className="mt-0.5 text-[12px] text-[#6B7280] tabular-nums">
                          Vault <span className="font-mono text-[#374151]">{b.vault}</span> ·{' '}
                          {b.objectCount} objects · {b.canaryCount} canaries
                        </p>
                      </div>
                      <button
                        type="button"
                        onClick={() => handleAutoHarden(b.name)}
                        className="inline-flex h-[30px] items-center gap-1.5 rounded-md border border-[#D1D5DB] bg-white px-3 text-[12px] font-medium text-[#374151] hover:bg-[#F9FAFB] transition-colors whitespace-nowrap shrink-0"
                      >
                        <ShieldCheck className="h-3.5 w-3.5 text-[#16A34A]" />
                        Auto-Harden
                      </button>
                    </div>

                    {hr && (
                      <div className="mt-3 grid grid-cols-1 gap-2.5 border-t border-[#E5E7EB] pt-3 sm:grid-cols-2">
                        {hr.checks.map((chk) => (
                          <div key={chk.id} className="flex items-start gap-2 text-[12px]">
                            {chk.passed ? (
                              <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[#16A34A]" />
                            ) : (
                              <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[#DC2626]" />
                            )}
                            <div>
                              <p className="font-medium text-[#111827]">{chk.label}</p>
                              <p className="text-[#6B7280]">{chk.detail}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            <form
              onSubmit={handleRegisterBucket}
              className="flex flex-wrap items-end gap-3 border-t border-[#E5E7EB] bg-[#F9FAFB] px-5 py-3.5"
            >
              <div className="min-w-[160px] flex-1">
                <label className="block text-[11px] font-medium text-[#374151]">
                  Register Bucket
                </label>
                <input
                  type="text"
                  value={newBucketName}
                  onChange={(e) => setNewBucketName(e.target.value)}
                  placeholder="e.g. payroll-staging"
                  className="mt-1 h-[32px] w-full rounded-md border border-[#D1D5DB] bg-white px-2.5 font-mono text-[12px] text-[#111827] placeholder:text-[#9CA3AF] focus:border-[#1D6CF0] focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-[11px] font-medium text-[#374151]">Sensitivity</label>
                <select
                  value={newBucketSensitivity}
                  onChange={(e) => setNewBucketSensitivity(e.target.value as 'critical' | 'sandbox')}
                  className="mt-1 h-[32px] rounded-md border border-[#D1D5DB] bg-white px-2.5 text-[12px] text-[#111827] focus:border-[#1D6CF0] focus:outline-none"
                >
                  <option value="critical">critical (auto-revoke)</option>
                  <option value="sandbox">sandbox (alert-only)</option>
                </select>
              </div>
              <label className="flex h-[32px] items-center gap-1.5 text-[12px] text-[#4B5563]">
                <input
                  type="checkbox"
                  checked={newBucketSimOnly}
                  onChange={(e) => setNewBucketSimOnly(e.target.checked)}
                  className="accent-[#1D6CF0]"
                />
                sim-only tag
              </label>
              <button
                type="submit"
                className="inline-flex h-[32px] items-center gap-1 rounded-md bg-[#1D6CF0] px-3.5 text-[12px] font-medium text-white hover:bg-[#1558D6] transition-colors whitespace-nowrap shrink-0"
              >
                <Plus className="h-3.5 w-3.5" />
                Add
              </button>
            </form>
          </section>

          {/* 7. Identity & KMS Allowlists */}
          <section
            id="allowlists"
            className="scroll-mt-6 overflow-hidden rounded-lg border border-[#E5E7EB] bg-white"
          >
            <div className="flex items-center justify-between border-b border-[#E5E7EB] bg-[#F9FAFB] px-5 py-3">
              <h2 className="text-[14px] font-semibold text-[#111827]">Identity &amp; KMS Allowlist</h2>
              <span className="text-[12px] text-[#6B7280]">Exact match · no wildcards</span>
            </div>

            <div className="grid grid-cols-1 divide-y divide-[#E5E7EB] md:grid-cols-2 md:divide-x md:divide-y-0">
              <div className="p-5">
                <p className="text-[12px] font-semibold text-[#374151]">
                  Trusted Principals ({state.policy.allowlist.principals.length})
                </p>
                <div className="mt-2.5 divide-y divide-[#F3F4F6] border-y border-[#E5E7EB]">
                  {state.policy.allowlist.principals.map((pid) => (
                    <div
                      key={pid}
                      className="flex h-[36px] items-center justify-between px-1 text-[12.5px] hover:bg-[#F9FAFB]"
                    >
                      <span className="font-mono text-[#111827]">{pid}</span>
                      <button
                        type="button"
                        onClick={() =>
                          updateAllowlist(
                            state.policy.allowlist.principals.filter((x) => x !== pid),
                            state.policy.allowlist.kms_keys,
                          )
                        }
                        className="rounded p-1 text-[#9CA3AF] hover:bg-[#FEF2F2] hover:text-[#DC2626]"
                        aria-label={`Remove ${pid}`}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
                <div className="mt-3 flex gap-2">
                  <input
                    type="text"
                    value={newPrincipal}
                    onChange={(e) => setNewPrincipal(e.target.value)}
                    placeholder="Add principal ID"
                    className="h-[32px] flex-1 rounded-md border border-[#D1D5DB] bg-white px-2.5 font-mono text-[12px] text-[#111827] placeholder:text-[#9CA3AF] focus:border-[#1D6CF0] focus:outline-none"
                  />
                  <button
                    type="button"
                    onClick={() => {
                      if (!newPrincipal.trim()) return;
                      void updateAllowlist(
                        [...state.policy.allowlist.principals, newPrincipal.trim()],
                        state.policy.allowlist.kms_keys,
                      );
                      setNewPrincipal('');
                    }}
                    className="h-[32px] rounded-md border border-[#D1D5DB] bg-white px-3 text-[12px] font-medium text-[#374151] hover:bg-[#F9FAFB]"
                  >
                    Add
                  </button>
                </div>
              </div>

              <div className="p-5">
                <p className="text-[12px] font-semibold text-[#374151]">
                  Trusted KMS Key ARNs / IDs ({state.policy.allowlist.kms_keys.length})
                </p>
                <div className="mt-2.5 divide-y divide-[#F3F4F6] border-y border-[#E5E7EB]">
                  {state.policy.allowlist.kms_keys.map((k) => (
                    <div
                      key={k}
                      className="flex h-[36px] items-center justify-between gap-2 px-1 text-[12.5px] hover:bg-[#F9FAFB]"
                    >
                      <span className="truncate font-mono text-[#111827]">{k}</span>
                      <button
                        type="button"
                        onClick={() =>
                          updateAllowlist(
                            state.policy.allowlist.principals,
                            state.policy.allowlist.kms_keys.filter((x) => x !== k),
                          )
                        }
                        className="shrink-0 rounded p-1 text-[#9CA3AF] hover:bg-[#FEF2F2] hover:text-[#DC2626]"
                        aria-label={`Remove ${k}`}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
                <div className="mt-3 flex gap-2">
                  <input
                    type="text"
                    value={newKmsKey}
                    onChange={(e) => setNewKmsKey(e.target.value)}
                    placeholder="Add KMS key ARN"
                    className="h-[32px] flex-1 rounded-md border border-[#D1D5DB] bg-white px-2.5 font-mono text-[12px] text-[#111827] placeholder:text-[#9CA3AF] focus:border-[#1D6CF0] focus:outline-none"
                  />
                  <button
                    type="button"
                    onClick={() => {
                      if (!newKmsKey.trim()) return;
                      void updateAllowlist(state.policy.allowlist.principals, [
                        ...state.policy.allowlist.kms_keys,
                        newKmsKey.trim(),
                      ]);
                      setNewKmsKey('');
                    }}
                    className="h-[32px] rounded-md border border-[#D1D5DB] bg-white px-3 text-[12px] font-medium text-[#374151] hover:bg-[#F9FAFB]"
                  >
                    Add
                  </button>
                </div>
              </div>
            </div>
          </section>

          {/* 8. Policy as Code (policies.yaml) */}
          <section
            id="policy-yaml"
            className="scroll-mt-6 overflow-hidden rounded-lg border border-[#E5E7EB] bg-white"
          >
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#E5E7EB] bg-[#F9FAFB] px-5 py-3">
              <div>
                <h2 className="text-[14px] font-semibold text-[#111827]">
                  Policy as Code (<span className="font-mono">policies.yaml</span>)
                </h2>
                <p className="mt-0.5 text-[12px] text-[#6B7280]">
                  Strict schema validation · rejects unknown keys before applying
                </p>
              </div>
              <button
                type="button"
                disabled={savingYaml}
                onClick={handleSavePolicyYaml}
                className="inline-flex h-[32px] items-center gap-1.5 rounded-md bg-[#1D6CF0] px-3.5 text-[12px] font-medium text-white hover:bg-[#1558D6] transition-colors disabled:opacity-50 whitespace-nowrap shrink-0"
              >
                <Save className="h-3.5 w-3.5" />
                {savingYaml ? 'Validating…' : 'Validate & Save'}
              </button>
            </div>

            <div className="p-5">
              <textarea
                value={yamlDraft}
                onChange={(e) => setYamlDraft(e.target.value)}
                spellCheck={false}
                rows={18}
                className="w-full rounded-md border border-[#D1D5DB] bg-[#F9FAFB] p-3.5 font-mono text-[12px] leading-relaxed text-[#111827] focus:border-[#1D6CF0] focus:bg-white focus:outline-none"
              />

              {yamlErrors.length > 0 && (
                <div className="mt-3 rounded-md border border-[#FECACA] bg-[#FEF2F2] p-3 text-[12px] text-[#991B1B]">
                  <p className="font-semibold">Schema Validation Rejected:</p>
                  <ul className="mt-1 list-disc space-y-0.5 pl-4 font-mono text-[11.5px]">
                    {yamlErrors.map((err, i) => (
                      <li key={i}>{err}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </section>

          {/* 9. Danger Zone */}
          <section
            id="danger-zone"
            className="scroll-mt-6 overflow-hidden rounded-lg border border-[#FECACA] bg-white"
          >
            <div className="flex items-center gap-2 border-b border-[#FECACA] bg-[#FEF2F2] px-5 py-3">
              <AlertTriangle className="h-4 w-4 text-[#DC2626]" />
              <h2 className="text-[14px] font-semibold text-[#991B1B]">Danger zone</h2>
            </div>

            <div className="divide-y divide-[#FEE2E2]">
              <div className="flex flex-wrap items-center justify-between gap-4 px-5 py-4">
                <div>
                  <p className="text-[13px] font-semibold text-[#111827]">
                    Clear integration credentials
                  </p>
                  <p className="mt-0.5 text-[12px] text-[#6B7280]">
                    Immediately purge AI provider and external S3 monitor/vault credentials from
                    active session memory.
                  </p>
                </div>
                <button
                  type="button"
                  disabled={dangerBusy}
                  onClick={handleClearAllSecrets}
                  className="h-[32px] rounded-md border border-[#FECACA] bg-white px-3.5 text-[12px] font-medium text-[#DC2626] hover:bg-[#FEF2F2] whitespace-nowrap shrink-0"
                >
                  Clear Credentials
                </button>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-4 px-5 py-4">
                <div>
                  <p className="text-[13px] font-semibold text-[#111827]">
                    Reset workspace to clean baseline
                  </p>
                  <p className="mt-0.5 text-[12px] text-[#6B7280]">
                    Restore seeded objects, clear active incidents, and unrevoke simulated
                    principals.
                  </p>
                </div>
                <button
                  type="button"
                  disabled={dangerBusy}
                  onClick={handleResetDemo}
                  className="h-[32px] rounded-md bg-[#DC2626] px-3.5 text-[12px] font-medium text-white hover:bg-[#B91C1C] whitespace-nowrap shrink-0"
                >
                  Reset Workspace
                </button>
              </div>
            </div>
          </section>
        </div>

        {/* Sticky Right-Hand Anchor Navigation Rail */}
        <aside className="hidden lg:block">
          <div className="sticky top-[68px]">
            <p className="mb-2.5 pl-3 type-caption text-[#6B7280]">
              On this page
            </p>
            <nav className="border-l border-[#E5E7EB]">
              {SETTINGS_ANCHORS.map((item) => {
                const isActive = activeAnchor === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => scrollToSection(item.id)}
                    className={`-ml-px flex w-full items-center border-l-2 py-1.5 pl-3 text-left type-control transition-colors ${
                      isActive
                        ? item.danger
                          ? 'border-[#DC2626] font-semibold text-[#DC2626]'
                          : 'border-[#1D6CF0] font-semibold text-[#1D6CF0]'
                        : item.danger
                          ? 'border-transparent text-[#DC2626]/80 hover:border-[#FECACA] hover:text-[#DC2626]'
                          : 'border-transparent text-[#4B5563] hover:border-[#D1D5DB] hover:text-[#111827]'
                    }`}
                  >
                    {item.label}
                  </button>
                );
              })}
            </nav>
          </div>
        </aside>
      </div>
    </div>
  );
};
