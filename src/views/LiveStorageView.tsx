import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Check,
  Copy,
  Download,
  Eye,
  FileUp,
  HardDrive,
  Lock,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Trash2,
  Unlock,
} from 'lucide-react';
import { LiveStorageTableSkeleton } from '../components/WorkspaceSkeletons.tsx';
import { useConsole } from '../context/ConsoleContext.tsx';
import type { LiveObjectSummary, TelemetryEvent } from '../shared/types.ts';

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

type KitTab = 'curl' | 'backblaze' | 'supabase' | 'minio';

export const LiveStorageView: React.FC = () => {
  const {
    state,
    role,
    apiFetch,
    pushToast,
    openSettingsSection,
    selectedBucket,
    setSelectedBucket,
  } = useConsole();

  const [actingPrincipal, setActingPrincipal] = useState('svc-billing-etl');
  const [customPrincipal, setCustomPrincipal] = useState('');
  const [objects, setObjects] = useState<LiveObjectSummary[]>([]);
  const [loadingList, setLoadingList] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterMode, setFilterMode] = useState<'all' | 'business' | 'canary' | 'flagged'>('all');
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [rightTab, setRightTab] = useState<'inspector' | 'cli'>('inspector');
  const [kitTab, setKitTab] = useState<KitTab>('curl');
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [actionBusy, setActionBusy] = useState(false);
  const [lastVerdict, setLastVerdict] = useState<{
    httpStatus: number;
    key: string;
    principalId: string;
    entropy?: number;
    magicValid?: boolean;
    signals: string[];
    error?: string;
  } | null>(null);

  const [revealedToken, setRevealedToken] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const effectivePrincipal =
    actingPrincipal === '__custom__'
      ? customPrincipal.trim() || 'custom-cli-client'
      : actingPrincipal;

  const fetchObjects = useCallback(async () => {
    setLoadingList(true);
    try {
      const res = await apiFetch<{ objects: LiveObjectSummary[] }>(
        `/api/storage/objects?bucket=${encodeURIComponent(selectedBucket)}`,
      );
      setObjects(res.objects);
      setSelectedKey((prev) =>
        prev && res.objects.some((o) => o.key === prev) ? prev : (res.objects[0]?.key ?? null),
      );
    } catch (err) {
      pushToast({
        title: 'Could not list bucket objects',
        detail: err instanceof Error ? err.message : 'Error',
        tone: 'error',
      });
    } finally {
      setLoadingList(false);
    }
  }, [apiFetch, pushToast, selectedBucket]);

  const prevBucketRef = useRef(selectedBucket);

  useEffect(() => {
    if (prevBucketRef.current !== selectedBucket) {
      prevBucketRef.current = selectedBucket;
      setObjects([]);
      setSelectedKey(null);
    }
  }, [selectedBucket]);

  useEffect(() => {
    void fetchObjects();
  }, [fetchObjects, state?.events.length]);

  const filteredObjects = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return objects.filter((o) => {
      if (filterMode === 'business' && o.isCanary) return false;
      if (filterMode === 'canary' && !o.isCanary) return false;
      if (filterMode === 'flagged' && o.magicValid && o.entropy < 7.2) return false;
      if (!q) return true;
      return (
        o.key.toLowerCase().includes(q) ||
        o.principalId.toLowerCase().includes(q) ||
        o.magicDetected.toLowerCase().includes(q)
      );
    });
  }, [objects, searchQuery, filterMode]);

  if (!state) return null;

  const selectedObj = objects.find((o) => o.key === selectedKey) ?? null;
  const actingPrincipalState = state.principals.find((p) => p.id === effectivePrincipal);
  const isPrincipalRevoked =
    actingPrincipalState?.status === 'REVOKED' || actingPrincipalState?.quarantinePolicyAttached;
  const vaultProtectedCount = objects.filter((o) => o.vaultProtected).length;
  const canaryCount = objects.filter((o) => o.isCanary).length;

  const uploadRealFiles = async (fileList: FileList | File[]) => {
    const files = Array.from(fileList);
    if (files.length === 0) return;
    setUploading(true);
    try {
      for (const file of files) {
        if (file.size > 10 * 1024 * 1024) {
          pushToast({
            title: `Skipped ${file.name}`,
            detail: 'Exceeds 10 MB per-file upload cap.',
            tone: 'warning',
          });
          continue;
        }
        const buf = await file.arrayBuffer();
        const key = `uploads/${file.name}`;
        const res = await fetch('/api/storage/objects', {
          method: 'POST',
          headers: {
            'x-defyswarm-role': role,
            'x-defyswarm-bucket': selectedBucket,
            'x-defyswarm-key': key,
            'x-defyswarm-principal': effectivePrincipal,
            'Content-Type': file.type || 'application/octet-stream',
          },
          body: buf,
        });
        const data = (await res.json().catch(() => ({}))) as {
          httpStatus?: number;
          error?: string;
          event?: TelemetryEvent;
        };
        setLastVerdict({
          httpStatus: res.status,
          key,
          principalId: effectivePrincipal,
          entropy: data.event?.entropy,
          magicValid: data.event?.magicValid,
          signals: data.event?.signals ?? [],
          error: data.error,
        });

        if (res.status === 403) {
          pushToast({
            title: `HTTP 403 AccessDenied (${effectivePrincipal})`,
            detail: data.error || 'Principal is revoked/quarantined by DefySwarm.',
            tone: 'error',
          });
        } else if (!res.ok) {
          pushToast({
            title: `Upload failed (${res.status})`,
            detail: data.error || file.name,
            tone: 'error',
          });
        } else {
          setSelectedKey(key);
          pushToast({
            title: `Uploaded ${file.name} (HTTP 200)`,
            detail: `Entropy ${data.event?.entropy?.toFixed(2) ?? '—'} · Magic ${data.event?.magicDetected ?? 'OK'} · Streamed to Observability.`,
            tone: (data.event?.signals.length ?? 0) > 0 ? 'warning' : 'success',
          });
        }
      }
      await fetchObjects();
    } finally {
      setUploading(false);
    }
  };

  const handleEncryptedOverwriteTest = async () => {
    if (!selectedObj) return;
    setActionBusy(true);
    try {
      const res = await fetch('/api/storage/objects/encrypt-test', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-defyswarm-role': role,
        },
        body: JSON.stringify({
          bucket: selectedBucket,
          key: selectedObj.key,
          principalId: effectivePrincipal,
        }),
      });
      const data = (await res.json().catch(() => ({}))) as {
        httpStatus?: number;
        error?: string;
        event?: TelemetryEvent;
      };
      setLastVerdict({
        httpStatus: res.status,
        key: selectedObj.key,
        principalId: effectivePrincipal,
        entropy: data.event?.entropy,
        magicValid: data.event?.magicValid,
        signals: data.event?.signals ?? [],
        error: data.error,
      });

      if (res.status === 403) {
        pushToast({
          title: `Blocked with HTTP 403 (${effectivePrincipal})`,
          detail: data.error || 'Compromised principal denied.',
          tone: 'error',
        });
      } else if (!res.ok) {
        pushToast({
          title: 'Overwrite test failed',
          detail: data.error || `HTTP ${res.status}`,
          tone: 'error',
        });
      } else {
        pushToast({
          title: 'Encrypted Overwrite Applied',
          detail: `Entropy jumped to ${data.event?.entropy?.toFixed(2)} bits/byte · Signals: ${data.event?.signals.join(', ') || 'scored'}.`,
          tone: 'warning',
        });
      }
      await fetchObjects();
    } finally {
      setActionBusy(false);
    }
  };

  const handleDeleteSelected = async () => {
    if (!selectedObj) return;
    setActionBusy(true);
    try {
      const res = await fetch(
        `/api/storage/objects?bucket=${encodeURIComponent(selectedBucket)}&key=${encodeURIComponent(selectedObj.key)}&principal=${encodeURIComponent(effectivePrincipal)}`,
        {
          method: 'DELETE',
          headers: { 'x-defyswarm-role': role },
        },
      );
      const data = (await res.json().catch(() => ({}))) as {
        error?: string;
        event?: TelemetryEvent;
      };
      setLastVerdict({
        httpStatus: res.status,
        key: selectedObj.key,
        principalId: effectivePrincipal,
        signals: data.event?.signals ?? [],
        error: data.error,
      });

      if (res.status === 403) {
        pushToast({
          title: `Delete Blocked (HTTP 403)`,
          detail: data.error || 'Principal is revoked.',
          tone: 'error',
        });
      } else if (!res.ok) {
        pushToast({ title: 'Delete failed', detail: data.error, tone: 'error' });
      } else {
        pushToast({
          title: `Deleted ${selectedObj.key}`,
          detail: `Delete marker recorded under ${effectivePrincipal}; clean copy remains in WORM vault.`,
          tone: 'info',
        });
      }
      await fetchObjects();
    } finally {
      setActionBusy(false);
    }
  };

  const handleTogglePrincipalStatus = async (targetStatus: 'ACTIVE' | 'REVOKED') => {
    setActionBusy(true);
    try {
      await apiFetch(`/api/principals/${encodeURIComponent(effectivePrincipal)}/status`, {
        method: 'POST',
        body: JSON.stringify({ status: targetStatus }),
      });
      pushToast({
        title: `Principal ${effectivePrincipal} → ${targetStatus}`,
        detail:
          targetStatus === 'ACTIVE'
            ? 'Access restored; live uploads will succeed again.'
            : 'Principal revoked; live uploads will now return HTTP 403.',
        tone: targetStatus === 'ACTIVE' ? 'success' : 'warning',
      });
    } catch (err) {
      pushToast({
        title: 'Status update failed',
        detail: err instanceof Error ? err.message : 'Error',
        tone: 'error',
      });
    } finally {
      setActionBusy(false);
    }
  };

  const handlePollNow = async () => {
    setActionBusy(true);
    try {
      const res = await apiFetch<{ message: string }>('/api/ingest/poll-now', { method: 'POST' });
      pushToast({ title: 'S3 Sync Complete', detail: res.message, tone: 'info' });
      await fetchObjects();
    } catch (err) {
      pushToast({
        title: 'Sync failed',
        detail: err instanceof Error ? err.message : 'Error',
        tone: 'error',
      });
    } finally {
      setActionBusy(false);
    }
  };

  const handleRevealToken = async () => {
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
    }
  };

  const copySnippet = (id: string, text: string) => {
    void navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1800);
  };

  const baseUrl = typeof window !== 'undefined' ? window.location.origin : 'http://localhost:3000';
  const displayToken = revealedToken ?? '<CLICK_REVEAL_TOKEN_ABOVE>';

  const curlUploadCmd = `curl -i -X POST "${baseUrl}/api/storage/objects" \\
  -H "X-DefySwarm-Token: ${displayToken}" \\
  -H "X-DefySwarm-Bucket: ${selectedBucket}" \\
  -H "X-DefySwarm-Key: uploads/real_report.pdf" \\
  -H "X-DefySwarm-Principal: ${effectivePrincipal}" \\
  -H "Content-Type: application/pdf" \\
  --data-binary @./real_report.pdf`;

  const curlWebhookCmd = `curl -i -X POST "${baseUrl}/api/ingest/s3-event" \\
  -H "X-DefySwarm-Token: ${displayToken}" \\
  -H "Content-Type: application/json" \\
  -d '{"Records":[{"eventName":"s3:ObjectCreated:Put","userIdentity":{"principalId":"${effectivePrincipal}"},"s3":{"bucket":{"name":"${selectedBucket}"},"object":{"key":"finance/2026/Q3/live_webhook_test.csv","size":4096}}}]}'`;

  const minioDockerCmd = `# 1. Start a local MinIO instance
docker run -d --name defyswarm-minio \\
  -p 9000:9000 -p 9001:9001 \\
  -e MINIO_ROOT_USER=minioadmin \\
  -e MINIO_ROOT_PASSWORD=minioadmin \\
  quay.io/minio/minio server /data --console-address ":9001"

# 2. Configure MinIO webhook pointing to DefySwarm
mc alias set local http://localhost:9000 minioadmin minioadmin
mc admin config set local notify_webhook:defyswarm \\
  endpoint="${baseUrl}/api/ingest/s3-event" \\
  auth_token="${displayToken}"
mc admin service restart local
mc event add local/${selectedBucket} arn:minio:sqs::defyswarm:webhook --event put,get,delete`;

  const providerLabel =
    state.storage.provider === 'backblaze-b2'
      ? 'Backblaze B2'
      : state.storage.provider === 'supabase-s3'
        ? 'Supabase Storage'
        : state.storage.provider === 'minio'
          ? 'MinIO'
          : state.storage.provider === 'custom-s3'
            ? 'Custom S3'
            : 'Local Sandbox';

  return (
    <div className="mx-auto max-w-[1380px] space-y-6 px-4 py-6 sm:px-6">
      {/* Header Row */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="type-page-title">
            Live Storage
          </h1>
          <p className="mt-1.5 text-[13px] text-[#6B7280]">
            Upload files directly, stream CLI traffic, or inspect objects in your connected S3
            bucket.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <select
            value={selectedBucket}
            onChange={(e) => setSelectedBucket(e.target.value)}
            aria-label="Select bucket"
            className="h-[32px] rounded-md border border-[#D1D5DB] bg-white px-2.5 font-mono text-[12px] text-[#111827] focus:border-[#1D6CF0] focus:outline-none"
          >
            {state.buckets.map((b) => (
              <option key={b.name} value={b.name}>
                {b.name}
              </option>
            ))}
          </select>

          <select
            value={actingPrincipal}
            onChange={(e) => setActingPrincipal(e.target.value)}
            aria-label="Select acting principal"
            className="h-[32px] rounded-md border border-[#D1D5DB] bg-white px-2.5 font-mono text-[12px] text-[#111827] focus:border-[#1D6CF0] focus:outline-none"
          >
            {state.principals.map((p) => (
              <option key={p.id} value={p.id}>
                {p.id} ({p.status})
              </option>
            ))}
            <option value="__custom__">+ Custom principal…</option>
          </select>

          {actingPrincipal === '__custom__' && (
            <input
              type="text"
              value={customPrincipal}
              onChange={(e) => setCustomPrincipal(e.target.value)}
              placeholder="e.g. svc-invoice-bot"
              className="h-[32px] w-40 rounded-md border border-[#D1D5DB] bg-white px-2.5 font-mono text-[12px] text-[#111827] focus:border-[#1D6CF0] focus:outline-none"
            />
          )}

          {state.storage.minioConnected && (
            <button
              type="button"
              disabled={actionBusy}
              onClick={handlePollNow}
              className="inline-flex h-[32px] items-center gap-1.5 rounded-md border border-[#D1D5DB] bg-white px-3 text-[12px] font-medium text-[#374151] hover:bg-[#F9FAFB] whitespace-nowrap shrink-0"
            >
              <RefreshCw className={`h-3.5 w-3.5 text-[#6B7280] ${actionBusy ? 'animate-spin' : ''}`} />
              Sync S3
            </button>
          )}

          <input
            ref={fileInputRef}
            type="file"
            multiple
            className="hidden"
            onChange={(e) => {
              if (e.target.files) void uploadRealFiles(e.target.files);
              e.target.value = '';
            }}
          />
          <button
            type="button"
            disabled={uploading}
            onClick={() => fileInputRef.current?.click()}
            className="inline-flex h-[32px] items-center gap-1.5 rounded-md bg-[#1D6CF0] px-3.5 text-[12.5px] font-medium text-white hover:bg-[#1558D6] transition-colors disabled:opacity-50 whitespace-nowrap shrink-0"
          >
            <FileUp className="h-3.5 w-3.5" />
            {uploading ? 'Uploading…' : 'Upload Files'}
          </button>
        </div>
      </div>

      {/* 4-Cell Live Storage Posture Strip */}
      <div className="surface-card grid grid-cols-1 divide-y divide-[#E5E7EB] overflow-hidden sm:grid-cols-2 sm:divide-y-0 sm:divide-x xl:grid-cols-4">
        <div className="px-4 py-4">
          <div className="flex items-center justify-between text-[12px] font-medium text-[#6B7280]">
            <span>Active Storage Backend</span>
            <HardDrive className="h-3.5 w-3.5 text-[#1D6CF0]" />
          </div>
          <p className="mt-2 truncate font-display text-[16px] font-semibold tracking-[-0.015em] text-[#111827]">
            {state.storage.minioConnected ? providerLabel : 'Local Sandbox'}
          </p>
          <button
            type="button"
            onClick={() => openSettingsSection('storage-connector')}
            className="mt-1 text-[12px] font-medium text-[#1D6CF0] hover:underline"
          >
            {state.storage.minioConnected
              ? `Poller: ${state.storage.pollingEnabled ? `${state.storage.pollingIntervalSec}s` : 'Manual'} · ${state.storage.apiCallsToday} calls today`
              : 'Connect S3 provider →'}
          </button>
        </div>

        <div className="px-4 py-4">
          <p className="text-[12px] font-medium text-[#6B7280]">
            Objects in <span className="font-mono text-[#374151]">{selectedBucket}</span>
          </p>
          <p className="mt-2 type-kpi text-[26px] text-[#111827]">
            {objects.length}
          </p>
          <p className="mt-1 text-[12px] text-[#6B7280] tabular-nums">
            {objects.length - canaryCount} business · {canaryCount} active canaries
          </p>
        </div>

        <div className="px-4 py-4">
          <p className="text-[12px] font-medium text-[#6B7280]">WORM Vault Coverage</p>
          <p className="mt-2 type-kpi text-[26px] text-[#16A34A]">
            {vaultProtectedCount} / {objects.length}
          </p>
          <p className="mt-1 text-[12px] text-[#6B7280]">
            SHA-256 verified clean snapshots
          </p>
        </div>

        <div className="px-4 py-4">
          <p className="text-[12px] font-medium text-[#6B7280]">Last Write Verdict</p>
          {lastVerdict ? (
            <>
              <p
                className={`mt-2 text-[15px] font-semibold tabular-nums leading-tight ${
                  lastVerdict.httpStatus === 403
                    ? 'text-[#DC2626]'
                    : lastVerdict.signals.length > 0
                      ? 'text-[#D97706]'
                      : 'text-[#16A34A]'
                }`}
              >
                HTTP {lastVerdict.httpStatus} ·{' '}
                {lastVerdict.httpStatus === 403
                  ? 'Access Denied'
                  : lastVerdict.entropy !== undefined
                    ? `Entropy ${lastVerdict.entropy.toFixed(2)}`
                    : 'Verified'}
              </p>
              <p className="mt-1 truncate font-mono text-[11.5px] text-[#6B7280]">
                {lastVerdict.principalId} · {lastVerdict.key}
              </p>
            </>
          ) : (
            <>
              <p className="mt-2 text-[15px] font-semibold text-[#4B5563] leading-tight">
                Awaiting write event
              </p>
              <p className="mt-1 text-[12px] text-[#6B7280]">
                Drop a file below or send via CLI
              </p>
            </>
          )}
        </div>
      </div>

      {/* Main 2-Column Workspace */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
        {/* Left Pane: Dropzone + Object Table (7 cols) */}
        <section className="flex flex-col overflow-hidden rounded-lg border border-[#E5E7EB] bg-white lg:col-span-7">
          {/* Interactive Drag-and-Drop Strip */}
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragging(false);
              if (e.dataTransfer.files) void uploadRealFiles(e.dataTransfer.files);
            }}
            className={`flex flex-wrap items-center justify-between gap-3 border-b border-[#E5E7EB] px-4 py-3 transition-colors ${
              dragging ? 'bg-[#EFF6FF]' : 'bg-[#F9FAFB]'
            }`}
          >
            <div className="flex items-center gap-2.5 text-[12.5px]">
              <FileUp className="h-4 w-4 shrink-0 text-[#1D6CF0]" />
              <div>
                <span className="font-medium text-[#111827]">
                  Drop files here to upload (up to 10 MB)
                </span>
                <span className="ml-2 text-[12px] text-[#6B7280]">
                  acting as <strong className="font-mono font-medium text-[#111827]">{effectivePrincipal}</strong>
                </span>
                {isPrincipalRevoked && (
                  <span className="ml-2 text-[12px] font-semibold text-[#DC2626]">
                    · Revoked (writes return HTTP 403)
                  </span>
                )}
              </div>
            </div>
            <div className="flex items-center gap-2">
              {actingPrincipalState && (
                <button
                  type="button"
                  disabled={actionBusy}
                  onClick={() =>
                    handleTogglePrincipalStatus(isPrincipalRevoked ? 'ACTIVE' : 'REVOKED')
                  }
                  className={`inline-flex h-[28px] items-center gap-1 rounded-md border px-2.5 text-[11.5px] font-medium transition-colors whitespace-nowrap shrink-0 ${
                    isPrincipalRevoked
                      ? 'border-[#BBF7D0] bg-[#F0FDF4] text-[#15803D] hover:bg-[#DCFCE7]'
                      : 'border-[#FECACA] bg-[#FEF2F2] text-[#DC2626] hover:bg-[#FEE2E2]'
                  }`}
                >
                  {isPrincipalRevoked ? (
                    <>
                      <Unlock className="h-3 w-3" /> Unblock Principal
                    </>
                  ) : (
                    <>
                      <Lock className="h-3 w-3" /> Revoke Now
                    </>
                  )}
                </button>
              )}
            </div>
          </div>

          {/* Filter Toolbar */}
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#E5E7EB] bg-white px-4 py-2.5">
            <div className="flex items-center rounded-[8px] border border-[#E5E7EB]/80 bg-[#F2F4F7] p-0.5">
              {(
                [
                  { id: 'all', label: 'All' },
                  { id: 'business', label: 'Business' },
                  { id: 'canary', label: 'Canaries' },
                  { id: 'flagged', label: 'High Entropy / Invalid' },
                ] as const
              ).map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setFilterMode(tab.id)}
                  className={`rounded-[6px] px-2.5 py-1 text-[11.5px] font-medium transition-colors whitespace-nowrap shrink-0 ${
                    filterMode === tab.id
                      ? 'segmented-thumb-shadow bg-white text-[#111827]'
                      : 'text-[#6B7280] hover:text-[#111827]'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <div className="relative w-full sm:w-56">
              <Search className="pointer-events-none absolute left-2.5 top-2 h-3.5 w-3.5 text-[#9CA3AF]" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter key, principal, type…"
                className="h-[30px] w-full rounded-[7px] border border-[#D1D5DB] bg-white pl-8 pr-2.5 text-[12px] text-[#111827] placeholder:text-[#9CA3AF] focus:border-[#1D6CF0] focus:outline-none"
              />
            </div>
          </div>

          {/* Object Table */}
          <div className="max-h-[540px] flex-1 overflow-auto bg-white">
            {loadingList && objects.length === 0 ? (
              <LiveStorageTableSkeleton rows={8} />
            ) : filteredObjects.length === 0 ? (
              <div className="py-16 text-center text-[13px] text-[#6B7280]">
                No objects match the current filter. Drop a file above to test ingestion.
              </div>
            ) : (
              <table className="w-full min-w-[600px] text-left text-[12.5px]">
                <thead className="kumo-table-head sticky top-0 z-10">
                  <tr className="h-[36px] type-caption text-[#6B7280]">
                    <th className="pl-4 pr-3 font-medium">Object Key</th>
                    <th className="px-3 text-right font-medium">Size</th>
                    <th className="px-3 text-right font-medium">Entropy</th>
                    <th className="px-3 font-medium">File Signature</th>
                    <th className="pl-3 pr-4 text-right font-medium">Vault</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#F3F4F6] tabular-nums">
                  {filteredObjects.map((obj) => {
                    const selected = obj.key === selectedKey;
                    const highEntropy = obj.entropy >= 7.2;
                    return (
                      <tr
                        key={obj.key}
                        onClick={() => {
                          setSelectedKey(obj.key);
                          setRightTab('inspector');
                        }}
                        className={`h-[40px] cursor-pointer transition-colors ${
                          selected ? 'bg-[#EFF6FF]' : 'hover:bg-[#F8F9FB]'
                        }`}
                      >
                        <td className="max-w-[270px] truncate pl-4 pr-3 font-mono text-[12px] text-[#111827]">
                          {obj.key}
                          {obj.isCanary && (
                            <span className="ml-2 rounded border border-[#BFDBFE] bg-[#EFF6FF] px-1.5 py-0.5 font-sans text-[10.5px] font-medium text-[#1D6CF0]">
                              Canary
                            </span>
                          )}
                        </td>
                        <td className="px-3 text-right text-[12px] text-[#4B5563]">
                          {formatBytes(obj.sizeBytes)}
                        </td>
                        <td
                          className={`px-3 text-right text-[12px] ${
                            highEntropy ? 'font-semibold text-[#DC2626]' : 'text-[#111827]'
                          }`}
                        >
                          {obj.entropy > 0 ? obj.entropy.toFixed(2) : '—'}
                        </td>
                        <td className="px-3 text-[12px]">
                          <span className={obj.magicValid ? 'text-[#16A34A]' : 'font-medium text-[#DC2626]'}>
                            {obj.magicValid ? obj.magicDetected : `Invalid (${obj.magicDetected})`}
                          </span>
                        </td>
                        <td className="pl-3 pr-4 text-right text-[12px]">
                          <span className={obj.vaultProtected ? 'text-[#16A34A]' : 'text-[#D97706]'}>
                            {obj.vaultProtected ? 'Protected' : 'None'}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </section>

        {/* Right Pane: Object Inspector + CLI & Integrations (5 cols) */}
        <aside className="surface-card flex flex-col overflow-hidden lg:col-span-5">
          <div className="flex items-center justify-between border-b border-[#E5E7EB] bg-[#F8F9FA] px-4 py-2">
            <div className="flex items-center rounded-[8px] border border-[#E5E7EB]/80 bg-[#F2F4F7] p-0.5">
              <button
                type="button"
                onClick={() => setRightTab('inspector')}
                className={`rounded-[6px] px-3 py-1 text-[12px] font-medium transition-colors whitespace-nowrap ${
                  rightTab === 'inspector'
                    ? 'segmented-thumb-shadow bg-white text-[#111827]'
                    : 'text-[#6B7280] hover:text-[#111827]'
                }`}
              >
                Object Inspector
              </button>
              <button
                type="button"
                onClick={() => setRightTab('cli')}
                className={`inline-flex items-center gap-1.5 rounded-[6px] px-3 py-1 text-[12px] font-medium transition-colors whitespace-nowrap ${
                  rightTab === 'cli'
                    ? 'segmented-thumb-shadow bg-white text-[#111827]'
                    : 'text-[#6B7280] hover:text-[#111827]'
                }`}
              >
                <Terminal className="h-3.5 w-3.5" />
                CLI &amp; Integrations
              </button>
            </div>
          </div>

          {rightTab === 'inspector' ? (
            !selectedObj ? (
              <div className="flex flex-1 flex-col items-center justify-center p-8 text-center text-[13px] text-[#6B7280]">
                Select any object row on the left to inspect its cryptographic signature, download
                the clean vault copy, or simulate an encrypted overwrite.
              </div>
            ) : (
              <div className="flex flex-col divide-y divide-[#E5E7EB]">
                <div className="p-5">
                  <p className="text-[12px] font-medium text-[#6B7280]">
                    Selected Object ·{' '}
                    {selectedObj.source === 'external-s3' ? 'External S3' : 'Local Sandbox'}
                  </p>
                  <p className="mt-1 break-all font-mono text-[13.5px] font-semibold text-[#111827]">
                    {selectedObj.bucket}/{selectedObj.key}
                  </p>
                  {selectedObj.isCanary && (
                    <p className="mt-2 rounded-md border border-[#BFDBFE] bg-[#EFF6FF] px-3 py-2 text-[12px] text-[#1D4ED8]">
                      Adaptive Canary Decoy — writing or deleting this object triggers immediate P0
                      containment (+100 risk).
                    </p>
                  )}

                  <div className="mt-4 grid grid-cols-2 gap-x-4 gap-y-3 border-t border-[#E5E7EB] pt-3.5 text-[12.5px] tabular-nums">
                    <div>
                      <p className="text-[11.5px] font-medium text-[#6B7280]">
                        Payload Entropy
                      </p>
                      <p
                        className={`mt-0.5 font-semibold ${
                          selectedObj.entropy >= 7.2 ? 'text-[#DC2626]' : 'text-[#111827]'
                        }`}
                      >
                        {selectedObj.entropy > 0
                          ? `${selectedObj.entropy.toFixed(3)} bits/B`
                          : 'Not sampled'}
                      </p>
                    </div>
                    <div>
                      <p className="text-[11.5px] font-medium text-[#6B7280]">
                        File Signature
                      </p>
                      <p
                        className={`mt-0.5 font-semibold ${
                          selectedObj.magicValid ? 'text-[#16A34A]' : 'text-[#DC2626]'
                        }`}
                      >
                        {selectedObj.magicValid
                          ? `Valid (${selectedObj.magicDetected})`
                          : 'Header Destroyed'}
                      </p>
                    </div>
                    <div>
                      <p className="text-[11.5px] font-medium text-[#6B7280]">
                        Size / Version
                      </p>
                      <p className="mt-0.5 truncate text-[#111827]">
                        {formatBytes(selectedObj.sizeBytes)} ·{' '}
                        <span className="font-mono text-[11.5px] text-[#4B5563]">
                          {selectedObj.versionId.slice(0, 14)}
                        </span>
                      </p>
                    </div>
                    <div>
                      <p className="text-[11.5px] font-medium text-[#6B7280]">
                        Last Principal
                      </p>
                      <p className="mt-0.5 truncate font-mono text-[12px] text-[#111827]">
                        {selectedObj.principalId}
                      </p>
                    </div>
                  </div>

                  <div className="mt-3.5 border-t border-[#E5E7EB] pt-3">
                    <p className="text-[11.5px] font-medium text-[#6B7280]">
                      Current SHA-256 Digest
                    </p>
                    <p className="mt-0.5 break-all font-mono text-[11px] text-[#4B5563]">
                      {selectedObj.sha256 || '—'}
                    </p>
                  </div>

                  <div className="mt-3.5 border-t border-[#E5E7EB] pt-3">
                    <div className="flex items-center justify-between">
                      <p className="text-[11.5px] font-medium text-[#6B7280]">
                        WORM Vault Clean Snapshot
                      </p>
                      <span
                        className={`text-[12px] font-semibold ${
                          selectedObj.vaultProtected ? 'text-[#16A34A]' : 'text-[#D97706]'
                        }`}
                      >
                        {selectedObj.vaultProtected ? 'Verified Immutable' : 'Not Snapshotted'}
                      </span>
                    </div>
                    {selectedObj.vaultSha256 && (
                      <p className="mt-0.5 break-all font-mono text-[11px] text-[#6B7280]">
                        {selectedObj.vaultSha256}
                      </p>
                    )}
                  </div>
                </div>

                {/* Object Actions */}
                <div className="space-y-2.5 bg-[#F9FAFB]/60 p-5">
                  <p className="text-[12px] font-medium text-[#6B7280]">
                    Object Actions (Acting as{' '}
                    <span className="font-mono font-semibold text-[#111827]">
                      {effectivePrincipal}
                    </span>
                    )
                  </p>

                  <div className="grid grid-cols-2 gap-2">
                    <a
                      href={`/api/storage/objects/download?bucket=${encodeURIComponent(selectedBucket)}&key=${encodeURIComponent(selectedObj.key)}&fromVault=false`}
                      className="inline-flex h-[32px] items-center justify-center gap-1.5 rounded-md border border-[#D1D5DB] bg-white px-3 text-[12px] font-medium text-[#374151] hover:bg-[#F9FAFB]"
                    >
                      <Download className="h-3.5 w-3.5 text-[#6B7280]" />
                      Download Current
                    </a>
                    <a
                      href={`/api/storage/objects/download?bucket=${encodeURIComponent(selectedBucket)}&key=${encodeURIComponent(selectedObj.key)}&fromVault=true`}
                      className="inline-flex h-[32px] items-center justify-center gap-1.5 rounded-md border border-[#BBF7D0] bg-[#F0FDF4] px-3 text-[12px] font-medium text-[#15803D] hover:bg-[#DCFCE7]"
                    >
                      <ShieldCheck className="h-3.5 w-3.5" />
                      Download Vault Copy
                    </a>
                  </div>

                  <button
                    type="button"
                    disabled={actionBusy}
                    onClick={handleEncryptedOverwriteTest}
                    className="inline-flex h-[34px] w-full items-center justify-center gap-1.5 rounded-md border border-[#FDE68A] bg-[#FFFBEB] px-3 text-[12.5px] font-medium text-[#B45309] hover:bg-[#FEF3C7] transition-colors disabled:opacity-50"
                  >
                    <ShieldAlert className="h-3.5 w-3.5" />
                    Simulate AES-256-GCM Overwrite
                  </button>

                  <button
                    type="button"
                    disabled={actionBusy}
                    onClick={handleDeleteSelected}
                    className="inline-flex h-[32px] w-full items-center justify-center gap-1.5 rounded-md border border-[#FECACA] bg-[#FEF2F2] px-3 text-[12px] font-medium text-[#DC2626] hover:bg-[#FEE2E2] transition-colors disabled:opacity-50"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                    Delete Object as {effectivePrincipal}
                  </button>
                </div>
              </div>
            )
          ) : (
            /* CLI & Cloud Integration Kit */
            <div className="flex flex-col divide-y divide-[#E5E7EB]">
              {/* Token Bar */}
              <div className="flex items-center justify-between gap-2 bg-[#F9FAFB] px-4 py-3 text-[12px]">
                <div className="min-w-0 truncate">
                  <span className="text-[#6B7280]">Ingest Token: </span>
                  <span className="font-mono font-medium text-[#111827]">
                    {revealedToken ?? state.ingest.tokenMasked}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={handleRevealToken}
                  className="inline-flex h-[28px] items-center gap-1 rounded-md border border-[#D1D5DB] bg-white px-2.5 text-[11.5px] font-medium text-[#374151] hover:bg-[#F9FAFB] whitespace-nowrap shrink-0"
                >
                  <Eye className="h-3 w-3 text-[#1D6CF0]" />
                  {revealedToken ? 'Revealed' : 'Reveal Token'}
                </button>
              </div>

              {/* Integration Kit Sub-Tabs */}
              <div className="flex flex-wrap gap-1 bg-white px-4 py-2">
                {(
                  [
                    { id: 'curl', label: 'cURL' },
                    { id: 'backblaze', label: 'Backblaze B2' },
                    { id: 'supabase', label: 'Supabase S3' },
                    { id: 'minio', label: 'MinIO' },
                  ] as const
                ).map((t) => (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => setKitTab(t.id)}
                    className={`rounded-md px-2.5 py-1 text-[11.5px] font-medium transition-colors whitespace-nowrap ${
                      kitTab === t.id
                        ? 'bg-[#EFF6FF] text-[#1D6CF0]'
                        : 'text-[#6B7280] hover:bg-[#F9FAFB] hover:text-[#111827]'
                    }`}
                  >
                    {t.label}
                  </button>
                ))}
              </div>

              <div className="space-y-4 p-4 text-[12.5px] text-[#4B5563]">
                {kitTab === 'curl' && (
                  <>
                    <div>
                      <div className="flex items-center justify-between">
                        <p className="font-semibold text-[#111827]">
                          1. Upload a file via CLI
                        </p>
                        <button
                          type="button"
                          onClick={() => copySnippet('curl-put', curlUploadCmd)}
                          className="inline-flex items-center gap-1 text-[12px] font-medium text-[#1D6CF0] hover:underline"
                        >
                          {copiedId === 'curl-put' ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                          {copiedId === 'curl-put' ? 'Copied' : 'Copy'}
                        </button>
                      </div>
                      <pre className="mt-1.5 overflow-x-auto rounded-md border border-[#E5E7EB] bg-[#F9FAFB] p-3 font-mono text-[11px] leading-relaxed text-[#111827]">
                        {curlUploadCmd}
                      </pre>
                    </div>

                    <div>
                      <div className="flex items-center justify-between">
                        <p className="font-semibold text-[#111827]">
                          2. Send an authenticated S3 webhook event
                        </p>
                        <button
                          type="button"
                          onClick={() => copySnippet('curl-hook', curlWebhookCmd)}
                          className="inline-flex items-center gap-1 text-[12px] font-medium text-[#1D6CF0] hover:underline"
                        >
                          {copiedId === 'curl-hook' ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                          {copiedId === 'curl-hook' ? 'Copied' : 'Copy'}
                        </button>
                      </div>
                      <pre className="mt-1.5 overflow-x-auto rounded-md border border-[#E5E7EB] bg-[#F9FAFB] p-3 font-mono text-[11px] leading-relaxed text-[#111827]">
                        {curlWebhookCmd}
                      </pre>
                    </div>
                  </>
                )}

                {kitTab === 'backblaze' && (
                  <div className="space-y-2.5 leading-relaxed">
                    <p className="font-semibold text-[#111827]">
                      Backblaze B2 S3-Compatible Setup
                    </p>
                    <ol className="list-decimal space-y-1.5 pl-4">
                      <li>Sign in to your Backblaze B2 console.</li>
                      <li>
                        Create two private buckets: e.g.{' '}
                        <code className="rounded bg-[#F3F4F6] px-1 font-mono text-[#111827]">my-prod-files</code> and{' '}
                        <code className="rounded bg-[#F3F4F6] px-1 font-mono text-[#111827]">my-worm-vault</code> (enable Object Lock on the vault).
                      </li>
                      <li>
                        Under <strong>Application Keys</strong>, create one key for your production bucket and an isolated key for your vault bucket.
                      </li>
                      <li>
                        Open <strong>Settings</strong> → select <strong>Backblaze B2</strong>, paste your S3 endpoint (e.g.{' '}
                        <code className="rounded bg-[#F3F4F6] px-1 font-mono text-[#111827]">https://s3.us-west-004.backblazeb2.com</code>), and enable the <strong>Bucket Change Poller</strong>.
                      </li>
                    </ol>
                    <button
                      type="button"
                      onClick={() => openSettingsSection('storage-connector')}
                      className="mt-2 inline-flex h-[32px] items-center rounded-md bg-[#1D6CF0] px-3.5 text-[12px] font-medium text-white hover:bg-[#1558D6]"
                    >
                      Configure Backblaze B2 in Settings →
                    </button>
                  </div>
                )}

                {kitTab === 'supabase' && (
                  <div className="space-y-2.5 leading-relaxed">
                    <p className="font-semibold text-[#111827]">
                      Supabase Storage S3 Setup
                    </p>
                    <ol className="list-decimal space-y-1.5 pl-4">
                      <li>Open your project in the Supabase dashboard.</li>
                      <li>
                        Create a private Storage bucket (e.g.{' '}
                        <code className="rounded bg-[#F3F4F6] px-1 font-mono text-[#111827]">finance-prod</code>).
                      </li>
                      <li>
                        Go to <strong>Project Settings → Storage → S3 Access Keys</strong> and generate an Access Key ID and Secret.
                      </li>
                      <li>
                        Open <strong>Settings</strong> → select <strong>Supabase Storage</strong>, paste{' '}
                        <code className="rounded bg-[#F3F4F6] px-1 font-mono text-[#111827]">
                          https://&lt;project-ref&gt;.storage.supabase.co/storage/v1/s3
                        </code>
                        , and click <strong>Verify &amp; Connect</strong>.
                      </li>
                    </ol>
                    <button
                      type="button"
                      onClick={() => openSettingsSection('storage-connector')}
                      className="mt-2 inline-flex h-[32px] items-center rounded-md bg-[#1D6CF0] px-3.5 text-[12px] font-medium text-white hover:bg-[#1558D6]"
                    >
                      Configure Supabase Storage in Settings →
                    </button>
                  </div>
                )}

                {kitTab === 'minio' && (
                  <div>
                    <div className="flex items-center justify-between">
                      <p className="font-semibold text-[#111827]">
                        Self-Hosted MinIO
                      </p>
                      <button
                        type="button"
                        onClick={() => copySnippet('minio-docker', minioDockerCmd)}
                        className="inline-flex items-center gap-1 text-[12px] font-medium text-[#1D6CF0] hover:underline"
                      >
                        {copiedId === 'minio-docker' ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                        {copiedId === 'minio-docker' ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                    <pre className="mt-1.5 overflow-x-auto rounded-md border border-[#E5E7EB] bg-[#F9FAFB] p-3 font-mono text-[11px] leading-relaxed text-[#111827]">
                      {minioDockerCmd}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
};
