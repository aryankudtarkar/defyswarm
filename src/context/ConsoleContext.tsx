import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import type {
  ConsoleBootstrapState,
  IncidentRecord,
  Role,
  SimRunState,
  TelemetryEvent,
} from '../shared/types.ts';

export type WorkspaceId = 'overview' | 'storage' | 'threat-ops' | 'validation' | 'settings';

export type StorageSubTab = 'live-files' | 'canaries-vault';
export type ThreatOpsSubTab = 'telemetry' | 'incidents';
export type ValidationSubTab = 'simulator' | 'analytics';
export type SettingsSubTab = 'configuration' | 'health-audit';

export type WorkspaceSubTabMap = {
  overview: null;
  storage: StorageSubTab;
  'threat-ops': ThreatOpsSubTab;
  validation: ValidationSubTab;
  settings: SettingsSubTab;
};

export type SubTabState = {
  storage: StorageSubTab;
  'threat-ops': ThreatOpsSubTab;
  validation: ValidationSubTab;
  settings: SettingsSubTab;
};

export type ActiveSubTab = StorageSubTab | ThreatOpsSubTab | ValidationSubTab | SettingsSubTab | null;

export interface ToastItem {
  id: string;
  title: string;
  detail?: string;
  tone: 'info' | 'success' | 'warning' | 'error';
}

export interface ConfirmRequest {
  title: string;
  message: string;
  confirmLabel: string;
  destructive?: boolean;
  onConfirm: () => Promise<void> | void;
}

export interface BenchmarkProgress {
  running: boolean;
  completed: number;
  total: number;
  stage: string;
}

interface ConsoleContextValue {
  state: ConsoleBootstrapState | null;
  loading: boolean;
  error: string | null;
  activeWorkspace: WorkspaceId;
  activeSubTab: ActiveSubTab;
  subTabs: SubTabState;
  setActiveWorkspace: (workspace: WorkspaceId) => void;
  navigateTo: <W extends WorkspaceId>(workspace: W, subTab?: WorkspaceSubTabMap[W]) => void;
  settingsAnchor: string | null;
  openSettingsSection: (sectionId: string) => void;
  clearSettingsAnchor: () => void;
  selectedIncidentId: string | null;
  setSelectedIncidentId: (id: string | null) => void;
  selectedBucket: string;
  setSelectedBucket: (bucket: string) => void;
  openBucket: (bucket: string) => void;
  role: Role;
  setRole: (r: Role) => void;
  wsConnected: boolean;
  reconnectWs: () => void;
  benchmarkProgress: BenchmarkProgress;
  setBenchmarkProgress: React.Dispatch<React.SetStateAction<BenchmarkProgress>>;
  toasts: ToastItem[];
  pushToast: (toast: Omit<ToastItem, 'id'>) => void;
  dismissToast: (id: string) => void;
  confirmReq: ConfirmRequest | null;
  requestConfirm: (req: ConfirmRequest) => void;
  closeConfirm: () => void;
  showOnboarding: boolean;
  setShowOnboarding: (open: boolean) => void;
  apiFetch: <T = unknown>(url: string, init?: RequestInit) => Promise<T>;
  refreshBootstrap: () => Promise<void>;
}

const ConsoleContext = createContext<ConsoleContextValue | null>(null);

export const ConsoleProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [state, setState] = useState<ConsoleBootstrapState | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeWorkspace, setActiveWorkspaceRaw] = useState<WorkspaceId>('overview');
  const [subTabs, setSubTabs] = useState<SubTabState>({
    storage: 'live-files',
    'threat-ops': 'telemetry',
    validation: 'simulator',
    settings: 'configuration',
  });
  const [settingsAnchor, setSettingsAnchor] = useState<string | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [selectedBucket, setSelectedBucket] = useState<string>('finance-prod');
  const [role, setRole] = useState<Role>('admin');
  const [wsConnected, setWsConnected] = useState(false);
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const [confirmReq, setConfirmReq] = useState<ConfirmRequest | null>(null);
  const [showOnboarding, setShowOnboarding] = useState(false);
  const [benchmarkProgress, setBenchmarkProgress] = useState<BenchmarkProgress>({
    running: false,
    completed: 0,
    total: 120,
    stage: '',
  });

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const activeSubTab: ActiveSubTab =
    activeWorkspace === 'overview' ? null : subTabs[activeWorkspace];

  const setActiveWorkspace = useCallback((workspace: WorkspaceId) => {
    setActiveWorkspaceRaw(workspace);
  }, []);

  const navigateTo = useCallback(
    <W extends WorkspaceId>(workspace: W, subTab?: WorkspaceSubTabMap[W]) => {
      setActiveWorkspaceRaw(workspace);
      if (workspace !== 'overview' && subTab) {
        setSubTabs((prev) => ({
          ...prev,
          [workspace]: subTab,
        }));
      }
    },
    [],
  );

  const openSettingsSection = useCallback(
    (sectionId: string) => {
      setSettingsAnchor(sectionId);
      navigateTo('settings', 'configuration');
    },
    [navigateTo],
  );

  const openBucket = useCallback(
    (bucket: string) => {
      setSelectedBucket(bucket);
      navigateTo('storage', 'live-files');
    },
    [navigateTo],
  );

  const clearSettingsAnchor = useCallback(() => {
    setSettingsAnchor(null);
  }, []);

  const pushToast = useCallback((toast: Omit<ToastItem, 'id'>) => {
    const id = `t-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    setToasts((prev) => [{ ...toast, id }, ...prev].slice(0, 4));
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4500);
  }, []);

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const apiFetch = useCallback(
    async <T = unknown,>(url: string, init?: RequestInit): Promise<T> => {
      const headers = new Headers(init?.headers || {});
      headers.set('x-defyswarm-role', role);
      if (init?.body && !headers.has('Content-Type')) {
        headers.set('Content-Type', 'application/json');
      }
      const res = await fetch(url, { ...init, headers });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const errMsg =
          (data as { error?: string; errors?: string[] }).error ||
          (data as { errors?: string[] }).errors?.join(' ') ||
          `Request failed (HTTP ${res.status})`;
        const err = new Error(errMsg) as Error & { details?: string[] };
        err.details = (data as { errors?: string[] }).errors;
        throw err;
      }
      return data as T;
    },
    [role],
  );

  const applyBootstrap = useCallback((next: ConsoleBootstrapState) => {
    setState(next);
    setLoading(false);
    setError(null);
  }, []);

  const refreshBootstrap = useCallback(async () => {
    try {
      const res = await fetch('/api/bootstrap', {
        headers: { 'x-defyswarm-role': role },
      });
      if (!res.ok) throw new Error(`Bootstrap failed (${res.status})`);
      const data = (await res.json()) as ConsoleBootstrapState;
      applyBootstrap(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to reach DefySwarm control plane.');
      setLoading(false);
    }
  }, [applyBootstrap, role]);

  const connectWs = useCallback(() => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) return;
    if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/live`;

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setWsConnected(true);
      };

      ws.onclose = () => {
        setWsConnected(false);
        reconnectTimerRef.current = setTimeout(() => {
          connectWs();
        }, 2500);
      };

      ws.onerror = () => {
        setWsConnected(false);
      };

      ws.onmessage = (msg) => {
        try {
          const parsed = JSON.parse(msg.data as string) as { type: string; payload: unknown };
          if (parsed.type === 'snapshot' || parsed.type === 'state:sync') {
            applyBootstrap(parsed.payload as ConsoleBootstrapState);
          } else if (parsed.type === 'event:ingested') {
            const evt = parsed.payload as TelemetryEvent;
            setState((prev) => {
              if (!prev) return prev;
              if (prev.events.some((e) => e.id === evt.id)) return prev;
              return {
                ...prev,
                events: [evt, ...prev.events].slice(0, 140),
              };
            });
          } else if (parsed.type === 'incident:updated') {
            const inc = parsed.payload as IncidentRecord;
            setState((prev) => {
              if (!prev) return prev;
              const idx = prev.incidents.findIndex((i) => i.id === inc.id);
              const nextIncidents =
                idx >= 0
                  ? prev.incidents.map((i) => (i.id === inc.id ? inc : i))
                  : [inc, ...prev.incidents];
              return { ...prev, incidents: nextIncidents };
            });
          } else if (parsed.type === 'sim:update') {
            const sim = parsed.payload as SimRunState;
            setState((prev) => (prev ? { ...prev, simulator: sim } : prev));
          } else if (parsed.type === 'benchmark:progress') {
            const p = parsed.payload as { completed: number; total: number; stage: string };
            setBenchmarkProgress({
              running: p.completed < p.total,
              completed: p.completed,
              total: p.total,
              stage: p.stage,
            });
          } else if (parsed.type === 'health:update') {
            const h = parsed.payload as Pick<ConsoleBootstrapState, 'health' | 'groq' | 'vault'>;
            setState((prev) =>
              prev ? { ...prev, health: h.health, groq: h.groq, vault: h.vault } : prev,
            );
          }
        } catch {
          // Ignore malformed frame
        }
      };
    } catch {
      setWsConnected(false);
    }
  }, [applyBootstrap]);

  useEffect(() => {
    void refreshBootstrap();
    connectWs();
    return () => {
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      wsRef.current?.close();
    };
  }, [connectWs, refreshBootstrap]);

  const requestConfirm = useCallback((req: ConfirmRequest) => setConfirmReq(req), []);
  const closeConfirm = useCallback(() => setConfirmReq(null), []);

  return (
    <ConsoleContext.Provider
      value={{
        state,
        loading,
        error,
        activeWorkspace,
        activeSubTab,
        subTabs,
        setActiveWorkspace,
        navigateTo,
        settingsAnchor,
        openSettingsSection,
        clearSettingsAnchor,
        selectedIncidentId,
        setSelectedIncidentId,
        selectedBucket,
        setSelectedBucket,
        openBucket,
        role,
        setRole,
        wsConnected,
        reconnectWs: connectWs,
        benchmarkProgress,
        setBenchmarkProgress,
        toasts,
        pushToast,
        dismissToast,
        confirmReq,
        requestConfirm,
        closeConfirm,
        showOnboarding,
        setShowOnboarding,
        apiFetch,
        refreshBootstrap,
      }}
    >
      {children}
    </ConsoleContext.Provider>
  );
};

export function useConsole() {
  const ctx = useContext(ConsoleContext);
  if (!ctx) throw new Error('useConsole must be used inside ConsoleProvider');
  return ctx;
}
