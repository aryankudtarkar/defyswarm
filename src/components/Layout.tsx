import React, { useEffect, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import {
  ChevronRight,
  FlaskConical,
  HardDrive,
  KeyRound,
  LayoutGrid,
  Menu,
  PanelLeftClose,
  PanelLeftOpen,
  Radio,
  RefreshCw,
  Search,
  Settings2,
  Shield,
  X,
} from 'lucide-react';
import {
  type ActiveSubTab,
  type WorkspaceId,
  useConsole,
} from '../context/ConsoleContext.tsx';
import type { Role } from '../shared/types.ts';
import { CommandPalette } from './CommandPalette.tsx';
import { Shimmer } from './WorkspaceSkeletons.tsx';

interface WorkspaceNavItem {
  id: WorkspaceId;
  label: string;
  description: string;
  icon: React.FC<{ className?: string }>;
}

const WORKSPACES: WorkspaceNavItem[] = [
  { id: 'overview', label: 'Overview', description: 'Topology & posture', icon: LayoutGrid },
  { id: 'storage', label: 'Storage', description: 'Live files & vault', icon: HardDrive },
  { id: 'threat-ops', label: 'Threat Ops', description: 'Telemetry & incidents', icon: Radio },
  { id: 'validation', label: 'Validation', description: 'Simulator & analytics', icon: FlaskConical },
  { id: 'settings', label: 'Settings', description: 'Config, health & audit', icon: Settings2 },
];

const WORKSPACE_LABELS: Record<WorkspaceId, string> = {
  overview: 'Overview',
  storage: 'Storage',
  'threat-ops': 'Threat Ops',
  validation: 'Validation',
  settings: 'Settings',
};

const SUBTAB_LABELS: Record<Exclude<ActiveSubTab, null>, string> = {
  'live-files': 'Live Files',
  'canaries-vault': 'Canaries & Vault',
  telemetry: 'Live Telemetry',
  incidents: 'Incidents',
  simulator: 'Simulator',
  analytics: 'Analytics',
  configuration: 'Configuration',
  'health-audit': 'Health & Audit',
};

const ROLES: Role[] = ['viewer', 'operator', 'admin'];
const APPLE_SPRING = { type: 'spring' as const, stiffness: 440, damping: 34, mass: 0.75 };

export const Layout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const {
    state,
    loading,
    activeWorkspace,
    activeSubTab,
    setActiveWorkspace,
    role,
    setRole,
    wsConnected,
    reconnectWs,
    toasts,
    dismissToast,
    setShowOnboarding,
  } = useConsole();

  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  const activeBucket = state?.storage.productionBucket || state?.buckets[0]?.name || 'finance-prod';
  const openIncidents =
    state?.incidents.filter((i) => i.status === 'ACTIVE' || i.status === 'CONTAINED').length ?? 0;
  const isHydrating = loading && !state;
  const streamHealthy = wsConnected && !state?.health.streamGapSimulated;
  const degradedStream = !isHydrating && !streamHealthy;
  const isDryRun = state?.policy.mode === 'dry-run';

  const renderSidebarBody = (surface: 'desktop' | 'mobile', onSelect?: () => void) => (
    <div className="flex flex-1 flex-col overflow-hidden">
      {/* Spotlight-style Quick Search ⌘K Trigger */}
      <div className="px-3 pt-3 pb-2">
        <button
          type="button"
          onClick={() => {
            setPaletteOpen(true);
            onSelect?.();
          }}
          className="flex h-[32px] w-full items-center justify-between rounded-[7px] border border-[#E5E7EB] bg-white px-2.5 type-control text-[#6B7280] shadow-[0_1px_1px_rgba(17,24,39,0.02)] transition-colors hover:border-[#D1D5DB] hover:text-[#111827]"
        >
          <span className="flex items-center gap-2 truncate">
            <Search className="h-3.5 w-3.5 shrink-0 text-[#9CA3AF]" />
            <span className="truncate font-normal">Quick search…</span>
          </span>
          <kbd className="rounded border border-[#E5E7EB] bg-[#F8F9FA] px-1.5 py-0.5 font-mono text-[10px] font-medium text-[#6B7280]">
            ⌘K
          </kbd>
        </button>
      </div>

      {/* Single-Source 5-Domain Navigation */}
      <nav className="flex-1 overflow-y-auto px-2.5 py-2" aria-label="Primary workspaces">
        <div className="px-2.5 pb-1.5 type-caption text-[#6B7280]">Workspaces</div>
        <div className="space-y-1">
          {WORKSPACES.map((ws) => {
            const Icon = ws.icon;
            const isActive = activeWorkspace === ws.id;
            return (
              <button
                key={ws.id}
                type="button"
                aria-current={isActive ? 'page' : undefined}
                onClick={() => {
                  setActiveWorkspace(ws.id);
                  onSelect?.();
                }}
                className={`relative flex h-[34px] w-full items-center justify-between rounded-[7px] px-2.5 type-control transition-colors ${
                  isActive
                    ? 'font-semibold text-[#111827]'
                    : 'text-[#4B5563] hover:bg-[#F1F3F5]/80 hover:text-[#111827]'
                }`}
              >
                {isActive && (
                  <motion.span
                    layoutId={`sidebar-active-ws-${surface}`}
                    transition={APPLE_SPRING}
                    className="absolute inset-0 rounded-[7px] bg-[#ECEFF3] shadow-[inset_0_0_0_1px_rgba(17,24,39,0.04)]"
                  />
                )}
                <span className="relative z-10 flex items-center gap-2.5 min-w-0">
                  <Icon
                    className={`h-4 w-4 shrink-0 transition-colors ${
                      isActive ? 'text-[#1D6CF0]' : 'text-[#6B7280]'
                    }`}
                  />
                  <span className="truncate">{ws.label}</span>
                </span>
                {ws.id === 'threat-ops' && openIncidents > 0 && (
                  <span className="relative z-10 inline-flex h-[18px] min-w-[18px] items-center justify-center rounded-[5px] bg-[#FEE2E2] px-1.5 type-mono-data text-[11px] font-semibold text-[#DC2626]">
                    {openIncidents}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </nav>

      {/* Bottom Collapse & Live Connection Strip */}
      <div className="flex h-[42px] items-center justify-between border-t border-[#E5E7EB] px-3 text-[11.5px] text-[#6B7280]">
        <button
          type="button"
          onClick={() => setSidebarCollapsed(true)}
          title="Collapse sidebar"
          aria-label="Collapse sidebar"
          className="hidden rounded-[6px] p-1.5 text-[#6B7280] transition-colors hover:bg-[#ECEFF3] hover:text-[#111827] lg:inline-flex"
        >
          <PanelLeftClose className="h-4 w-4" />
        </button>
        <span
          className={`text-[11.5px] font-medium tracking-[-0.004em] ${
            isHydrating
              ? 'text-[#6B7280]'
              : streamHealthy
                ? 'text-[#4B5563]'
                : 'text-[#B45309]'
          }`}
        >
          {isHydrating ? 'Connecting' : streamHealthy ? 'Connected' : 'Reconnecting'}
        </span>
      </div>
    </div>
  );

  return (
    <div className="flex min-h-screen bg-white text-[#111827]">
      {/* Desktop Collapsible Left Sidebar (#F8F9FA) */}
      {!sidebarCollapsed && (
        <aside className="sticky top-0 hidden h-screen w-[236px] shrink-0 flex-col border-r border-[#E5E7EB] bg-[#F8F9FA] lg:flex">
          <div className="flex h-[48px] items-center gap-2.5 border-b border-[#E5E7EB] px-3.5">
            <div className="flex h-6 w-6 items-center justify-center rounded-[7px] bg-gradient-to-br from-[#F6821F] to-[#EA580C] text-white shadow-[0_1px_2px_rgba(234,88,12,0.28)]">
              <Shield className="h-3.5 w-3.5" />
            </div>
            <span className="truncate font-display text-[14.5px] font-semibold tracking-[-0.02em] text-[#111827]">
              DefySwarm
            </span>
          </div>
          {renderSidebarBody('desktop')}
        </aside>
      )}

      {/* Mobile Drawer with Apple Vibrancy */}
      <AnimatePresence>
        {mobileNavOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.16 }}
            className="fixed inset-0 z-40 bg-[#111827]/28 backdrop-blur-[4px] lg:hidden"
            onClick={() => setMobileNavOpen(false)}
          >
            <motion.aside
              initial={{ x: -264 }}
              animate={{ x: 0 }}
              exit={{ x: -264 }}
              transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
              className="surface-vibrancy-overlay flex h-full w-[252px] flex-col border-r border-[#E5E7EB]"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex h-[48px] items-center justify-between border-b border-[#E5E7EB] px-4">
                <div className="flex items-center gap-2">
                  <div className="flex h-6 w-6 items-center justify-center rounded-[7px] bg-gradient-to-br from-[#F6821F] to-[#EA580C] text-white">
                    <Shield className="h-3.5 w-3.5" />
                  </div>
                  <span className="font-display text-[14px] font-semibold tracking-[-0.02em] text-[#111827]">
                    DefySwarm
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => setMobileNavOpen(false)}
                  aria-label="Close navigation"
                  className="rounded-[6px] p-1 text-[#6B7280] hover:bg-[#F3F4F6]"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
              {renderSidebarBody('mobile', () => setMobileNavOpen(false))}
            </motion.aside>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Main Content Area */}
      <div className="flex min-w-0 flex-1 flex-col bg-white">
        {/* Top Breadcrumb Bar (48px, Apple frosted vibrancy glass) */}
        <header className="surface-vibrancy-bar sticky top-0 z-30 flex h-[48px] items-center justify-between gap-4 border-b border-[#E5E7EB]/90 px-4 sm:px-6">
          <div className="flex items-center gap-2 min-w-0">
            <button
              type="button"
              onClick={() => setMobileNavOpen(true)}
              aria-label="Open navigation"
              className="rounded-[6px] p-1 text-[#6B7280] hover:bg-[#F3F4F6] lg:hidden"
            >
              <Menu className="h-4.5 w-4.5" />
            </button>
            {sidebarCollapsed && (
              <button
                type="button"
                onClick={() => setSidebarCollapsed(false)}
                title="Expand sidebar"
                aria-label="Expand sidebar"
                className="hidden rounded-[6px] p-1 text-[#6B7280] transition-colors hover:bg-[#F3F4F6] hover:text-[#111827] lg:inline-flex"
              >
                <PanelLeftOpen className="h-4 w-4" />
              </button>
            )}

            {/* Dynamic Location Breadcrumb + Quiet Active Bucket Context */}
            <div className="flex items-center gap-1.5 type-control min-w-0">
              <AnimatePresence mode="wait" initial={false}>
                <motion.div
                  key={`${activeWorkspace}:${activeSubTab ?? 'root'}`}
                  initial={{ opacity: 0, y: 2 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -2 }}
                  transition={{ duration: 0.11, ease: [0.22, 1, 0.36, 1] }}
                  className="flex items-center gap-1.5 min-w-0"
                >
                  <span className="font-semibold tracking-[-0.01em] text-[#111827] whitespace-nowrap">
                    {WORKSPACE_LABELS[activeWorkspace]}
                  </span>
                  {activeSubTab && (
                    <>
                      <ChevronRight className="h-3.5 w-3.5 shrink-0 text-[#D1D5DB]" />
                      <span className="font-medium text-[#4B5563] truncate">
                        {SUBTAB_LABELS[activeSubTab]}
                      </span>
                    </>
                  )}
                </motion.div>
              </AnimatePresence>
              <span className="mx-1.5 hidden h-3.5 w-[1px] bg-[#E5E7EB] sm:inline-block" />
              {isHydrating ? (
                <div className="hidden items-center gap-2.5 sm:flex">
                  <Shimmer subtle className="hidden h-[13px] w-24 md:block" />
                  <Shimmer subtle className="h-[13px] w-16" />
                </div>
              ) : (
                <>
                  <span className="hidden font-mono text-[12px] text-[#6B7280] truncate md:inline">
                    {activeBucket}
                  </span>
                  <span
                    className={`hidden sm:inline-flex items-center gap-1.5 text-[12px] font-medium whitespace-nowrap ${
                      isDryRun ? 'text-[#D97706]' : 'text-[#4B5563]'
                    }`}
                  >
                    <span
                      className={`h-1.5 w-1.5 rounded-full ${
                        isDryRun ? 'bg-[#D97706]' : 'bg-[#16A34A]'
                      }`}
                    />
                    {isDryRun ? 'Dry-Run' : 'Production'}
                  </span>
                </>
              )}
            </div>
          </div>

          <div className="flex items-center gap-2.5 shrink-0">
            {/* Discoverable ⌘K trigger when sidebar is collapsed or on mobile */}
            <button
              type="button"
              onClick={() => setPaletteOpen(true)}
              aria-label="Open command palette"
              className={`h-[30px] items-center gap-2 rounded-[7px] border border-[#E5E7EB] bg-white/90 px-2.5 text-[12px] font-medium text-[#6B7280] transition-colors hover:border-[#D1D5DB] hover:bg-white hover:text-[#111827] whitespace-nowrap shrink-0 ${
                sidebarCollapsed ? 'inline-flex' : 'inline-flex lg:hidden'
              }`}
            >
              <Search className="h-3.5 w-3.5 text-[#9CA3AF]" />
              <span className="hidden sm:inline font-normal">Search…</span>
              <kbd className="hidden sm:inline rounded border border-[#E5E7EB] bg-[#F8F9FA] px-1 py-0.5 font-mono text-[10px] font-medium text-[#6B7280]">
                ⌘K
              </kbd>
            </button>

            {/* Shown only after hydration and before AI key is connected */}
            {state && !state.groq.configured && (
              <button
                type="button"
                onClick={() => setShowOnboarding(true)}
                className="hidden md:inline-flex h-[30px] items-center gap-1.5 rounded-[7px] border border-[#E5E7EB] bg-white/90 px-2.5 text-[12px] font-medium tracking-[-0.004em] text-[#374151] transition-colors hover:border-[#D1D5DB] hover:bg-white hover:text-[#111827] whitespace-nowrap shrink-0"
              >
                <KeyRound className="h-3.5 w-3.5 text-[#6B7280]" />
                <span>Connect AI</span>
              </button>
            )}

            {/* Apple Spring-Gliding RBAC Segmented Control */}
            <div
              role="group"
              aria-label="Active console role"
              className="flex h-[30px] items-center rounded-[8px] border border-[#E5E7EB]/80 bg-[#F2F4F7] p-0.5"
            >
              {ROLES.map((r) => {
                const selected = role === r;
                return (
                  <button
                    key={r}
                    type="button"
                    onClick={() => setRole(r)}
                    className={`relative h-full rounded-[6px] px-2.5 text-[11.5px] font-medium capitalize tracking-[-0.004em] transition-colors whitespace-nowrap shrink-0 ${
                      selected ? 'text-[#111827]' : 'text-[#6B7280] hover:text-[#111827]'
                    }`}
                  >
                    {selected && (
                      <motion.span
                        layoutId="rbac-active-thumb"
                        transition={APPLE_SPRING}
                        className="segmented-thumb-shadow absolute inset-0 rounded-[6px] bg-white"
                      />
                    )}
                    <span className="relative z-10">{r}</span>
                  </button>
                );
              })}
            </div>
          </div>
        </header>

        {/* Degraded Stream Banner */}
        <AnimatePresence>
          {degradedStream && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }}
              className="flex flex-wrap items-center justify-between gap-3 border-b border-[#FDE68A] bg-[#FFFBEB] px-6 py-2 text-[12.5px]"
            >
              <span className="font-medium text-[#B45309]">
                {state?.health.streamGapSimulated
                  ? 'Ingestion Stream Gap Active — Live event pipeline paused for degraded-state verification.'
                  : 'WebSocket Telemetry Disconnected — Reconnecting to /ws/live control plane.'}
              </span>
              <button
                type="button"
                onClick={reconnectWs}
                className="inline-flex items-center gap-1.5 rounded-[6px] border border-[#F59E0B]/40 bg-white px-2.5 py-0.5 text-[11.5px] font-medium text-[#B45309] transition-colors hover:bg-[#FEF3C7] whitespace-nowrap shrink-0"
              >
                <RefreshCw className="h-3 w-3" />
                Reconnect
              </button>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Active View Viewport (workspace sub-tab bar & view cross-fades managed in App.tsx) */}
        <main className="flex-1 overflow-x-clip bg-white">{children}</main>
      </div>

      {/* Cmd+K Spotlight Command Palette */}
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />

      {/* Apple Vibrancy Notification Toasts */}
      <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-full max-w-[368px] flex-col gap-2">
        <AnimatePresence>
          {toasts.map((t) => (
            <motion.div
              key={t.id}
              initial={{ opacity: 0, y: 10, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 6, scale: 0.98 }}
              transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }}
              className="surface-vibrancy-toast pointer-events-auto flex items-start justify-between gap-3 rounded-[10px] border border-[#E5E7EB]/80 px-3.5 py-2.5"
            >
              <div className="flex items-start gap-2.5 min-w-0">
                <span
                  className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${
                    t.tone === 'error'
                      ? 'bg-[#DC2626]'
                      : t.tone === 'warning'
                        ? 'bg-[#D97706]'
                        : t.tone === 'success'
                          ? 'bg-[#16A34A]'
                          : 'bg-[#1D6CF0]'
                  }`}
                />
                <div className="min-w-0">
                  <p className="text-[12.5px] font-semibold tracking-[-0.008em] text-[#111827]">
                    {t.title}
                  </p>
                  {t.detail && (
                    <p className="mt-0.5 text-[12px] leading-snug text-[#4B5563]">{t.detail}</p>
                  )}
                </div>
              </div>
              <button
                type="button"
                onClick={() => dismissToast(t.id)}
                className="rounded-[5px] p-0.5 text-[#9CA3AF] transition-colors hover:bg-[#111827]/5 hover:text-[#111827]"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </div>
  );
};
