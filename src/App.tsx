/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useRef } from 'react';
import { AnimatePresence, MotionConfig, motion } from 'motion/react';
import { RefreshCw } from 'lucide-react';
import { ConfirmSheet } from './components/ConfirmSheet.tsx';
import { Layout } from './components/Layout.tsx';
import { OnboardingModal } from './components/OnboardingModal.tsx';
import { WorkspaceSkeleton } from './components/WorkspaceSkeletons.tsx';
import {
  type ActiveSubTab,
  ConsoleProvider,
  type SettingsSubTab,
  type StorageSubTab,
  type ThreatOpsSubTab,
  type ValidationSubTab,
  type WorkspaceId,
  useConsole,
} from './context/ConsoleContext.tsx';
import { AnalyticsView } from './views/AnalyticsView.tsx';
import { CanariesVaultView } from './views/CanariesVaultView.tsx';
import { HealthView } from './views/HealthView.tsx';
import { IncidentsView } from './views/IncidentsView.tsx';
import { LiveStorageView } from './views/LiveStorageView.tsx';
import { OverviewView } from './views/OverviewView.tsx';
import { SetupView } from './views/SetupView.tsx';
import { SimulatorView } from './views/SimulatorView.tsx';
import { WarRoomView } from './views/WarRoomView.tsx';

interface SubTabDef<T extends string> {
  id: T;
  label: string;
}

const STORAGE_TABS: SubTabDef<StorageSubTab>[] = [
  { id: 'live-files', label: 'Live Files' },
  { id: 'canaries-vault', label: 'Canaries & Vault' },
];

const THREAT_OPS_TABS: SubTabDef<ThreatOpsSubTab>[] = [
  { id: 'telemetry', label: 'Live Telemetry' },
  { id: 'incidents', label: 'Incidents' },
];

const VALIDATION_TABS: SubTabDef<ValidationSubTab>[] = [
  { id: 'simulator', label: 'Simulator' },
  { id: 'analytics', label: 'Analytics' },
];

const SETTINGS_TABS: SubTabDef<SettingsSubTab>[] = [
  { id: 'configuration', label: 'Configuration' },
  { id: 'health-audit', label: 'Health & Audit' },
];

const SUBTAB_ORDER: Record<Exclude<ActiveSubTab, null>, number> = {
  'live-files': 0,
  'canaries-vault': 1,
  telemetry: 0,
  incidents: 1,
  simulator: 0,
  analytics: 1,
  configuration: 0,
  'health-audit': 1,
};

const WORKSPACE_HINTS: Record<Exclude<WorkspaceId, 'overview'>, string> = {
  storage: 'Buckets, objects, adaptive decoys, and immutable WORM vault',
  'threat-ops': 'Live event telemetry, credential standing, and verified recovery',
  validation: 'Controlled ransomware drills and detection performance benchmarks',
  settings: 'Policies, storage connectors, AI analysis, system health, and audit log',
};

const APPLE_SPRING = { type: 'spring' as const, stiffness: 480, damping: 36, mass: 0.68 };
const EASE_OUT_EXPO: [number, number, number, number] = [0.22, 1, 0.36, 1];

interface TransitionContext {
  kind: 'workspace' | 'subtab';
  direction: 1 | -1;
}

const viewVariants = {
  initial: (ctx: TransitionContext) =>
    ctx.kind === 'subtab'
      ? { opacity: 0, x: ctx.direction * 10, y: 0 }
      : { opacity: 0, x: 0, y: 5 },
  animate: {
    opacity: 1,
    x: 0,
    y: 0,
    transition: { duration: 0.16, ease: EASE_OUT_EXPO },
  },
  exit: (ctx: TransitionContext) =>
    ctx.kind === 'subtab'
      ? {
          opacity: 0,
          x: ctx.direction * -8,
          y: 0,
          transition: { duration: 0.09, ease: EASE_OUT_EXPO },
        }
      : {
          opacity: 0,
          x: 0,
          y: -4,
          transition: { duration: 0.09, ease: EASE_OUT_EXPO },
        },
};

const WorkspaceSubTabBar: React.FC = () => {
  const { state, activeWorkspace, activeSubTab, navigateTo } = useConsole();

  const openIncidents =
    state?.incidents.filter((i) => i.status === 'ACTIVE' || i.status === 'CONTAINED').length ?? 0;

  const isMultiTab = activeWorkspace !== 'overview';

  const tabs: Array<{ id: string; label: string; badge?: number; onSelect: () => void }> =
    activeWorkspace === 'storage'
      ? STORAGE_TABS.map((t) => ({
          id: t.id,
          label: t.label,
          onSelect: () => navigateTo('storage', t.id),
        }))
      : activeWorkspace === 'threat-ops'
        ? THREAT_OPS_TABS.map((t) => ({
            id: t.id,
            label: t.label,
            badge: t.id === 'incidents' && openIncidents > 0 ? openIncidents : undefined,
            onSelect: () => navigateTo('threat-ops', t.id),
          }))
        : activeWorkspace === 'validation'
          ? VALIDATION_TABS.map((t) => ({
              id: t.id,
              label: t.label,
              onSelect: () => navigateTo('validation', t.id),
            }))
          : activeWorkspace === 'settings'
            ? SETTINGS_TABS.map((t) => ({
                id: t.id,
                label: t.label,
                onSelect: () => navigateTo('settings', t.id),
              }))
            : [];

  return (
    <AnimatePresence initial={false}>
      {isMultiTab && (
        <motion.div
          key="workspace-subtab-strip"
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          exit={{ opacity: 0, height: 0 }}
          transition={{ duration: 0.16, ease: EASE_OUT_EXPO }}
          className="overflow-hidden border-b border-[#E5E7EB] bg-[#FAFAFB]"
        >
          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              key={activeWorkspace}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.11, ease: EASE_OUT_EXPO }}
              className="mx-auto flex max-w-[1380px] flex-wrap items-center justify-between gap-3 px-4 py-2 sm:px-6"
            >
              <div
                role="tablist"
                aria-label="Workspace views"
                className="inline-flex items-center gap-0.5 rounded-[8px] border border-[#E5E7EB]/85 bg-[#F2F4F7] p-0.5"
              >
                {tabs.map((tab) => {
                  const selected = activeSubTab === tab.id;
                  return (
                    <button
                      key={tab.id}
                      type="button"
                      role="tab"
                      aria-selected={selected}
                      onClick={tab.onSelect}
                      className={`relative flex h-[28px] items-center gap-1.5 rounded-[6px] px-3 type-control transition-colors whitespace-nowrap shrink-0 ${
                        selected ? 'text-[#111827]' : 'text-[#6B7280] hover:text-[#111827]'
                      }`}
                    >
                      {selected && (
                        <motion.span
                          layoutId={`subtab-thumb-${activeWorkspace}`}
                          transition={APPLE_SPRING}
                          className="segmented-thumb-shadow absolute inset-0 rounded-[6px] bg-white"
                        />
                      )}
                      <span className="relative z-10">{tab.label}</span>
                      {tab.badge !== undefined && (
                        <span className="relative z-10 inline-flex h-[17px] min-w-[17px] items-center justify-center rounded-[4px] bg-[#FEE2E2] px-1 type-mono-data text-[10.5px] font-semibold text-[#DC2626]">
                          {tab.badge}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>

              <p className="hidden text-[12px] text-[#6B7280] md:block">
                {WORKSPACE_HINTS[activeWorkspace]}
              </p>
            </motion.div>
          </AnimatePresence>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

const ConsoleRouter: React.FC = () => {
  const { state, activeWorkspace, activeSubTab, loading, error, refreshBootstrap } = useConsole();

  const prevNavRef = useRef<{ workspace: WorkspaceId; subTab: ActiveSubTab }>({
    workspace: activeWorkspace,
    subTab: activeSubTab,
  });

  // Compute transition kind & horizontal direction synchronously before render commits
  const transitionCtx: TransitionContext = (() => {
    const prev = prevNavRef.current;
    if (prev.workspace === activeWorkspace && prev.subTab !== activeSubTab) {
      const prevIdx = prev.subTab ? SUBTAB_ORDER[prev.subTab] : 0;
      const nextIdx = activeSubTab ? SUBTAB_ORDER[activeSubTab] : 0;
      return { kind: 'subtab', direction: nextIdx >= prevIdx ? 1 : -1 };
    }
    return { kind: 'workspace', direction: 1 };
  })();

  useEffect(() => {
    prevNavRef.current = { workspace: activeWorkspace, subTab: activeSubTab };
  }, [activeWorkspace, activeSubTab]);

  if (!loading && error && !state) {
    return (
      <Layout>
        <div className="flex min-h-[calc(100vh-48px)] flex-col items-center justify-center bg-white px-4 text-center text-[#111827]">
          <p className="text-[15px] font-semibold text-[#DC2626]">Control Plane Unreachable</p>
          <p className="mt-1.5 max-w-md text-[12.5px] text-[#4B5563]">{error}</p>
          <button
            type="button"
            onClick={() => void refreshBootstrap()}
            className="mt-4 inline-flex h-[32px] items-center gap-1.5 rounded-md bg-[#1D6CF0] px-3.5 text-[12px] font-medium text-white hover:bg-[#1558D6] transition-colors"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Retry Connection
          </button>
        </div>
      </Layout>
    );
  }

  const routeKey = `${activeWorkspace}:${activeSubTab ?? 'root'}`;
  const isHydrating = loading || !state;

  const activeView = isHydrating ? (
    <WorkspaceSkeleton workspace={activeWorkspace} subTab={activeSubTab} />
  ) : activeWorkspace === 'overview' ? (
    <OverviewView />
  ) : activeWorkspace === 'storage' && activeSubTab === 'live-files' ? (
    <LiveStorageView />
  ) : activeWorkspace === 'storage' && activeSubTab === 'canaries-vault' ? (
    <CanariesVaultView />
  ) : activeWorkspace === 'threat-ops' && activeSubTab === 'telemetry' ? (
    <WarRoomView />
  ) : activeWorkspace === 'threat-ops' && activeSubTab === 'incidents' ? (
    <IncidentsView />
  ) : activeWorkspace === 'validation' && activeSubTab === 'simulator' ? (
    <SimulatorView />
  ) : activeWorkspace === 'validation' && activeSubTab === 'analytics' ? (
    <AnalyticsView />
  ) : activeWorkspace === 'settings' && activeSubTab === 'configuration' ? (
    <SetupView />
  ) : (
    <HealthView />
  );

  return (
    <Layout>
      <WorkspaceSubTabBar />
      <AnimatePresence mode="wait" initial={false} custom={transitionCtx}>
        <motion.div
          key={isHydrating ? `skeleton:${routeKey}` : routeKey}
          custom={transitionCtx}
          variants={viewVariants}
          initial="initial"
          animate="animate"
          exit="exit"
          className="min-h-[calc(100vh-92px)] will-change-[opacity,transform]"
        >
          {activeView}
        </motion.div>
      </AnimatePresence>
      <OnboardingModal />
      <ConfirmSheet />
    </Layout>
  );
};

export default function App() {
  return (
    <MotionConfig reducedMotion="user">
      <ConsoleProvider>
        <ConsoleRouter />
      </ConsoleProvider>
    </MotionConfig>
  );
}
