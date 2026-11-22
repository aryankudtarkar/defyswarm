import React from 'react';
import type { ActiveSubTab, WorkspaceId } from '../context/ConsoleContext.tsx';

interface ShimmerProps {
  className?: string;
  subtle?: boolean;
}

export const Shimmer: React.FC<ShimmerProps> = ({ className = '', subtle = false }) => (
  <span
    aria-hidden="true"
    className={`block rounded-[5px] ${subtle ? 'shimmer-block-subtle' : 'shimmer-block'} ${className}`}
  />
);

const PageHeaderSkeleton: React.FC<{
  titleWidth?: string;
  subtitleWidth?: string;
  actions?: string[];
}> = ({ titleWidth = 'w-44', subtitleWidth = 'w-80', actions = ['w-28', 'w-32'] }) => (
  <div className="flex flex-wrap items-center justify-between gap-3">
    <div className="space-y-2">
      <Shimmer className={`h-[26px] ${titleWidth}`} />
      <Shimmer subtle className={`h-[14px] max-w-full ${subtitleWidth}`} />
    </div>
    {actions.length > 0 && (
      <div className="flex flex-wrap items-center gap-2 shrink-0">
        {actions.map((w, idx) => (
          <Shimmer key={idx} className={`h-[32px] rounded-[7px] ${w}`} />
        ))}
      </div>
    )}
  </div>
);

const KpiStripSkeleton: React.FC<{ cells?: 4 | 5 }> = ({ cells = 4 }) => (
  <div
    className={`surface-card grid grid-cols-1 divide-y divide-[#E5E7EB] overflow-hidden sm:grid-cols-2 sm:divide-y-0 sm:divide-x ${
      cells === 5 ? 'xl:grid-cols-5' : 'xl:grid-cols-4'
    }`}
  >
    {Array.from({ length: cells }).map((_, idx) => (
      <div key={idx} className="px-4 py-4">
        <Shimmer subtle className="h-[13px] w-28" />
        <Shimmer className="mt-2.5 h-[28px] w-24" />
        <Shimmer subtle className="mt-2 h-[12px] w-36" />
      </div>
    ))}
  </div>
);

export const LiveStorageTableSkeleton: React.FC<{ rows?: number }> = ({ rows = 8 }) => (
  <table className="w-full min-w-[600px] text-left text-[12.5px]" aria-busy="true">
    <thead className="kumo-table-head sticky top-0 z-10">
      <tr className="h-[36px] type-caption text-[#6B7280]">
        <th className="pl-4 pr-3 font-medium">Object Key</th>
        <th className="px-3 text-right font-medium">Size</th>
        <th className="px-3 text-right font-medium">Entropy</th>
        <th className="px-3 font-medium">File Signature</th>
        <th className="pl-3 pr-4 text-right font-medium">Vault</th>
      </tr>
    </thead>
    <tbody className="divide-y divide-[#F3F4F6]">
      {Array.from({ length: rows }).map((_, idx) => {
        const keyWidths = ['w-48', 'w-56', 'w-40', 'w-52', 'w-44', 'w-60', 'w-36', 'w-50'];
        return (
          <tr key={idx} className="h-[40px]">
            <td className="pl-4 pr-3">
              <Shimmer className={`h-[13px] ${keyWidths[idx % keyWidths.length]}`} />
            </td>
            <td className="px-3">
              <Shimmer subtle className="ml-auto h-[13px] w-12" />
            </td>
            <td className="px-3">
              <Shimmer subtle className="ml-auto h-[13px] w-10" />
            </td>
            <td className="px-3">
              <Shimmer subtle className="h-[13px] w-20" />
            </td>
            <td className="pl-3 pr-4">
              <Shimmer subtle className="ml-auto h-[13px] w-16" />
            </td>
          </tr>
        );
      })}
    </tbody>
  </table>
);

const OverviewSkeleton: React.FC = () => (
  <div className="mx-auto max-w-[1380px] space-y-6 px-4 py-6 sm:px-6">
    <PageHeaderSkeleton
      titleWidth="w-32"
      subtitleWidth="w-96"
      actions={['w-28', 'w-24']}
    />

    {/* Posture Status Strip */}
    <div className="surface-card flex flex-wrap items-center justify-between gap-4 px-5 py-3.5">
      <div className="flex flex-wrap items-center gap-6">
        <div className="space-y-1.5">
          <Shimmer subtle className="h-[11px] w-20" />
          <Shimmer className="h-[15px] w-32" />
        </div>
        <div className="space-y-1.5">
          <Shimmer subtle className="h-[11px] w-24" />
          <Shimmer className="h-[15px] w-28" />
        </div>
        <div className="space-y-1.5">
          <Shimmer subtle className="h-[11px] w-20" />
          <Shimmer className="h-[15px] w-24" />
        </div>
      </div>
      <Shimmer className="h-[30px] w-28 rounded-[7px]" />
    </div>

    {/* 3-Column Live Protection Topology Skeleton */}
    <section className="surface-card overflow-hidden">
      <div className="flex items-center justify-between border-b border-[#E5E7EB] bg-[#F8F9FA] px-5 py-3">
        <div className="space-y-1.5">
          <Shimmer className="h-[15px] w-44" />
          <Shimmer subtle className="h-[12px] w-64" />
        </div>
        <Shimmer className="h-[28px] w-24 rounded-[6px]" />
      </div>
      <div className="topology-stage grid grid-cols-1 items-center gap-6 p-6 lg:grid-cols-12">
        <div className="space-y-2.5 lg:col-span-4">
          {Array.from({ length: 4 }).map((_, idx) => (
            <div
              key={idx}
              className="flex items-center justify-between rounded-[9px] border border-[#E5E7EB] bg-white px-3.5 py-3"
            >
              <div className="flex items-center gap-2.5">
                <Shimmer className="h-7 w-7 rounded-[7px]" />
                <div className="space-y-1.5">
                  <Shimmer className="h-[13px] w-28" />
                  <Shimmer subtle className="h-[11px] w-36" />
                </div>
              </div>
              <Shimmer subtle className="h-4 w-4 rounded" />
            </div>
          ))}
        </div>

        <div className="lg:col-span-4">
          <div className="rounded-[10px] border border-[#E5E7EB] bg-white p-5">
            <div className="flex items-center gap-3">
              <Shimmer className="h-9 w-9 rounded-[8px]" />
              <div className="space-y-1.5">
                <Shimmer className="h-[15px] w-36" />
                <Shimmer subtle className="h-[12px] w-44" />
              </div>
            </div>
            <div className="mt-4 grid grid-cols-2 gap-2.5 border-t border-[#E5E7EB] pt-4">
              {Array.from({ length: 4 }).map((_, idx) => (
                <div key={idx} className="rounded-[7px] border border-[#F1F3F5] bg-[#FAFAFB] p-2.5">
                  <Shimmer subtle className="h-[11px] w-16" />
                  <Shimmer className="mt-1.5 h-[14px] w-20" />
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="lg:col-span-4">
          <div className="rounded-[10px] border border-[#E5E7EB] bg-white p-4 space-y-3">
            <div className="flex items-center justify-between">
              <Shimmer className="h-[14px] w-28" />
              <Shimmer subtle className="h-[18px] w-14 rounded-full" />
            </div>
            {Array.from({ length: 3 }).map((_, idx) => (
              <div key={idx} className="flex items-center justify-between border-t border-[#F3F4F6] pt-3">
                <div className="space-y-1.5">
                  <Shimmer className="h-[13px] w-32" />
                  <Shimmer subtle className="h-[11px] w-40" />
                </div>
                <Shimmer subtle className="h-[13px] w-14" />
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>

    {/* 8 / 4 Metrics Sparkline + Protected Endpoints */}
    <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
      <section className="surface-card p-5 lg:col-span-8">
        <div className="flex items-center justify-between">
          <div className="space-y-1.5">
            <Shimmer className="h-[15px] w-36" />
            <Shimmer subtle className="h-[12px] w-56" />
          </div>
          <Shimmer className="h-[28px] w-24 rounded-[6px]" />
        </div>
        <div className="mt-5 grid grid-cols-1 gap-4 sm:grid-cols-2">
          {Array.from({ length: 2 }).map((_, idx) => (
            <div key={idx} className="rounded-[8px] border border-[#F1F3F5] p-4">
              <Shimmer subtle className="h-[12px] w-28" />
              <Shimmer className="mt-2 h-[24px] w-20" />
              <Shimmer subtle className="mt-4 h-[64px] w-full rounded-[6px]" />
            </div>
          ))}
        </div>
      </section>

      <section className="surface-card p-5 lg:col-span-4">
        <Shimmer className="h-[15px] w-40" />
        <Shimmer subtle className="mt-1.5 h-[12px] w-48" />
        <div className="mt-4 space-y-3">
          {Array.from({ length: 4 }).map((_, idx) => (
            <div key={idx} className="flex items-center justify-between border-t border-[#F3F4F6] pt-3">
              <div className="space-y-1.5">
                <Shimmer className="h-[13px] w-32" />
                <Shimmer subtle className="h-[11px] w-24" />
              </div>
              <Shimmer subtle className="h-[13px] w-16" />
            </div>
          ))}
        </div>
      </section>
    </div>

    {/* Recent Telemetry Table */}
    <section className="surface-card overflow-hidden">
      <div className="flex items-center justify-between border-b border-[#E5E7EB] bg-[#F8F9FA] px-5 py-3">
        <Shimmer className="h-[14px] w-36" />
        <Shimmer subtle className="h-[13px] w-24" />
      </div>
      <div className="divide-y divide-[#F3F4F6]">
        {Array.from({ length: 5 }).map((_, idx) => (
          <div key={idx} className="flex h-[42px] items-center justify-between gap-4 px-5">
            <Shimmer subtle className="h-[12px] w-16" />
            <Shimmer className="h-[12px] w-28" />
            <Shimmer subtle className="hidden h-[12px] w-44 sm:block" />
            <Shimmer subtle className="h-[12px] w-24" />
            <Shimmer className="h-[12px] w-14" />
          </div>
        ))}
      </div>
    </section>
  </div>
);

const LiveStorageSkeleton: React.FC = () => (
  <div className="mx-auto max-w-[1380px] space-y-6 px-4 py-6 sm:px-6">
    <PageHeaderSkeleton
      titleWidth="w-36"
      subtitleWidth="w-[420px]"
      actions={['w-32', 'w-44', 'w-28']}
    />
    <KpiStripSkeleton cells={4} />

    <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
      <section className="flex flex-col overflow-hidden rounded-lg border border-[#E5E7EB] bg-white lg:col-span-7">
        <div className="flex items-center justify-between border-b border-[#E5E7EB] bg-[#F9FAFB] px-4 py-3">
          <Shimmer className="h-[15px] w-72" />
          <Shimmer className="h-[28px] w-24 rounded-[6px]" />
        </div>
        <div className="flex items-center justify-between gap-3 border-b border-[#E5E7EB] px-4 py-2.5">
          <Shimmer subtle className="h-[28px] w-64 rounded-[7px]" />
          <Shimmer subtle className="h-[30px] w-48 rounded-[7px]" />
        </div>
        <div className="overflow-hidden">
          <LiveStorageTableSkeleton rows={7} />
        </div>
      </section>

      <aside className="surface-card flex flex-col overflow-hidden lg:col-span-5">
        <div className="border-b border-[#E5E7EB] bg-[#F8F9FA] px-4 py-2.5">
          <Shimmer subtle className="h-[28px] w-56 rounded-[7px]" />
        </div>
        <div className="space-y-4 p-5">
          <div className="space-y-2">
            <Shimmer subtle className="h-[12px] w-36" />
            <Shimmer className="h-[16px] w-64" />
          </div>
          <div className="grid grid-cols-2 gap-4 border-t border-[#E5E7EB] pt-4">
            {Array.from({ length: 4 }).map((_, idx) => (
              <div key={idx} className="space-y-1.5">
                <Shimmer subtle className="h-[11px] w-24" />
                <Shimmer className="h-[14px] w-28" />
              </div>
            ))}
          </div>
          <div className="space-y-2 border-t border-[#E5E7EB] pt-4">
            <Shimmer subtle className="h-[11px] w-32" />
            <Shimmer subtle className="h-[12px] w-full" />
          </div>
          <div className="grid grid-cols-2 gap-2 border-t border-[#E5E7EB] pt-4">
            <Shimmer className="h-[32px] w-full rounded-md" />
            <Shimmer className="h-[32px] w-full rounded-md" />
          </div>
          <Shimmer className="h-[34px] w-full rounded-md" />
        </div>
      </aside>
    </div>
  </div>
);

const CanariesVaultSkeleton: React.FC = () => (
  <div className="mx-auto max-w-[1380px] space-y-6 px-4 py-6 sm:px-6">
    <PageHeaderSkeleton
      titleWidth="w-60"
      subtitleWidth="w-[440px]"
      actions={['w-28', 'w-44']}
    />
    <KpiStripSkeleton cells={4} />

    <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
      <section className="surface-card overflow-hidden lg:col-span-8">
        <div className="flex items-center justify-between border-b border-[#E5E7EB] bg-[#F8F9FA] px-5 py-3">
          <Shimmer className="h-[15px] w-44" />
          <Shimmer subtle className="h-[12px] w-28" />
        </div>
        <div className="divide-y divide-[#F3F4F6]">
          {Array.from({ length: 6 }).map((_, idx) => (
            <div key={idx} className="flex h-[42px] items-center justify-between gap-4 px-5">
              <Shimmer className="h-[13px] w-56" />
              <Shimmer subtle className="h-[13px] w-20" />
              <Shimmer subtle className="h-[13px] w-24" />
              <Shimmer subtle className="h-[13px] w-16" />
            </div>
          ))}
        </div>
      </section>

      <aside className="surface-card p-5 space-y-4 lg:col-span-4">
        <div className="flex items-center justify-between">
          <Shimmer className="h-[15px] w-40" />
          <Shimmer subtle className="h-[28px] w-24 rounded-[6px]" />
        </div>
        <Shimmer subtle className="h-[12px] w-full" />
        <Shimmer subtle className="h-[12px] w-4/5" />
        <div className="grid grid-cols-2 gap-3 border-t border-[#E5E7EB] pt-4">
          <div className="space-y-1.5">
            <Shimmer subtle className="h-[11px] w-20" />
            <Shimmer className="h-[24px] w-16" />
          </div>
          <div className="space-y-1.5">
            <Shimmer subtle className="h-[11px] w-24" />
            <Shimmer className="h-[24px] w-20" />
          </div>
        </div>
        <Shimmer className="h-[34px] w-full rounded-[7px]" />
      </aside>
    </div>
  </div>
);

const WarRoomSkeleton: React.FC = () => (
  <div className="mx-auto max-w-[1380px] space-y-6 px-4 py-6 sm:px-6">
    <PageHeaderSkeleton
      titleWidth="w-64"
      subtitleWidth="w-[460px]"
      actions={['w-36']}
    />
    <KpiStripSkeleton cells={4} />

    {/* 8 / 4 Entropy Chart + Risk Score Gauge */}
    <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
      <section className="surface-card p-5 lg:col-span-8">
        <div className="flex items-center justify-between">
          <Shimmer className="h-[15px] w-48" />
          <Shimmer subtle className="h-[12px] w-28" />
        </div>
        <Shimmer subtle className="mt-4 h-[210px] w-full rounded-[8px]" />
      </section>
      <section className="surface-card p-5 lg:col-span-4">
        <Shimmer className="h-[15px] w-36" />
        <div className="mt-6 flex flex-col items-center justify-center gap-3">
          <Shimmer className="h-[132px] w-[132px] rounded-full" />
          <Shimmer subtle className="h-[13px] w-32" />
        </div>
      </section>
    </div>

    {/* 6 / 6 Monitored Credentials + Timeline */}
    <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
      {Array.from({ length: 2 }).map((_, panelIdx) => (
        <section key={panelIdx} className="surface-card overflow-hidden lg:col-span-6">
          <div className="border-b border-[#E5E7EB] bg-[#F8F9FA] px-5 py-3">
            <Shimmer className="h-[14px] w-40" />
          </div>
          <div className="divide-y divide-[#F3F4F6]">
            {Array.from({ length: 4 }).map((_, idx) => (
              <div key={idx} className="flex h-[42px] items-center justify-between gap-3 px-5">
                <Shimmer className="h-[13px] w-36" />
                <Shimmer subtle className="h-[13px] w-24" />
                <Shimmer subtle className="h-[13px] w-16" />
              </div>
            ))}
          </div>
        </section>
      ))}
    </div>

    {/* Full-Width Live Activity Table */}
    <section className="surface-card overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#E5E7EB] bg-[#F8F9FA] px-5 py-3">
        <Shimmer className="h-[14px] w-40" />
        <div className="flex items-center gap-2">
          <Shimmer subtle className="h-[28px] w-44 rounded-[7px]" />
          <Shimmer subtle className="h-[28px] w-48 rounded-[7px]" />
        </div>
      </div>
      <div className="divide-y divide-[#F3F4F6]">
        {Array.from({ length: 6 }).map((_, idx) => (
          <div key={idx} className="flex h-[40px] items-center justify-between gap-4 px-5">
            <Shimmer subtle className="h-[12px] w-16" />
            <Shimmer className="h-[12px] w-28" />
            <Shimmer subtle className="hidden h-[12px] w-48 md:block" />
            <Shimmer subtle className="h-[12px] w-24" />
            <Shimmer className="h-[12px] w-16" />
          </div>
        ))}
      </div>
    </section>
  </div>
);

const IncidentsSkeleton: React.FC = () => (
  <div className="mx-auto max-w-[1380px] space-y-6 px-4 py-6 sm:px-6">
    <PageHeaderSkeleton
      titleWidth="w-60"
      subtitleWidth="w-[460px]"
      actions={['w-64']}
    />

    {/* 8 / 4 Summary Strip */}
    <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
      <div className="surface-card grid grid-cols-1 divide-y divide-[#E5E7EB] sm:grid-cols-3 sm:divide-y-0 sm:divide-x lg:col-span-8">
        {Array.from({ length: 3 }).map((_, idx) => (
          <div key={idx} className="px-4 py-4">
            <Shimmer subtle className="h-[12px] w-24" />
            <Shimmer className="mt-2 h-[26px] w-16" />
            <Shimmer subtle className="mt-1.5 h-[12px] w-32" />
          </div>
        ))}
      </div>
      <div className="surface-card p-4 lg:col-span-4">
        <Shimmer subtle className="h-[12px] w-32" />
        <Shimmer subtle className="mt-3 h-[56px] w-full rounded-[6px]" />
      </div>
    </div>

    {/* 4 / 8 Master-Detail Incident Queue */}
    <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
      <section className="surface-card overflow-hidden lg:col-span-4">
        <div className="border-b border-[#E5E7EB] bg-[#F8F9FA] px-4 py-3">
          <Shimmer className="h-[14px] w-32" />
        </div>
        <div className="divide-y divide-[#F3F4F6]">
          {Array.from({ length: 5 }).map((_, idx) => (
            <div key={idx} className="space-y-2 p-4">
              <div className="flex items-center justify-between">
                <Shimmer className="h-[13px] w-32" />
                <Shimmer subtle className="h-[12px] w-16" />
              </div>
              <Shimmer subtle className="h-[12px] w-48" />
            </div>
          ))}
        </div>
      </section>

      <section className="surface-card p-5 space-y-5 lg:col-span-8">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#E5E7EB] pb-4">
          <div className="space-y-2">
            <Shimmer className="h-[18px] w-56" />
            <Shimmer subtle className="h-[12px] w-72" />
          </div>
          <div className="flex items-center gap-2">
            <Shimmer className="h-[32px] w-28 rounded-[7px]" />
            <Shimmer className="h-[32px] w-32 rounded-[7px]" />
          </div>
        </div>
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {Array.from({ length: 4 }).map((_, idx) => (
            <div key={idx} className="space-y-1.5">
              <Shimmer subtle className="h-[11px] w-20" />
              <Shimmer className="h-[16px] w-24" />
            </div>
          ))}
        </div>
        <div className="space-y-2.5 border-t border-[#E5E7EB] pt-4">
          <Shimmer className="h-[14px] w-40" />
          {Array.from({ length: 4 }).map((_, idx) => (
            <div key={idx} className="flex h-[36px] items-center justify-between border-b border-[#F3F4F6]">
              <Shimmer subtle className="h-[12px] w-52" />
              <Shimmer subtle className="h-[12px] w-24" />
            </div>
          ))}
        </div>
      </section>
    </div>
  </div>
);

const SimulatorSkeleton: React.FC = () => (
  <div className="mx-auto max-w-[1380px] space-y-6 px-4 py-6 sm:px-6">
    <PageHeaderSkeleton
      titleWidth="w-44"
      subtitleWidth="w-[460px]"
      actions={['w-36', 'w-32']}
    />

    {/* Blast-Radius Guard Bar */}
    <div className="surface-card flex flex-wrap items-center justify-between gap-4 px-4 py-3.5">
      <Shimmer className="h-[15px] w-80" />
      <Shimmer subtle className="h-[30px] w-44 rounded-md" />
    </div>

    {/* 2x2 Attack Drill Cards */}
    <div className="grid grid-cols-1 gap-5 md:grid-cols-2">
      {Array.from({ length: 4 }).map((_, idx) => (
        <div key={idx} className="surface-card flex flex-col justify-between p-5">
          <div className="space-y-2.5">
            <div className="flex items-center justify-between">
              <Shimmer className="h-[16px] w-44" />
              <Shimmer subtle className="h-[20px] w-20 rounded-md" />
            </div>
            <Shimmer subtle className="h-[13px] w-full" />
            <Shimmer subtle className="h-[13px] w-5/6" />
          </div>
          <div className="mt-5 flex items-center justify-between border-t border-[#F3F4F6] pt-4">
            <Shimmer subtle className="h-[12px] w-32" />
            <Shimmer className="h-[32px] w-32 rounded-[7px]" />
          </div>
        </div>
      ))}
    </div>

    {/* Verification Checklist Panel */}
    <section className="surface-card p-5 space-y-3">
      <Shimmer className="h-[15px] w-44" />
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        {Array.from({ length: 3 }).map((_, idx) => (
          <div key={idx} className="rounded-[8px] border border-[#F1F3F5] p-3.5 space-y-2">
            <Shimmer className="h-[13px] w-32" />
            <Shimmer subtle className="h-[12px] w-44" />
          </div>
        ))}
      </div>
    </section>
  </div>
);

const AnalyticsSkeleton: React.FC = () => (
  <div className="mx-auto max-w-[1380px] space-y-6 px-4 py-6 sm:px-6">
    <PageHeaderSkeleton
      titleWidth="w-64"
      subtitleWidth="w-[460px]"
      actions={['w-44', 'w-28', 'w-40']}
    />
    <KpiStripSkeleton cells={5} />

    {/* Scenario Comparison Table + Signal Breakdown */}
    <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
      <section className="surface-card overflow-hidden lg:col-span-8">
        <div className="border-b border-[#E5E7EB] bg-[#F8F9FA] px-5 py-3">
          <Shimmer className="h-[14px] w-48" />
        </div>
        <div className="divide-y divide-[#F3F4F6]">
          {Array.from({ length: 5 }).map((_, idx) => (
            <div key={idx} className="flex h-[42px] items-center justify-between gap-4 px-5">
              <Shimmer className="h-[13px] w-40" />
              <Shimmer subtle className="h-[13px] w-16" />
              <Shimmer subtle className="h-[13px] w-16" />
              <Shimmer subtle className="h-[13px] w-20" />
              <Shimmer subtle className="h-[13px] w-16" />
            </div>
          ))}
        </div>
      </section>

      <section className="surface-card p-5 space-y-4 lg:col-span-4">
        <Shimmer className="h-[14px] w-40" />
        {Array.from({ length: 4 }).map((_, idx) => (
          <div key={idx} className="space-y-1.5">
            <div className="flex justify-between">
              <Shimmer subtle className="h-[12px] w-28" />
              <Shimmer subtle className="h-[12px] w-10" />
            </div>
            <Shimmer className="h-[8px] w-full rounded-full" />
          </div>
        ))}
      </section>
    </div>
  </div>
);

const SetupSkeleton: React.FC = () => (
  <div className="mx-auto max-w-[1380px] space-y-6 px-4 py-6 sm:px-6">
    <PageHeaderSkeleton
      titleWidth="w-40"
      subtitleWidth="w-96"
      actions={['w-44']}
    />

    <div className="grid grid-cols-1 items-start gap-6 lg:grid-cols-[minmax(0,1fr)_208px]">
      <div className="space-y-5">
        {Array.from({ length: 3 }).map((_, cardIdx) => (
          <section key={cardIdx} className="surface-card overflow-hidden">
            <div className="flex items-center justify-between border-b border-[#E5E7EB] bg-[#F8F9FA] px-5 py-3.5">
              <div className="space-y-1.5">
                <Shimmer className="h-[15px] w-44" />
                <Shimmer subtle className="h-[12px] w-72" />
              </div>
              <Shimmer className="h-[30px] w-24 rounded-[7px]" />
            </div>
            <div className="grid grid-cols-1 gap-4 p-5 sm:grid-cols-2">
              {Array.from({ length: 4 }).map((_, fieldIdx) => (
                <div key={fieldIdx} className="space-y-2">
                  <Shimmer subtle className="h-[12px] w-28" />
                  <Shimmer subtle className="h-[34px] w-full rounded-md" />
                </div>
              ))}
            </div>
          </section>
        ))}
      </div>

      {/* Right Sticky Section Anchor Rail */}
      <aside className="hidden space-y-2 border-l border-[#E5E7EB] pl-4 lg:block">
        <Shimmer subtle className="mb-3 h-[11px] w-20" />
        {Array.from({ length: 8 }).map((_, idx) => (
          <Shimmer key={idx} subtle className="h-[24px] w-36" />
        ))}
      </aside>
    </div>
  </div>
);

const HealthSkeleton: React.FC = () => (
  <div className="mx-auto max-w-[1380px] space-y-6 px-4 py-6 sm:px-6">
    <PageHeaderSkeleton
      titleWidth="w-56"
      subtitleWidth="w-96"
      actions={['w-40']}
    />
    <KpiStripSkeleton cells={4} />

    {/* 4-Column Component Health Strip */}
    <div className="surface-card grid grid-cols-1 divide-y divide-[#E5E7EB] overflow-hidden md:grid-cols-2 md:divide-y-0 md:divide-x xl:grid-cols-4">
      {Array.from({ length: 4 }).map((_, idx) => (
        <div key={idx} className="flex items-start justify-between gap-3 px-4 py-3.5">
          <div className="space-y-1.5">
            <Shimmer className="h-[13px] w-32" />
            <Shimmer subtle className="h-[12px] w-44" />
          </div>
          <Shimmer subtle className="h-4 w-4 rounded-full" />
        </div>
      ))}
    </div>

    {/* Operator Audit Log Table */}
    <section className="surface-card overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#E5E7EB] bg-[#F8F9FA] px-5 py-3">
        <Shimmer className="h-[14px] w-44" />
        <Shimmer subtle className="h-[30px] w-56 rounded-[7px]" />
      </div>
      <div className="divide-y divide-[#F3F4F6]">
        {Array.from({ length: 6 }).map((_, idx) => (
          <div key={idx} className="flex h-[40px] items-center justify-between gap-4 px-5">
            <Shimmer subtle className="h-[12px] w-20" />
            <Shimmer className="h-[12px] w-32" />
            <Shimmer subtle className="h-[12px] w-20" />
            <Shimmer subtle className="hidden h-[12px] w-64 sm:block" />
          </div>
        ))}
      </div>
    </section>
  </div>
);

export const WorkspaceSkeleton: React.FC<{
  workspace: WorkspaceId;
  subTab: ActiveSubTab;
}> = ({ workspace, subTab }) => {
  return (
    <div role="status" aria-busy="true" aria-label="Loading workspace">
      {workspace === 'overview' ? (
        <OverviewSkeleton />
      ) : workspace === 'storage' && subTab === 'live-files' ? (
        <LiveStorageSkeleton />
      ) : workspace === 'storage' && subTab === 'canaries-vault' ? (
        <CanariesVaultSkeleton />
      ) : workspace === 'threat-ops' && subTab === 'telemetry' ? (
        <WarRoomSkeleton />
      ) : workspace === 'threat-ops' && subTab === 'incidents' ? (
        <IncidentsSkeleton />
      ) : workspace === 'validation' && subTab === 'simulator' ? (
        <SimulatorSkeleton />
      ) : workspace === 'validation' && subTab === 'analytics' ? (
        <AnalyticsSkeleton />
      ) : workspace === 'settings' && subTab === 'configuration' ? (
        <SetupSkeleton />
      ) : (
        <HealthSkeleton />
      )}
    </div>
  );
};
