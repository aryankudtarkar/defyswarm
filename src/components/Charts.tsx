import React, { useMemo, useState } from 'react';
import { motion } from 'motion/react';
import type { TelemetryEvent } from '../shared/types.ts';

interface SparklineAreaProps {
  values: number[];
  height?: number;
  strokeColor?: string;
  fillId: string;
  empty?: boolean;
  emptyLabel?: string;
}

export const SparklineArea: React.FC<SparklineAreaProps> = ({
  values,
  height = 46,
  strokeColor = '#1D6CF0',
  fillId,
  empty = false,
  emptyLabel = 'No data',
}) => {
  if (empty || values.length < 2) {
    return (
      <div
        className="relative flex w-full items-center justify-center"
        style={{ height }}
        aria-label={emptyLabel}
      >
        <div className="pointer-events-none absolute inset-x-0 top-1/2 -translate-y-1/2 border-b border-[#E5E7EB]" />
        <span className="relative z-10 bg-white px-2.5 text-[11px] font-medium text-[#9CA3AF]">
          {emptyLabel}
        </span>
      </div>
    );
  }

  const width = 220;
  const min = Math.min(...values);
  const max = Math.max(...values, min + 1);
  const padTop = 6;
  const padBottom = 2;
  const plotH = height - padTop - padBottom;

  const points = values.map((v, i) => {
    const x = (i / (values.length - 1)) * width;
    const y = padTop + (1 - (v - min) / (max - min)) * plotH;
    return { x, y };
  });

  const linePath = points
    .map((pt, i) => `${i === 0 ? 'M' : 'L'} ${pt.x.toFixed(1)} ${pt.y.toFixed(1)}`)
    .join(' ');
  const areaPath = `${linePath} L ${width} ${height} L 0 ${height} Z`;

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      className="block w-full"
      style={{ height }}
      aria-hidden="true"
    >
      <defs>
        <linearGradient id={fillId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={strokeColor} stopOpacity="0.16" />
          <stop offset="100%" stopColor={strokeColor} stopOpacity="0.02" />
        </linearGradient>
      </defs>
      <path d={areaPath} fill={`url(#${fillId})`} />
      <path
        d={linePath}
        fill="none"
        stroke={strokeColor}
        strokeWidth="1.5"
        vectorEffect="non-scaling-stroke"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
};

interface EntropyChartProps {
  events: TelemetryEvent[];
  deltaThreshold: number;
  onSelectEvent?: (event: TelemetryEvent) => void;
}

export const EntropyTimeSeriesChart: React.FC<EntropyChartProps> = ({
  events,
  deltaThreshold,
  onSelectEvent,
}) => {
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);

  const points = useMemo(() => {
    return [...events]
      .filter((e) => typeof e.entropy === 'number' && e.entropy > 0)
      .slice(0, 56)
      .reverse();
  }, [events]);

  const width = 680;
  const height = 186;
  const pad = { top: 14, right: 14, bottom: 22, left: 34 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;

  const yMin = 3.0;
  const yMax = 8.2;
  const toY = (h: number) =>
    pad.top + ((yMax - Math.min(yMax, Math.max(yMin, h))) / (yMax - yMin)) * plotH;
  const toX = (idx: number) =>
    points.length <= 1 ? pad.left + plotW / 2 : pad.left + (idx / (points.length - 1)) * plotW;

  const pathD = useMemo(() => {
    if (points.length === 0) return '';
    return points
      .map(
        (pt, idx) =>
          `${idx === 0 ? 'M' : 'L'} ${toX(idx).toFixed(1)} ${toY(pt.entropy ?? 4).toFixed(1)}`,
      )
      .join(' ');
  }, [points]);

  const areaD = useMemo(() => {
    if (points.length < 2) return '';
    const lastX = toX(points.length - 1).toFixed(1);
    const firstX = toX(0).toFixed(1);
    const baseY = (pad.top + plotH).toFixed(1);
    return `${pathD} L ${lastX} ${baseY} L ${firstX} ${baseY} Z`;
  }, [pathD, points.length, plotH]);

  const hovered = hoverIdx !== null ? points[hoverIdx] : null;
  const encryptGuideY = toY(7.5);

  return (
    <div className="relative">
      <div className="mb-2.5 flex items-center justify-between gap-4">
        <div>
          <h3 className="type-section text-[14px]">
            Payload Entropy Stream
          </h3>
          <p className="mt-0.5 text-[12px] text-[#6B7280]">
            Threshold ΔH ≥ {deltaThreshold.toFixed(1)} · Click any point to inspect event
          </p>
        </div>
        {hovered ? (
          <div className="text-right text-[11.5px] tabular-nums">
            <span className="font-semibold text-[#111827]">H {hovered.entropy?.toFixed(3)}</span>
            {typeof hovered.deltaEntropy === 'number' && (
              <span
                className={`ml-2 font-medium ${
                  hovered.deltaEntropy >= deltaThreshold ? 'text-[#DC2626]' : 'text-[#4B5563]'
                }`}
              >
                ΔH {hovered.deltaEntropy >= 0 ? '+' : ''}
                {hovered.deltaEntropy.toFixed(2)}
              </span>
            )}
            <div className="font-mono text-[10.5px] text-[#6B7280] truncate max-w-[230px]">
              {hovered.key || hovered.apiOp}
            </div>
          </div>
        ) : (
          <div className="flex items-center gap-2 text-[11.5px] text-[#6B7280] tabular-nums">
            <span>{points.length} samples</span>
            <span>·</span>
            <span>3.0–8.0 bits/byte</span>
          </div>
        )}
      </div>

      {points.length === 0 ? (
        <div className="flex h-[186px] items-center justify-center rounded-md border border-[#E5E7EB] bg-[#F9FAFB] text-[12px] text-[#6B7280]">
          Upload a file in Live Storage or run a drill in Attack Simulator to stream entropy telemetry.
        </div>
      ) : (
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="h-[186px] w-full select-none overflow-visible"
          onMouseLeave={() => setHoverIdx(null)}
        >
          <defs>
            <linearGradient id="lightEntropyArea" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#1D6CF0" stopOpacity="0.16" />
              <stop offset="100%" stopColor="#1D6CF0" stopOpacity="0.01" />
            </linearGradient>
          </defs>

          {[4, 5, 6, 7, 8].map((tick) => {
            const y = toY(tick);
            return (
              <g key={tick}>
                <line
                  x1={pad.left}
                  y1={y}
                  x2={width - pad.right}
                  y2={y}
                  stroke="#EEF0F3"
                  strokeWidth="1"
                />
                <text
                  x={pad.left - 8}
                  y={y + 3.5}
                  textAnchor="end"
                  fill="#6B7280"
                  fontSize="10"
                  fontFamily="SF Mono, ui-monospace, JetBrains Mono, monospace"
                >
                  {tick}.0
                </text>
              </g>
            );
          })}

          {/* Ciphertext zone threshold line */}
          <line
            x1={pad.left}
            y1={encryptGuideY}
            x2={width - pad.right}
            y2={encryptGuideY}
            stroke="rgba(220,38,38,0.45)"
            strokeDasharray="3 3"
            strokeWidth="1"
          />
          <text
            x={width - pad.right}
            y={encryptGuideY - 5}
            textAnchor="end"
            fill="#DC2626"
            fontSize="9.5"
            fontFamily="SF Mono, ui-monospace, JetBrains Mono, monospace"
          >
            Ciphertext zone (H ≥ 7.5)
          </text>

          {/* Vertical Hover Crosshair */}
          {hoverIdx !== null && (
            <line
              x1={toX(hoverIdx)}
              y1={pad.top}
              x2={toX(hoverIdx)}
              y2={pad.top + plotH}
              stroke="#9CA3AF"
              strokeDasharray="2 2"
              strokeWidth="1"
            />
          )}

          {areaD && <path d={areaD} fill="url(#lightEntropyArea)" />}
          <path
            d={pathD}
            fill="none"
            stroke="#1D6CF0"
            strokeWidth="1.75"
            strokeLinecap="round"
            strokeLinejoin="round"
          />

          {points.map((pt, idx) => {
            const cx = toX(idx);
            const cy = toY(pt.entropy ?? 4);
            const flagged =
              pt.signals.includes('entropy_delta') ||
              pt.signals.includes('magic_header_lost') ||
              pt.signals.includes('ssec_abuse');
            const isActive = hoverIdx === idx;
            return (
              <g key={pt.id} className={onSelectEvent ? 'cursor-pointer' : ''}>
                <circle
                  cx={cx}
                  cy={cy}
                  r={isActive ? 4.5 : flagged ? 3.5 : 2.25}
                  fill={flagged ? '#DC2626' : '#16A34A'}
                  stroke="#FFFFFF"
                  strokeWidth="1.5"
                />
                <rect
                  x={cx - Math.max(5, plotW / Math.max(points.length, 12) / 2)}
                  y={pad.top}
                  width={Math.max(10, plotW / Math.max(points.length, 12))}
                  height={plotH}
                  fill="transparent"
                  onMouseEnter={() => setHoverIdx(idx)}
                  onClick={() => onSelectEvent?.(pt)}
                />
              </g>
            );
          })}
        </svg>
      )}
    </div>
  );
};

interface RiskGaugeProps {
  score: number;
  watchlistThreshold: number;
  containThreshold: number;
  mode: 'active' | 'dry-run';
}

export const RiskScoreGauge: React.FC<RiskGaugeProps> = ({
  score,
  watchlistThreshold,
  containThreshold,
  mode,
}) => {
  const clamped = Math.min(120, Math.max(0, score));
  const pct = clamped / 120;
  const radius = 66;
  const strokeWidth = 8;
  const circumference = Math.PI * radius;
  const dashOffset = circumference * (1 - pct);

  const color =
    score >= containThreshold
      ? '#DC2626'
      : score >= watchlistThreshold
        ? '#D97706'
        : '#16A34A';

  const postureLabel =
    score >= containThreshold
      ? mode === 'dry-run'
        ? 'P0 Logged (Dry-Run)'
        : 'P0 Contained'
      : score >= watchlistThreshold
        ? 'P1 Watchlist'
        : 'Nominal Posture';

  return (
    <div className="flex flex-col items-center justify-center">
      <div className="relative h-[112px] w-[180px]">
        <svg viewBox="0 0 180 108" className="h-full w-full overflow-visible">
          <path
            d="M 24 90 A 66 66 0 0 1 156 90"
            fill="none"
            stroke="#E5E7EB"
            strokeWidth={strokeWidth}
            strokeLinecap="round"
          />
          <motion.path
            d="M 24 90 A 66 66 0 0 1 156 90"
            fill="none"
            stroke={color}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={circumference}
            animate={{ strokeDashoffset: dashOffset }}
            transition={{ type: 'spring', stiffness: 280, damping: 32 }}
          />
        </svg>
        <div className="absolute inset-x-0 bottom-1 text-center">
          <div className="type-kpi text-[32px] leading-none text-[#111827]">
            {score}
          </div>
          <div className="mt-1.5 text-[11.5px] font-medium" style={{ color }}>
            {postureLabel}
          </div>
        </div>
      </div>

      <div className="mt-3 flex w-full items-center justify-between border-t border-[#E5E7EB] pt-2.5 text-[11.5px] text-[#6B7280] tabular-nums">
        <span>Watchlist {watchlistThreshold}</span>
        <span>Contain {containThreshold}</span>
      </div>
    </div>
  );
};

interface SignalBarsProps {
  counts: Record<string, number>;
}

const SIGNAL_LABELS: Record<string, string> = {
  versioning_suspend: 'Versioning Sabotage',
  version_purge: 'Version Purge',
  lifecycle_expiry: 'Lifecycle Expiry ≤1d',
  object_lock_tamper: 'Object Lock Tamper',
  canary_write: 'Canary Modification',
  canary_read: 'Canary Read',
  entropy_delta: 'Entropy Spike (ΔH)',
  magic_header_lost: 'File Signature Lost',
  rename_burst: 'Rename/Delete Burst',
  ssec_abuse: 'Unauthorized SSE-C Copy',
  untrusted_kms: 'Untrusted KMS Key',
  swarm_correlation: 'Multi-Principal Correlation',
};

export const SignalBreakdownBars: React.FC<SignalBarsProps> = ({ counts }) => {
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...entries.map(([, v]) => v));

  if (entries.length === 0) {
    return (
      <div className="py-8 text-center text-[12px] text-[#6B7280]">
        Run a validation suite to inspect signal attribution.
      </div>
    );
  }

  return (
    <div className="space-y-2.5">
      {entries.map(([signal, count]) => {
        const widthPct = Math.max(5, (count / max) * 100);
        return (
          <div key={signal}>
            <div className="mb-1 flex items-center justify-between text-[12px]">
              <span className="text-[#111827]">{SIGNAL_LABELS[signal] ?? signal}</span>
              <span className="font-medium text-[#4B5563] tabular-nums">{count}</span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded bg-[#F3F4F6]">
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${widthPct}%` }}
                transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
                className="h-full bg-[#1D6CF0]"
              />
            </div>
          </div>
        );
      })}
    </div>
  );
};
