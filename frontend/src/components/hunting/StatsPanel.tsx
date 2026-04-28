import React, { useMemo } from 'react';
import { useHuntStore } from '../../store/useHuntStore';
import { BarChart3, Server, Globe, Cpu, Activity } from 'lucide-react';

/* ── Bar Visualization (horizontal) ───────────────────────────────────── */
const BarRow: React.FC<{ label: string; count: number; max: number; color: string }> = React.memo(
  ({ label, count, max, color }) => {
    const pct = max > 0 ? (count / max) * 100 : 0;
    return (
      <div className="group flex items-center gap-2 text-[11px]">
        <span className="truncate font-mono text-gray-300 w-28 shrink-0 group-hover:text-white transition-colors" title={label}>
          {label}
        </span>
        <div className="flex-1 h-3.5 bg-gray-900/50 rounded-full overflow-hidden border border-gray-800/50">
          <div
            className={`h-full rounded-full transition-all duration-500 ${color}`}
            style={{ width: `${Math.max(pct, 2)}%` }}
          />
        </div>
        <span className="font-mono text-gray-500 w-8 text-right shrink-0 tabular-nums">{count}</span>
      </div>
    );
  },
);

BarRow.displayName = 'BarRow';

/* ── Stats Section ─────────────────────────────────────────────────────── */
const StatsSection: React.FC<{
  title: string;
  icon: React.ReactNode;
  values: Record<string, number> | undefined;
  color: string;
  limit?: number;
}> = React.memo(({ title, icon, values, color, limit = 5 }) => {
  const rows = useMemo(() => Object.entries(values || {}).slice(0, limit), [values, limit]);
  const max = useMemo(() => Math.max(...rows.map(([, c]) => c), 1), [rows]);

  return (
    <div className="rounded-lg border border-gray-800/60 bg-[#0c0f17] p-3 space-y-2.5">
      <p className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-gray-500">
        {icon}
        {title}
      </p>
      <div className="space-y-1.5">
        {rows.map(([label, count]) => (
          <BarRow key={label} label={label} count={count} max={max} color={color} />
        ))}
        {rows.length === 0 && <p className="text-[11px] text-gray-600 italic">No data available.</p>}
      </div>
    </div>
  );
});

StatsSection.displayName = 'StatsSection';

/* ── Main Component ───────────────────────────────────────────────────── */
export const StatsPanel: React.FC = React.memo(() => {
  const stats = useHuntStore((s) => s.stats);

  if (!stats) {
    return (
      <div className="space-y-3">
        <div className="h-10 animate-pulse rounded-lg bg-gray-800/50" />
        <div className="h-24 animate-pulse rounded-lg bg-gray-800/30" />
        <div className="h-24 animate-pulse rounded-lg bg-gray-800/30" />
      </div>
    );
  }

  const s = stats.stats || {};

  return (
    <div id="hunt-stats-panel" className="space-y-3">
      <h3 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.15em] text-gray-500">
        <BarChart3 className="h-4 w-4" />
        Hunt Stats
      </h3>

      {/* ── KPI Row ────────────────────────────────────────────────── */}
      <div className="grid grid-cols-3 gap-2">
        <div className="rounded-lg border border-gray-800/60 bg-[#0c0f17] p-3 text-center">
          <Activity className="h-3.5 w-3.5 text-indigo-400 mx-auto mb-1" />
          <p className="text-[9px] uppercase tracking-wider text-gray-600">Events</p>
          <p className="text-lg font-bold text-indigo-300 tabular-nums">{s.total_events || 0}</p>
        </div>
        <div className="rounded-lg border border-gray-800/60 bg-[#0c0f17] p-3 text-center">
          <Server className="h-3.5 w-3.5 text-cyan-400 mx-auto mb-1" />
          <p className="text-[9px] uppercase tracking-wider text-gray-600">Hosts</p>
          <p className="text-lg font-bold text-cyan-300 tabular-nums">{s.active_hosts || 0}</p>
        </div>
        <div className="rounded-lg border border-gray-800/60 bg-[#0c0f17] p-3 text-center">
          <BarChart3 className="h-3.5 w-3.5 text-red-400 mx-auto mb-1" />
          <p className="text-[9px] uppercase tracking-wider text-gray-600">High/Crit</p>
          <p className="text-lg font-bold text-red-300 tabular-nums">{s.high_severity_count || 0}</p>
        </div>
      </div>

      {/* ── Distribution Charts ────────────────────────────────────── */}
      <StatsSection
        title="Most Common Processes"
        icon={<Cpu className="h-3 w-3" />}
        values={s.most_common_processes}
        color="bg-gradient-to-r from-indigo-600 to-indigo-400"
      />
      <StatsSection
        title="Top Hosts"
        icon={<Server className="h-3 w-3" />}
        values={s.top_hosts}
        color="bg-gradient-to-r from-cyan-600 to-cyan-400"
      />
      <StatsSection
        title="Frequent IPs"
        icon={<Globe className="h-3 w-3" />}
        values={s.frequent_ips}
        color="bg-gradient-to-r from-violet-600 to-fuchsia-400"
      />
    </div>
  );
});

StatsPanel.displayName = 'StatsPanel';
