import React from 'react';
import { useHuntStore } from '../../store/useHuntStore';
import { AlertTriangle, Layers, Repeat, Fingerprint } from 'lucide-react';

export const PatternInsights: React.FC = React.memo(() => {
  const stats = useHuntStore((s) => s.stats);

  if (!stats) {
    return (
      <div className="space-y-3">
        <div className="h-28 animate-pulse rounded-lg bg-gray-800/30" />
        <div className="h-28 animate-pulse rounded-lg bg-gray-800/30" />
      </div>
    );
  }

  const repeated = stats.patterns?.repeated_processes_across_hosts || [];
  const rare = stats.patterns?.rare_single_occurrences || [];

  return (
    <div id="hunt-pattern-insights" className="space-y-3">
      <h3 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.15em] text-gray-500">
        <Layers className="h-4 w-4" />
        Pattern Insights
      </h3>

      {/* ── Repeated Across Hosts ──────────────────────────────────── */}
      <div className="rounded-lg border border-indigo-500/15 bg-indigo-500/[0.03] p-3 space-y-2">
        <div className="flex items-center gap-1.5">
          <Repeat className="h-3.5 w-3.5 text-indigo-400" />
          <p className="text-xs font-semibold text-indigo-300">Repeated Across Hosts</p>
        </div>
        <p className="text-[11px] text-gray-500 leading-relaxed">
          Process names observed on multiple distinct endpoints — potential lateral movement indicator.
        </p>
        <div className="flex flex-wrap gap-1.5">
          {repeated.slice(0, 8).map((entry, i) => (
            <span
              key={`${entry.process_name}-${i}`}
              className="inline-flex items-center gap-1 rounded-md border border-indigo-500/25 bg-indigo-950/40 px-2 py-1 font-mono text-[10px] text-indigo-200 transition-colors hover:bg-indigo-900/40"
            >
              {entry.process_name}
              <span className="rounded-full bg-indigo-500/20 px-1 text-[8px] text-indigo-300 tabular-nums">
                {entry.host_count}
              </span>
            </span>
          ))}
          {repeated.length === 0 && (
            <span className="text-[11px] text-gray-600 italic">No repeated patterns detected.</span>
          )}
        </div>
      </div>

      {/* ── Rare Processes ─────────────────────────────────────────── */}
      <div className="rounded-lg border border-orange-500/15 bg-orange-500/[0.03] p-3 space-y-2">
        <div className="flex items-center gap-1.5">
          <Fingerprint className="h-3.5 w-3.5 text-orange-400" />
          <p className="flex items-center gap-1 text-xs font-semibold text-orange-300">
            <AlertTriangle className="h-3 w-3" /> Rare Processes
          </p>
        </div>
        <p className="text-[11px] text-gray-500 leading-relaxed">
          Single-occurrence process executions — potential novel TTPs or one-shot payloads.
        </p>
        <div className="flex flex-wrap gap-1.5">
          {rare.slice(0, 8).map((entry, i) => (
            <span
              key={`${entry.process_name}-${i}`}
              className="rounded-md border border-orange-500/25 bg-orange-950/20 px-2 py-1 font-mono text-[10px] text-orange-200 transition-colors hover:bg-orange-900/25"
            >
              {entry.process_name}
            </span>
          ))}
          {rare.length === 0 && (
            <span className="text-[11px] text-gray-600 italic">No rare process anomalies found.</span>
          )}
        </div>
      </div>
    </div>
  );
});

PatternInsights.displayName = 'PatternInsights';
