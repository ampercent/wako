import React from 'react';
import { useHuntStore } from '../../store/useHuntStore';
import { AlertTriangle, Layers, Repeat, Fingerprint } from 'lucide-react';

export const PatternInsights: React.FC = React.memo(() => {
  const stats = useHuntStore((s) => s.stats);

  if (!stats) {
    return (
      <div className="space-y-3">
        <div className="h-28 animate-pulse rounded-lg bg-muted/30" />
        <div className="h-28 animate-pulse rounded-lg bg-muted/30" />
      </div>
    );
  }

  const repeated = stats.patterns?.repeated_processes_across_hosts || [];
  const rare = stats.patterns?.rare_single_occurrences || [];

  return (
    <div id="hunt-pattern-insights" className="space-y-3">
      <h3 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.15em] text-muted-foreground">
        <Layers className="h-4 w-4" />
        Pattern Insights
      </h3>

      {/* ── Repeated Across Hosts ──────────────────────────────────── */}
      <div className="rounded-lg border border-primary/15 bg-primary/5 p-3 space-y-2">
        <div className="flex items-center gap-1.5">
          <Repeat className="h-3.5 w-3.5 text-primary" />
          <p className="text-xs font-semibold text-primary">Repeated Across Hosts</p>
        </div>
        <p className="text-[11px] text-muted-foreground leading-relaxed">
          Process names observed on multiple distinct endpoints — potential lateral movement indicator.
        </p>
        <div className="flex flex-wrap gap-1.5">
          {repeated.slice(0, 8).map((entry, i) => (
            <span
              key={`${entry.process_name}-${i}`}
              className="inline-flex items-center gap-1 rounded-md border border-primary/25 bg-primary/10 px-2 py-1 font-mono text-[10px] text-primary transition-colors hover:bg-primary/20"
            >
              {entry.process_name}
              <span className="rounded-full bg-primary/20 px-1 text-[8px] text-primary tabular-nums">
                {entry.host_count}
              </span>
            </span>
          ))}
          {repeated.length === 0 && (
            <span className="text-[11px] text-muted-foreground/60 italic">No repeated patterns detected.</span>
          )}
        </div>
      </div>

      {/* ── Rare Processes ─────────────────────────────────────────── */}
      <div className="rounded-lg border border-warning/15 bg-warning/5 p-3 space-y-2">
        <div className="flex items-center gap-1.5">
          <Fingerprint className="h-3.5 w-3.5 text-warning" />
          <p className="flex items-center gap-1 text-xs font-semibold text-warning">
            <AlertTriangle className="h-3 w-3" /> Rare Processes
          </p>
        </div>
        <p className="text-[11px] text-muted-foreground leading-relaxed">
          Single-occurrence process executions — potential novel TTPs or one-shot payloads.
        </p>
        <div className="flex flex-wrap gap-1.5">
          {rare.slice(0, 8).map((entry, i) => (
            <span
              key={`${entry.process_name}-${i}`}
              className="rounded-md border border-warning/25 bg-warning/10 px-2 py-1 font-mono text-[10px] text-warning transition-colors hover:bg-warning/20"
            >
              {entry.process_name}
            </span>
          ))}
          {rare.length === 0 && (
            <span className="text-[11px] text-muted-foreground/60 italic">No rare process anomalies found.</span>
          )}
        </div>
      </div>
    </div>
  );
});

PatternInsights.displayName = 'PatternInsights';
