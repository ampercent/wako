import React, { useEffect, useRef, useCallback } from 'react';
import { useHuntStore } from '../../store/useHuntStore';
import { executeHuntQuery, cancelActiveHuntRequest, getHuntStats } from '../../api/hunting';
import { QueryBar } from './QueryBar';
import { ResultsTable } from './ResultsTable';
import { PatternInsights } from './PatternInsights';
import { StatsPanel } from './StatsPanel';
import { Crosshair, Radio } from 'lucide-react';

/* ── Live Mode Interval (ms) ──────────────────────────────────────────── */
const LIVE_INTERVAL = 5000;

export const HuntingWorkspace: React.FC = () => {
  const query = useHuntStore((s) => s.query);
  const isLive = useHuntStore((s) => s.isLive);
  const setResults = useHuntStore((s) => s.setResults);
  const setError = useHuntStore((s) => s.setError);
  const setStats = useHuntStore((s) => s.setStats);
  const setLastQueryCount = useHuntStore((s) => s.setLastQueryCount);
  const loading = useHuntStore((s) => s.loading);
  const results = useHuntStore((s) => s.results);

  const isExecutingRef = useRef(false);
  const mountedRef = useRef(true);

  /* ── Fetch Stats ─────────────────────────────────────────────────── */
  const refreshStats = useCallback(() => {
    getHuntStats()
      .then((res) => {
        if (mountedRef.current) setStats(res);
      })
      .catch(console.error);
  }, [setStats]);

  // Load stats on mount
  useEffect(() => {
    refreshStats();
  }, [refreshStats]);

  /* ── Live Mode ───────────────────────────────────────────────────── */
  useEffect(() => {
    if (!isLive || !query.trim()) return;

    const interval = setInterval(async () => {
      if (isExecutingRef.current || !mountedRef.current) return;
      isExecutingRef.current = true;

      try {
        const res = await executeHuntQuery(query, 100);
        if (mountedRef.current) {
          setResults(res.results);
          setLastQueryCount(res.count);
        }
      } catch (err: any) {
        if (mountedRef.current) {
          setError(err?.message || 'Live hunt refresh failed.');
        }
      } finally {
        isExecutingRef.current = false;
      }
    }, LIVE_INTERVAL);

    return () => {
      clearInterval(interval);
      cancelActiveHuntRequest();
    };
  }, [isLive, query, setResults, setError, setLastQueryCount]);

  /* ── Cleanup on unmount ──────────────────────────────────────────── */
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      cancelActiveHuntRequest();
    };
  }, []);

  return (
    <div className="flex h-full w-full flex-col overflow-hidden bg-background text-foreground xl:flex-row">
      {/* ═══════════════════════════════════════════════════════════════
           LEFT: Query + Results (main workspace)
         ═══════════════════════════════════════════════════════════════ */}
      <div className="flex min-w-0 flex-1 flex-col border-b border-border xl:border-b-0 xl:border-r">
        {/* ── Header ───────────────────────────────────────────────── */}
        <div className="flex h-14 items-center justify-between border-b border-border bg-card px-4 backdrop-blur-sm">
          <div className="flex items-center gap-2.5">
            <Crosshair className="h-5 w-5 text-primary" />
            <h2 className="text-sm font-semibold uppercase tracking-[0.2em] text-foreground">
              Threat Hunting
            </h2>
          </div>

          <div className="flex items-center gap-3">
            {results.length > 0 && (
              <span className="rounded-full bg-primary/10 border border-primary/20 px-2.5 py-0.5 text-[10px] font-mono text-primary tabular-nums">
                {results.length} results
              </span>
            )}
          </div>
        </div>

        {/* ── Query Bar ────────────────────────────────────────────── */}
        <div className="border-b border-border bg-card/40 p-4 backdrop-blur-sm">
          <QueryBar onRunSuccess={refreshStats} />
        </div>

        {/* ── Results ──────────────────────────────────────────────── */}
        <div className="min-h-0 flex-1 overflow-auto bg-background p-4">
          {loading && results.length === 0 ? (
            <div className="flex h-full items-center justify-center">
              <div className="flex flex-col items-center gap-4">
                <div className="relative">
                  <div className="h-12 w-12 rounded-full border-2 border-primary/20 border-t-primary animate-spin" />
                  <Crosshair className="h-5 w-5 text-primary absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2" />
                </div>
                <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground animate-pulse">
                  Executing hunt query...
                </p>
              </div>
            </div>
          ) : (
            <ResultsTable />
          )}
        </div>
      </div>

      {/* ═══════════════════════════════════════════════════════════════
           RIGHT: Sidebar (Stats + Patterns + Saved)
         ═══════════════════════════════════════════════════════════════ */}
      <div className="w-full shrink-0 overflow-y-auto bg-card/50 xl:w-[400px] 2xl:w-[440px]">
        <div className="space-y-5 p-4">
          <StatsPanel />
          <div className="border-t border-border" />
          <PatternInsights />
        </div>
      </div>
    </div>
  );
};
