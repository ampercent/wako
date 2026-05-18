import React, { useMemo, useCallback } from 'react';
import { useHuntStore } from '../../store/useHuntStore';
import { executeHuntQuery, cancelActiveHuntRequest } from '../../api/hunting';
import { Search, Play, RefreshCw, AlertCircle, Zap, ZapOff } from 'lucide-react';

/* ── Syntax Highlighting ───────────────────────────────────────────────── */
function highlightQuery(query: string): string {
  let html = query
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  // Order matters: strings first, then fields, operators, keywords
  html = html.replace(/'[^']*'/g, (m) => `<span class="text-emerald-300">${m}</span>`);
  html = html.replace(
    /\b(process_name|severity|source|case_id|timestamp|event_type|pid|ip)\b/gi,
    (m) => `<span class="text-cyan-300">${m}</span>`,
  );
  html = html.replace(/(==|!=|&gt;=|&lt;=|&gt;|&lt;)/g, (m) => `<span class="text-fuchsia-400">${m}</span>`);
  html = html.replace(
    /\b(AND|OR|NOT)\b/gi,
    (m) => `<span class="text-indigo-300 font-semibold">${m}</span>`,
  );
  return html;
}

/* ── Syntax Hint ───────────────────────────────────────────────────────── */
function useSyntaxHint(query: string): string | null {
  return useMemo(() => {
    if (!query.trim()) return null;
    const hasField = /(process_name|severity|source|case_id|timestamp|event_type|pid|ip)/i.test(query);
    const hasOp = /(==|!=|>=|<=|>|<)/.test(query);
    const balanced = (query.match(/'/g) || []).length % 2 === 0;
    if (!hasField || !hasOp || !balanced) {
      return "Example: process_name == 'powershell.exe' AND severity == 'HIGH'";
    }
    return null;
  }, [query]);
}

/* ── Component ─────────────────────────────────────────────────────────── */
interface QueryBarProps {
  onRunSuccess?: () => void;
}

export const QueryBar: React.FC<QueryBarProps> = React.memo(({ onRunSuccess }) => {
  const query = useHuntStore((s) => s.query);
  const setQuery = useHuntStore((s) => s.setQuery);
  const loading = useHuntStore((s) => s.loading);
  const setLoading = useHuntStore((s) => s.setLoading);
  const setResults = useHuntStore((s) => s.setResults);
  const setError = useHuntStore((s) => s.setError);
  const setLastQueryCount = useHuntStore((s) => s.setLastQueryCount);
  const resetPagination = useHuntStore((s) => s.resetPagination);
  const isLive = useHuntStore((s) => s.isLive);
  const toggleLive = useHuntStore((s) => s.toggleLive);
  const error = useHuntStore((s) => s.error);

  const syntaxHint = useSyntaxHint(query);

  const runQuery = useCallback(async () => {
    const q = query.trim();
    if (!q) {
      setError('Enter a query before running a hunt.');
      return;
    }

    setLoading(true);
    setError(null);
    resetPagination();

    try {
      const res = await executeHuntQuery(q, 100);
      setResults(res.results);
      setLastQueryCount(res.count);
      onRunSuccess?.();
    } catch (err: any) {
      setError(err?.message || 'Failed to execute hunting query.');
    } finally {
      setLoading(false);
    }
  }, [query, setLoading, setError, resetPagination, setResults, setLastQueryCount, onRunSuccess]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        runQuery();
      }
      // Ctrl/Cmd+Shift+L → toggle live
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'L') {
        e.preventDefault();
        toggleLive();
      }
    },
    [runQuery, toggleLive],
  );

  const handleStop = useCallback(() => {
    cancelActiveHuntRequest();
    setLoading(false);
  }, [setLoading]);

  const previewHtml = useMemo(
    () => highlightQuery(query || "process_name == 'powershell.exe' AND severity == 'HIGH'"),
    [query],
  );

  return (
    <div id="hunt-query-bar" className="space-y-3">
      {/* ─── Input Row ─────────────────────────────────────────────── */}
      <div className="flex flex-col gap-3 xl:flex-row xl:items-center">
        <div className="relative flex-1 group">
          <Search className="pointer-events-none absolute left-3 top-3.5 h-4 w-4 text-muted-foreground transition-colors group-focus-within:text-primary" />
          <input
            id="hunt-query-input"
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="process_name == 'powershell.exe' AND severity == 'HIGH'"
            className="w-full rounded-lg border border-border bg-background py-3 pl-10 pr-3 font-mono text-sm text-primary placeholder:text-muted-foreground transition-all duration-200 focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/30 focus:shadow-[0_0_20px_hsl(var(--primary)/0.08)]"
            spellCheck={false}
            autoComplete="off"
          />
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {loading ? (
            <button
              id="hunt-stop-btn"
              onClick={handleStop}
              className="inline-flex items-center gap-2 rounded-lg bg-destructive/80 px-4 py-3 text-xs font-semibold uppercase tracking-wide text-destructive-foreground transition-colors hover:bg-destructive"
            >
              <RefreshCw className="h-4 w-4 animate-spin" />
              Cancel
            </button>
          ) : (
            <button
              id="hunt-run-btn"
              onClick={runQuery}
              disabled={!query.trim()}
              className="inline-flex items-center gap-2 rounded-lg bg-primary px-5 py-3 text-xs font-semibold uppercase tracking-wide text-primary-foreground transition-all duration-200 hover:bg-primary/90 hover:shadow-[0_0_20px_hsl(var(--primary)/0.25)] disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <Play className="h-4 w-4" />
              Run Hunt
            </button>
          )}
        </div>
      </div>

      {/* ─── Syntax Preview ────────────────────────────────────────── */}
      <div className="rounded-lg border border-border bg-card p-3 transition-colors">
        <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          Syntax Preview
        </p>
        <pre
          className="overflow-x-auto whitespace-pre-wrap break-words font-mono text-xs leading-6 text-muted-foreground"
          dangerouslySetInnerHTML={{ __html: previewHtml }}
        />
      </div>

      {/* ─── Hint / Error ──────────────────────────────────────────── */}
      {syntaxHint && !error && (
        <div className="flex items-center gap-2 rounded-md bg-amber-500/5 border border-amber-500/15 px-3 py-2 text-xs text-amber-400/90">
          <AlertCircle className="h-3.5 w-3.5 shrink-0" />
          <span>{syntaxHint}</span>
        </div>
      )}

      {error && (
        <div className="flex items-center gap-2 rounded-md bg-red-500/5 border border-red-500/20 px-3 py-2 text-xs text-red-400 animate-in fade-in duration-200">
          <AlertCircle className="h-3.5 w-3.5 shrink-0" />
          <span>{error}</span>
        </div>
      )}
    </div>
  );
});

QueryBar.displayName = 'QueryBar';
