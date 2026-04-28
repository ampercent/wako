import React, { useMemo, useCallback } from 'react';
import { useHuntStore } from '../../store/useHuntStore';
import { useStore } from '../../store/useStore';
import { AlertTriangle, ArrowUpDown, ExternalLink, Crosshair, ChevronLeft, ChevronRight } from 'lucide-react';

/* ── Constants ─────────────────────────────────────────────────────────── */
const SEVERITY_RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

function sevClass(value?: string): string {
  const v = (value || '').toUpperCase();
  if (v === 'CRITICAL') return 'text-red-400 bg-red-500/10 border-red-500/20';
  if (v === 'HIGH') return 'text-orange-300 bg-orange-500/8 border-orange-500/15';
  if (v === 'MEDIUM') return 'text-yellow-300 bg-yellow-500/8 border-yellow-500/15';
  return 'text-gray-400 bg-gray-500/8 border-gray-500/15';
}

type SortKey = 'case_id' | 'timestamp' | 'process_name' | 'severity' | 'source';
const COLUMNS: { key: SortKey; label: string; mono?: boolean }[] = [
  { key: 'case_id', label: 'Case', mono: true },
  { key: 'timestamp', label: 'Timestamp', mono: true },
  { key: 'process_name', label: 'Process' },
  { key: 'severity', label: 'Severity' },
  { key: 'source', label: 'Source (Host)' },
];

/* ── Component ─────────────────────────────────────────────────────────── */
export const ResultsTable: React.FC = React.memo(() => {
  const results = useHuntStore((s) => s.results);
  const pagination = useHuntStore((s) => s.pagination);
  const setPage = useHuntStore((s) => s.setPage);
  const setTotalFiltered = useHuntStore((s) => s.setTotalFiltered);
  const sortField = useHuntStore((s) => s.sortField);
  const sortDir = useHuntStore((s) => s.sortDir);
  const setSortField = useHuntStore((s) => s.setSortField);
  const tableFilter = useHuntStore((s) => s.tableFilter);
  const setTableFilter = useHuntStore((s) => s.setTableFilter);
  const severityFilter = useHuntStore((s) => s.severityFilter);
  const setSeverityFilter = useHuntStore((s) => s.setSeverityFilter);
  const lastQueryCount = useHuntStore((s) => s.lastQueryCount);

  // Global store integration for click-to-investigate
  const setSelectedPID = useStore((s) => s.setSelectedPID);
  const setSelectedNode = useStore((s) => s.setSelectedNode);
  const setSelectedCaseId = useStore((s) => s.setSelectedCaseId);
  const setPlaybackIndex = useStore((s) => s.setPlaybackIndex);
  const setActivePage = useStore((s) => s.setActivePage);
  const timelineData = useStore((s) => s.timelineData);

  const { page, pageSize } = pagination;

  /* ── Filtering + Sorting (memoized) ─────────────────────────────── */
  const filteredAndSorted = useMemo(() => {
    const search = tableFilter.trim().toLowerCase();

    const filtered = results.filter((item) => {
      if (severityFilter !== 'ALL' && String(item.severity).toUpperCase() !== severityFilter) return false;
      if (!search) return true;
      const haystack = `${item.case_id} ${item.process_name} ${item.source} ${item.timestamp} ${item.pid || ''}`.toLowerCase();
      return haystack.includes(search);
    });

    const sorted = [...filtered].sort((a, b) => {
      let cmp = 0;
      if (sortField === 'severity') {
        cmp = (SEVERITY_RANK[String(a.severity).toUpperCase()] || 0) - (SEVERITY_RANK[String(b.severity).toUpperCase()] || 0);
      } else if (sortField === 'timestamp') {
        cmp = new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
      } else {
        const la = String((a as any)[sortField] ?? '').toLowerCase();
        const lb = String((b as any)[sortField] ?? '').toLowerCase();
        cmp = la.localeCompare(lb, undefined, { numeric: true, sensitivity: 'base' });
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });

    return sorted;
  }, [results, tableFilter, severityFilter, sortField, sortDir]);

  // Sync totalFiltered
  useMemo(() => {
    setTotalFiltered(filteredAndSorted.length);
  }, [filteredAndSorted.length, setTotalFiltered]);

  /* ── Pagination ─────────────────────────────────────────────────── */
  const totalPages = Math.max(1, Math.ceil(filteredAndSorted.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const pageRows = useMemo(
    () => filteredAndSorted.slice((safePage - 1) * pageSize, safePage * pageSize),
    [filteredAndSorted, safePage, pageSize],
  );

  /* ── Click to Investigate ───────────────────────────────────────── */
  const handleInvestigate = useCallback(
    (row: any) => {
      // 1. Case
      if (row.case_id != null) setSelectedCaseId(row.case_id);

      // 2. PID → Graph focus
      if (row.pid != null) {
        setSelectedPID(String(row.pid));
        setSelectedNode(`pid_${row.pid}`);

        // Dispatch global event for custom integrations
        window.dispatchEvent(new CustomEvent('focusNode', { detail: row.pid }));
      }

      // 3. Timeline jump
      const idx = timelineData.findIndex((evt) => {
        const pidMatch = String(evt.pid) === String(row.pid);
        const tsMatch = row.timestamp
          ? new Date(evt.timestamp).getTime() === new Date(row.timestamp).getTime()
          : true;
        return pidMatch && tsMatch;
      });
      if (idx >= 0) setPlaybackIndex(idx);

      // 4. Navigate to graph
      setActivePage('GRAPH');
    },
    [setSelectedCaseId, setSelectedPID, setSelectedNode, setPlaybackIndex, setActivePage, timelineData],
  );

  /* ── Empty State ────────────────────────────────────────────────── */
  if (!results.length) {
    return (
      <div className="flex h-full flex-col items-center justify-center text-gray-600 gap-4 py-20">
        <div className="relative">
          <Crosshair className="h-16 w-16 opacity-10 absolute blur-lg" />
          <Crosshair className="h-16 w-16 opacity-25 relative" />
        </div>
        <p className="font-mono text-sm uppercase tracking-[0.2em] text-gray-600">
          Run a query to begin hunting
        </p>
        <p className="text-xs text-gray-700 max-w-xs text-center">
          Enter a query above and press <kbd className="px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 text-[10px] font-mono">Enter</kbd> or click <span className="text-indigo-400">Run Hunt</span>.
        </p>
      </div>
    );
  }

  /* ── Render ─────────────────────────────────────────────────────── */
  return (
    <div className="space-y-3" id="hunt-results-table">
      {/* ── Toolbar ────────────────────────────────────────────────── */}
      <div className="flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-center gap-2">
          <input
            id="hunt-table-filter"
            value={tableFilter}
            onChange={(e) => setTableFilter(e.target.value)}
            placeholder="Filter by case, process, host..."
            className="rounded-md border border-gray-700/80 bg-gray-900/80 px-3 py-2 text-xs text-gray-200 transition-colors focus:border-indigo-500 focus:outline-none w-48"
          />
          <select
            id="hunt-severity-filter"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="rounded-md border border-gray-700/80 bg-gray-900/80 px-2 py-2 text-xs text-gray-200 transition-colors focus:border-indigo-500 focus:outline-none cursor-pointer"
          >
            <option value="ALL">All Severity</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>
        </div>

        <div className="flex items-center gap-3">
          <p className="font-mono text-[11px] text-gray-500">
            <span className="text-indigo-400">{filteredAndSorted.length}</span>
            {filteredAndSorted.length !== lastQueryCount && (
              <span className="text-gray-600"> / {lastQueryCount}</span>
            )}
            {' '}matches
          </p>
        </div>
      </div>

      {/* ── Table ──────────────────────────────────────────────────── */}
      <div className="overflow-x-auto rounded-lg border border-gray-800/80 shadow-lg">
        <table className="min-w-full text-left text-xs">
          <thead className="bg-gray-900/90 text-[10px] uppercase tracking-wider text-gray-500 select-none">
            <tr>
              {COLUMNS.map(({ key, label }) => (
                <th key={key} className="px-3 py-2.5">
                  <button
                    onClick={() => setSortField(key)}
                    className={`inline-flex items-center gap-1 transition-colors hover:text-white ${
                      sortField === key ? 'text-indigo-400' : 'text-gray-400'
                    }`}
                  >
                    {label}
                    <ArrowUpDown className={`h-3 w-3 transition-transform ${sortField === key && sortDir === 'asc' ? 'rotate-180' : ''}`} />
                  </button>
                </th>
              ))}
              <th className="px-3 py-2.5 text-right text-gray-500">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/60">
            {pageRows.map((row, idx) => (
              <tr
                key={`${row.case_id}-${row.timestamp}-${idx}`}
                onClick={() => handleInvestigate(row)}
                className="group cursor-pointer bg-[#0b0f19] transition-all duration-150 hover:bg-indigo-500/[0.04] hover:shadow-[inset_2px_0_0_rgba(99,102,241,0.4)]"
              >
                <td className="px-3 py-2.5 font-mono text-gray-300">{row.case_id}</td>
                <td className="px-3 py-2.5 font-mono text-gray-500 text-[11px]">
                  {row.timestamp ? new Date(row.timestamp).toLocaleString() : '-'}
                </td>
                <td className="px-3 py-2.5 text-gray-200 font-medium">{row.process_name || '-'}</td>
                <td className="px-3 py-2.5">
                  <span className={`inline-block rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide ${sevClass(String(row.severity))}`}>
                    {String(row.severity || 'LOW').toUpperCase()}
                  </span>
                </td>
                <td className="px-3 py-2.5 text-gray-400">{row.source || '-'}</td>
                <td className="px-3 py-2.5 text-right">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      handleInvestigate(row);
                    }}
                    className="inline-flex items-center gap-1 rounded-md border border-indigo-500/30 bg-indigo-500/8 px-2.5 py-1 text-[10px] font-semibold text-indigo-300 transition-all hover:bg-indigo-500/15 hover:border-indigo-500/50 opacity-60 group-hover:opacity-100"
                  >
                    <ExternalLink className="h-3 w-3" />
                    Pivot
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* ── No Match Warning ───────────────────────────────────────── */}
      {filteredAndSorted.length === 0 && results.length > 0 && (
        <div className="flex items-center gap-2 rounded-md border border-amber-500/20 bg-amber-500/5 p-3 text-xs text-amber-300">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          No rows matched the current filters.
        </div>
      )}

      {/* ── Pagination ─────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <p className="text-[11px] text-gray-600">
          Page {safePage} of {totalPages}
        </p>
        <div className="flex items-center gap-1">
          <button
            id="hunt-page-prev"
            onClick={() => setPage(Math.max(safePage - 1, 1))}
            disabled={safePage <= 1}
            className="rounded-md border border-gray-700/80 bg-gray-900/80 p-1.5 text-gray-400 transition-colors hover:text-white disabled:opacity-30 disabled:cursor-not-allowed"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>

          {/* Page number pills (max 5) */}
          {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
            const startPage = Math.max(1, Math.min(safePage - 2, totalPages - 4));
            const pageNum = startPage + i;
            if (pageNum > totalPages) return null;
            return (
              <button
                key={pageNum}
                onClick={() => setPage(pageNum)}
                className={`h-7 w-7 rounded-md text-xs font-mono transition-all ${
                  pageNum === safePage
                    ? 'bg-indigo-600/80 text-white shadow-sm'
                    : 'bg-gray-900/60 text-gray-500 hover:text-white hover:bg-gray-800'
                }`}
              >
                {pageNum}
              </button>
            );
          })}

          <button
            id="hunt-page-next"
            onClick={() => setPage(Math.min(safePage + 1, totalPages))}
            disabled={safePage >= totalPages}
            className="rounded-md border border-gray-700/80 bg-gray-900/80 p-1.5 text-gray-400 transition-colors hover:text-white disabled:opacity-30 disabled:cursor-not-allowed"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );
});

ResultsTable.displayName = 'ResultsTable';
