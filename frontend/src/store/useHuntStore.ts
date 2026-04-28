import { create } from 'zustand';
import type { HuntResultItem, SavedHuntQuery, HuntStatsResponse } from '../api/hunting';

export interface HuntPagination {
  page: number;
  pageSize: number;
  totalFiltered: number;
}

interface HuntState {
  // Query
  query: string;
  setQuery: (q: string) => void;

  // Results
  results: HuntResultItem[];
  setResults: (r: HuntResultItem[]) => void;
  clearResults: () => void;

  // Async state
  loading: boolean;
  setLoading: (l: boolean) => void;
  error: string | null;
  setError: (e: string | null) => void;

  // Pagination
  pagination: HuntPagination;
  setPage: (p: number) => void;
  setTotalFiltered: (t: number) => void;
  resetPagination: () => void;

  // Stats
  stats: HuntStatsResponse | null;
  setStats: (s: HuntStatsResponse | null) => void;

  // Saved queries
  savedQueries: SavedHuntQuery[];
  setSavedQueries: (q: SavedHuntQuery[]) => void;

  // Live mode
  isLive: boolean;
  toggleLive: () => void;
  setLive: (v: boolean) => void;

  // Sorting (table)
  sortField: string;
  sortDir: 'asc' | 'desc';
  setSortField: (f: string) => void;
  toggleSortDir: () => void;

  // Inline filter
  tableFilter: string;
  setTableFilter: (f: string) => void;
  severityFilter: string;
  setSeverityFilter: (s: string) => void;

  // Result count from last query
  lastQueryCount: number;
  setLastQueryCount: (c: number) => void;
}

const DEFAULT_PAGE_SIZE = 25;

export const useHuntStore = create<HuntState>((set) => ({
  // Query
  query: '',
  setQuery: (q) => set({ query: q }),

  // Results
  results: [],
  setResults: (r) => set({ results: r, error: null }),
  clearResults: () =>
    set({
      results: [],
      pagination: { page: 1, pageSize: DEFAULT_PAGE_SIZE, totalFiltered: 0 },
      lastQueryCount: 0,
    }),

  // Async
  loading: false,
  setLoading: (l) => set({ loading: l }),
  error: null,
  setError: (e) => set({ error: e }),

  // Pagination
  pagination: { page: 1, pageSize: DEFAULT_PAGE_SIZE, totalFiltered: 0 },
  setPage: (p) => set((s) => ({ pagination: { ...s.pagination, page: p } })),
  setTotalFiltered: (t) => set((s) => ({ pagination: { ...s.pagination, totalFiltered: t } })),
  resetPagination: () =>
    set({ pagination: { page: 1, pageSize: DEFAULT_PAGE_SIZE, totalFiltered: 0 } }),

  // Stats
  stats: null,
  setStats: (s) => set({ stats: s }),

  // Saved
  savedQueries: [],
  setSavedQueries: (q) => set({ savedQueries: q }),

  // Live
  isLive: false,
  toggleLive: () => set((s) => ({ isLive: !s.isLive })),
  setLive: (v) => set({ isLive: v }),

  // Sort
  sortField: 'timestamp',
  sortDir: 'desc',
  setSortField: (f) =>
    set((s) => ({
      sortField: f,
      sortDir: s.sortField === f ? (s.sortDir === 'asc' ? 'desc' : 'asc') : 'desc',
    })),
  toggleSortDir: () => set((s) => ({ sortDir: s.sortDir === 'asc' ? 'desc' : 'asc' })),

  // Filters
  tableFilter: '',
  setTableFilter: (f) => set({ tableFilter: f, pagination: { page: 1, pageSize: DEFAULT_PAGE_SIZE, totalFiltered: 0 } }),
  severityFilter: 'ALL',
  setSeverityFilter: (s) => set({ severityFilter: s, pagination: { page: 1, pageSize: DEFAULT_PAGE_SIZE, totalFiltered: 0 } }),

  // Count
  lastQueryCount: 0,
  setLastQueryCount: (c) => set({ lastQueryCount: c }),
}));
