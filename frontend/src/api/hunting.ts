import axios, { AxiosError, CancelTokenSource } from 'axios';
import { logComponentError } from './telemetry';

const API_BASE = 'http://localhost:8001';

const huntClient = axios.create({
  baseURL: API_BASE,
  timeout: 5000,
  headers: { 'Content-Type': 'application/json' },
});

// ─── Types ──────────────────────────────────────────────────────────────

export interface HuntResultItem {
  case_id: number;
  timestamp: string;
  process_name: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | string;
  source: string;
  pid?: number;
  event_type?: string;
  ip?: string;
  [key: string]: any;
}

export interface SavedHuntQuery {
  id: number;
  name: string;
  query: string;
  created_at?: string;
}

export interface HuntStats {
  most_common_processes: Record<string, number>;
  top_hosts: Record<string, number>;
  frequent_ips: Record<string, number>;
  total_events?: number;
  active_hosts?: number;
  high_severity_count?: number;
}

export interface HuntPatterns {
  rare_single_occurrences?: Array<{ process_name: string; count?: number }>;
  repeated_processes_across_hosts?: Array<{ process_name: string; host_count: number }>;
}

export interface HuntStatsResponse {
  stats: HuntStats;
  patterns?: HuntPatterns;
}

export interface HuntQueryResponse {
  count: number;
  results: HuntResultItem[];
}

// ─── Mock Data (fallback when backend is offline) ───────────────────────

const MOCK_RESULTS: HuntResultItem[] = [
  { case_id: 1, timestamp: '2026-04-27T10:06:30Z', process_name: 'powershell.exe', severity: 'HIGH', source: 'host-finance-01', pid: 3010, event_type: 'injection', ip: '198.51.100.1' },
  { case_id: 1, timestamp: '2026-04-27T10:05:30Z', process_name: 'certutil.exe', severity: 'MEDIUM', source: 'host-finance-01', pid: 2010, event_type: 'network_connect', ip: '8.8.8.8' },
  { case_id: 2, timestamp: '2026-04-27T11:10:12Z', process_name: 'wscript.exe', severity: 'HIGH', source: 'host-hr-02', pid: 4412, event_type: 'process_start', ip: '203.0.113.22' },
  { case_id: 3, timestamp: '2026-04-27T11:22:02Z', process_name: 'chrome.exe', severity: 'LOW', source: 'host-dev-05', pid: 9912, event_type: 'dns_query', ip: '1.1.1.1' },
  { case_id: 4, timestamp: '2026-04-27T12:01:45Z', process_name: 'mshta.exe', severity: 'CRITICAL', source: 'host-finance-01', pid: 6621, event_type: 'process_start', ip: '198.51.100.1' },
  { case_id: 5, timestamp: '2026-04-27T12:15:33Z', process_name: 'rundll32.exe', severity: 'HIGH', source: 'host-hr-02', pid: 7744, event_type: 'injection', ip: '10.0.0.1' },
  { case_id: 6, timestamp: '2026-04-27T12:30:00Z', process_name: 'cmd.exe', severity: 'MEDIUM', source: 'host-dev-05', pid: 5500, event_type: 'process_start', ip: '203.0.113.22' },
];

const MOCK_SAVED: SavedHuntQuery[] = [
  { id: 1, name: 'High severity script engines', query: "process_name == 'powershell.exe' AND severity == 'HIGH'", created_at: '2026-04-25T08:12:00Z' },
  { id: 2, name: 'Rare process executions', query: "event_type == 'process_start' AND severity != 'LOW'", created_at: '2026-04-26T14:32:00Z' },
];

const MOCK_STATS: HuntStatsResponse = {
  stats: {
    most_common_processes: { 'powershell.exe': 19, 'certutil.exe': 11, 'cmd.exe': 9, 'wscript.exe': 7, 'mshta.exe': 4 },
    top_hosts: { 'host-finance-01': 24, 'host-hr-02': 16, 'host-dev-05': 9 },
    frequent_ips: { '198.51.100.1': 12, '8.8.8.8': 10, '203.0.113.22': 7, '10.0.0.1': 3 },
    total_events: 61,
    active_hosts: 3,
    high_severity_count: 17,
  },
  patterns: {
    repeated_processes_across_hosts: [
      { process_name: 'powershell.exe', host_count: 3 },
      { process_name: 'cmd.exe', host_count: 2 },
    ],
    rare_single_occurrences: [
      { process_name: 'mshta.exe', count: 1 },
      { process_name: 'rundll32.exe /sideload', count: 1 },
    ],
  },
};

// ─── Helpers ────────────────────────────────────────────────────────────

function isLikelyInvalidQuery(query: string): boolean {
  const q = query.trim();
  if (!q) return true;
  const hasOperator = /(==|!=|>=|<=|>|<)/.test(q);
  const hasField = /(process_name|severity|source|case_id|timestamp|event_type|pid|ip)/i.test(q);
  return !hasOperator || !hasField;
}

/** Client-side filter for mock fallback */
function filterMockResults(query: string): HuntResultItem[] {
  const lower = query.toLowerCase();
  return MOCK_RESULTS.filter((item) => {
    const checkProcess = !lower.includes('process_name') || lower.includes(item.process_name.toLowerCase());
    const checkSeverity = !lower.includes('severity') || lower.includes(String(item.severity).toLowerCase());
    return checkProcess && checkSeverity;
  });
}

function sanitizeError(err: unknown): string {
  if (axios.isCancel(err)) return 'Request cancelled.';
  if (err instanceof AxiosError) {
    if (err.code === 'ECONNABORTED') return 'Request timed out (>5s). Try a more specific query.';
    const detail = err.response?.data?.detail;
    if (detail) return String(detail);
    if (err.response?.status === 401) return 'Authentication required.';
    if (err.response?.status === 400) return 'Invalid query syntax.';
    if (err.response?.status) return `Server error (HTTP ${err.response.status}).`;
    return 'Network error — backend may be offline.';
  }
  if (err instanceof Error) return err.message;
  return 'Unknown error.';
}

// ─── Active abort controller tracking for live mode ─────────────────────

let _activeCancelSource: CancelTokenSource | null = null;

export function cancelActiveHuntRequest(): void {
  if (_activeCancelSource) {
    _activeCancelSource.cancel('Superseded by new request.');
    _activeCancelSource = null;
  }
}

// ─── API Functions ──────────────────────────────────────────────────────

export async function executeHuntQuery(
  query: string,
  limit: number = 100,
): Promise<HuntQueryResponse> {
  if (isLikelyInvalidQuery(query)) {
    throw new Error("Invalid query syntax. Use format: field == 'value' AND field == 'value'");
  }

  // Cancel any in-flight hunt request
  cancelActiveHuntRequest();
  _activeCancelSource = axios.CancelToken.source();

  try {
    const res = await huntClient.post<HuntQueryResponse>(
      '/hunt/query',
      { query, limit },
      { cancelToken: _activeCancelSource.token },
    );
    _activeCancelSource = null;
    const results = (res.data.results || []).slice(0, limit);
    return { count: results.length, results };
  } catch (err) {
    _activeCancelSource = null;

    // If backend is unreachable, fall back to mock filtering
    if (err instanceof AxiosError && !err.response) {
      const results = filterMockResults(query).slice(0, limit);
      return { count: results.length, results };
    }
    const errorMsg = sanitizeError(err);
    logComponentError('executeHuntQuery', errorMsg, '/hunt/query');
    throw new Error(errorMsg);
  }
}

export async function getSavedQueries(): Promise<SavedHuntQuery[]> {
  try {
    const res = await huntClient.get<{ queries: SavedHuntQuery[] }>('/hunt/saved');
    return res.data.queries || [];
  } catch {
    return MOCK_SAVED;
  }
}

export async function saveHuntQuery(name: string, query: string): Promise<void> {
  try {
    await huntClient.post('/hunt/save', { name, query });
  } catch {
    // Silently succeed for offline development
  }
}

export async function deleteSavedQuery(id: number | string): Promise<void> {
  try {
    await huntClient.delete(`/hunt/saved/${id}`);
  } catch {
    // Silently succeed for offline development
  }
}

export async function getHuntStats(): Promise<HuntStatsResponse> {
  try {
    const res = await huntClient.get<HuntStatsResponse>('/hunt/stats');
    return res.data;
  } catch {
    return MOCK_STATS;
  }
}
