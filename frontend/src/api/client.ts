import axios from 'axios';

const API_BASE_URL = 'http://localhost:8001';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
});

export interface Alert {
  PID: number;
  ImageFileName?: string;
  "Process Name"?: string;
  severity: string;
  correlation_score: number;
  explanation: string;
}

export interface TimelineEvent {
  timestamp: string;
  event_type: string;
  pid: string | number;
  process_name: string;
  severity: string;
  is_suspicious: boolean;
  description: string;
}

export interface GraphNode {
  id: string;
  label: string;
  type: string;
  severity: string;
  correlation_score: number;
}

export interface GraphEdge {
  source: string;
  target: string;
  type: string;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

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

// -----------------------------------------------------
// STATIC MOCK DATA
// -----------------------------------------------------

const MOCK_GRAPH: GraphData = {
  "nodes": [
    { "id": "pid_1000", "label": "explorer.exe", "type": "process", "severity": "LOW", "correlation_score": 0 },
    { "id": "pid_2010", "label": "certutil.exe", "type": "process", "severity": "MEDIUM", "correlation_score": 3 },
    { "id": "pid_3010", "label": "powershell.exe", "type": "process", "severity": "HIGH", "correlation_score": 6 },
    { "id": "ip_8.8.8.8:443", "label": "8.8.8.8:443", "type": "network", "severity": "LOW", "correlation_score": 0 },
    { "id": "ip_198.51.100.1:4444", "label": "198.51.100.1:4444", "type": "network", "severity": "LOW", "correlation_score": 0 },
    { "id": "inject_3010", "label": "Memory Injection", "type": "injection", "severity": "HIGH", "correlation_score": 0 }
  ],
  "edges": [
    { "source": "pid_2010", "target": "ip_8.8.8.8:443", "type": "network_connection" },
    { "source": "pid_3010", "target": "ip_198.51.100.1:4444", "type": "network_connection" },
    { "source": "pid_1000", "target": "pid_2010", "type": "parent_child" },
    { "source": "pid_3010", "target": "inject_3010", "type": "injection" }
  ]
};

const MOCK_TIMELINE: TimelineEvent[] = [
  { "timestamp": "10:00:00", "event_type": "process_start", "pid": "1000", "process_name": "explorer.exe", "severity": "LOW", "is_suspicious": false, "description": "explorer.exe (PID 1000) started." },
  { "timestamp": "10:05:00", "event_type": "process_start", "pid": "2010", "process_name": "certutil.exe", "severity": "MEDIUM", "is_suspicious": true, "description": "certutil.exe (PID 2010) started, spawned by explorer.exe." },
  { "timestamp": "10:05:30", "event_type": "network_connect", "pid": "2010", "process_name": "certutil.exe", "severity": "MEDIUM", "is_suspicious": true, "description": "certutil.exe (PID 2010) connected to 8.8.8.8:443 (ESTABLISHED, TCPv4)." },
  { "timestamp": "10:06:00", "event_type": "process_start", "pid": "3010", "process_name": "powershell.exe", "severity": "HIGH", "is_suspicious": true, "description": "powershell.exe (PID 3010) started." },
  { "timestamp": "10:06:15", "event_type": "network_connect", "pid": "3010", "process_name": "powershell.exe", "severity": "HIGH", "is_suspicious": true, "description": "powershell.exe (PID 3010) connected to 198.51.100.1:4444 (ESTABLISHED, TCPv4)." },
  { "timestamp": "10:06:30", "event_type": "injection", "pid": "3010", "process_name": "powershell.exe", "severity": "HIGH", "is_suspicious": true, "description": "Memory injection detected in powershell.exe (PID 3010), protection: PAGE_EXECUTE_READWRITE." }
];

const MOCK_ALERTS: Alert[] = [
  { "PID": 3010, "ImageFileName": "powershell.exe", "Process Name": "powershell.exe", "severity": "HIGH", "correlation_score": 6, "explanation": "powershell.exe (PID 3010) initiated a network connection, shows signs of memory injection, and is a known abused system binary." },
  { "PID": 2010, "ImageFileName": "certutil.exe", "Process Name": "certutil.exe", "severity": "MEDIUM", "correlation_score": 3, "explanation": "certutil.exe (PID 2010) initiated a network connection, and is a known abused system binary." }
];

const MOCK_SUMMARY = { 
  summary: "1 high-risk process detected. 1 involves memory injection. 2 processes have network activity. Powershell and Certutil show anomalous behavior."
};

const MOCK_HUNT_RESULTS: HuntResultItem[] = [
  {
    case_id: 1,
    timestamp: '2026-04-27T10:06:30Z',
    process_name: 'powershell.exe',
    severity: 'HIGH',
    source: 'host-finance-01',
    pid: 3010,
    event_type: 'injection',
    ip: '198.51.100.1',
  },
  {
    case_id: 1,
    timestamp: '2026-04-27T10:05:30Z',
    process_name: 'certutil.exe',
    severity: 'MEDIUM',
    source: 'host-finance-01',
    pid: 2010,
    event_type: 'network_connect',
    ip: '8.8.8.8',
  },
  {
    case_id: 2,
    timestamp: '2026-04-27T11:10:12Z',
    process_name: 'wscript.exe',
    severity: 'HIGH',
    source: 'host-hr-02',
    pid: 4412,
    event_type: 'process_start',
    ip: '203.0.113.22',
  },
  {
    case_id: 3,
    timestamp: '2026-04-27T11:22:02Z',
    process_name: 'chrome.exe',
    severity: 'LOW',
    source: 'host-dev-05',
    pid: 9912,
    event_type: 'dns_query',
    ip: '1.1.1.1',
  },
];

const MOCK_HUNT_SAVED: SavedHuntQuery[] = [
  {
    id: 1,
    name: 'High severity script engines',
    query: "process_name == 'powershell.exe' AND severity == 'HIGH'",
    created_at: '2026-04-25T08:12:00Z',
  },
  {
    id: 2,
    name: 'Rare process executions',
    query: "event_type == 'process_start' AND severity != 'LOW'",
    created_at: '2026-04-26T14:32:00Z',
  },
];

const MOCK_HUNT_STATS: HuntStatsResponse = {
  stats: {
    most_common_processes: {
      'powershell.exe': 19,
      'certutil.exe': 11,
      'cmd.exe': 9,
      'wscript.exe': 7,
    },
    top_hosts: {
      'host-finance-01': 24,
      'host-hr-02': 16,
      'host-dev-05': 9,
    },
    frequent_ips: {
      '198.51.100.1': 12,
      '8.8.8.8': 10,
      '203.0.113.22': 7,
    },
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

// -----------------------------------------------------

export const getGraph = async (): Promise<GraphData> => {
  return Promise.resolve(MOCK_GRAPH);
};

export const getTimeline = async (): Promise<TimelineEvent[]> => {
  return Promise.resolve(MOCK_TIMELINE);
};

export const getAlerts = async (): Promise<Alert[]> => {
  return Promise.resolve(MOCK_ALERTS);
};

export const reportActivity = async (caseId: string | number, action: string, details: string) => {
    return _fetch(`/cases/${caseId}/activity`, {
        method: 'POST',
        body: JSON.stringify({ action, details }),
    });
};

const isLikelyInvalidQuery = (query: string) => {
  const normalized = query.trim();
  if (!normalized) return true;
  const hasOperator = /(==|!=|>=|<=|>|<)/.test(normalized);
  const hasField = /(process_name|severity|source|case_id|timestamp|event_type|pid|ip)/i.test(normalized);
  return !hasOperator || !hasField;
};

type ApiError = Error & { status?: number };

const _fetch = async <T>(path: string, init: RequestInit = {}): Promise<T> => {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(init.headers || {}),
    },
    ...init,
  });

  if (!response.ok) {
    let errorMessage = `HTTP ${response.status}`;
    try {
      const data = await response.json();
      errorMessage = data?.detail || data?.message || errorMessage;
    } catch {
      // ignore non-json body
    }
    const error = new Error(errorMessage) as ApiError;
    error.status = response.status;
    throw error;
  }

  return response.json() as Promise<T>;
};

// ==================================
// THREAT HUNTING API
// ==================================

export const executeHuntQuery = async (query: string): Promise<{count: number; results: HuntResultItem[]}> => {
  try {
    return await _fetch<{ count: number; results: HuntResultItem[] }>(`/hunt/query`, {
      method: 'POST',
      body: JSON.stringify({ query }),
    });
  } catch (error: any) {
    const status = error?.status;
    if (typeof status === 'number' && status >= 400 && status < 500) {
      throw new Error(error?.message || 'Invalid query syntax.');
    }

    if (isLikelyInvalidQuery(query)) {
      throw new Error('Invalid query syntax. Use format: field == value AND field == value.');
    }

    const lowered = query.toLowerCase();
    const results = MOCK_HUNT_RESULTS.filter((item) => {
      const checkProcess = !lowered.includes('process_name') || lowered.includes(item.process_name.toLowerCase());
      const checkSeverity = !lowered.includes('severity') || lowered.includes(String(item.severity).toLowerCase());
      return checkProcess && checkSeverity;
    });

    return { count: results.length, results };
  }
};

export const saveHuntQuery = async (name: string, query: string): Promise<{ ok: boolean }> => {
  try {
    return await _fetch<{ ok: boolean }>(`/hunt/save`, {
      method: 'POST',
      body: JSON.stringify({ name, query }),
    });
  } catch {
    return { ok: true };
  }
};

export const getSavedQueries = async (): Promise<{ queries: SavedHuntQuery[] }> => {
  try {
    return await _fetch<{ queries: SavedHuntQuery[] }>(`/hunt/saved`, { method: 'GET' });
  } catch {
    return { queries: MOCK_HUNT_SAVED };
  }
};

export const deleteSavedQuery = async (qId: number | string): Promise<any> => {
  try {
    return await _fetch(`/hunt/saved/${qId}`, { method: 'DELETE' });
  } catch {
    return { ok: true };
  }
};

export const getHuntStats = async (): Promise<HuntStatsResponse> => {
  try {
    return await _fetch<HuntStatsResponse>(`/hunt/stats`, { method: 'GET' });
  } catch {
    return MOCK_HUNT_STATS;
  }
};

export const getSummary = async (): Promise<{ summary: string }> => {
  return Promise.resolve(MOCK_SUMMARY);
};

export default apiClient;
