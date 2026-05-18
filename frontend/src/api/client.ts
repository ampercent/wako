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
// STATIC MOCK DATA — Insider Threat / Data Exfiltration Scenario
// -----------------------------------------------------

const MOCK_GRAPH: GraphData = {
  nodes: [
    { id: "pid_1388", label: "explorer.exe", type: "process", severity: "LOW", correlation_score: 0.7 },
    { id: "pid_2412", label: "EXCEL.EXE", type: "process", severity: "LOW", correlation_score: 2.4 },
    { id: "pid_4100", label: "powershell.exe", type: "process", severity: "HIGH", correlation_score: 7.8 },
    { id: "pid_4264", label: "certutil.exe", type: "process", severity: "HIGH", correlation_score: 6.2 },
    { id: "pid_4388", label: "cmd.exe", type: "process", severity: "MEDIUM", correlation_score: 5.1 },
    { id: "pid_4520", label: "rundll32.exe", type: "process", severity: "HIGH", correlation_score: 8.4 },
    { id: "pid_4680", label: "mshta.exe", type: "process", severity: "HIGH", correlation_score: 9.1 },
    { id: "pid_4812", label: "wscript.exe", type: "process", severity: "HIGH", correlation_score: 7.3 },
    { id: "pid_5560", label: "ncat.exe", type: "process", severity: "HIGH", correlation_score: 9.5 },
    { id: "pid_5720", label: "rclone.exe", type: "process", severity: "HIGH", correlation_score: 8.7 },
    { id: "ip_198.51.100.14:4443", label: "198.51.100.14:4443", type: "network", severity: "HIGH", correlation_score: 0 },
    { id: "ip_203.0.113.88:8080", label: "203.0.113.88:8080", type: "network", severity: "MEDIUM", correlation_score: 0 },
    { id: "ip_45.33.32.156:4444", label: "45.33.32.156:4444", type: "network", severity: "HIGH", correlation_score: 0 },
    { id: "ip_203.0.113.22:443", label: "203.0.113.22:443", type: "network", severity: "MEDIUM", correlation_score: 0 },
    { id: "ip_162.159.135.232:443", label: "162.159.135.232:443 (MEGA CDN)", type: "network", severity: "HIGH", correlation_score: 0 },
    { id: "inject_4100", label: "Memory Injection (Cobalt Strike)", type: "injection", severity: "HIGH", correlation_score: 0 },
    { id: "inject_4520", label: "Reflective DLL Injection", type: "injection", severity: "HIGH", correlation_score: 0 },
  ],
  edges: [
    { source: "pid_1388", target: "pid_2412", type: "parent_child" },
    { source: "pid_2412", target: "pid_4100", type: "parent_child" },
    { source: "pid_4100", target: "pid_4264", type: "parent_child" },
    { source: "pid_4100", target: "pid_4388", type: "parent_child" },
    { source: "pid_4388", target: "pid_4520", type: "parent_child" },
    { source: "pid_4680", target: "pid_4812", type: "parent_child" },
    { source: "pid_4100", target: "ip_198.51.100.14:4443", type: "network_connection" },
    { source: "pid_4100", target: "ip_203.0.113.88:8080", type: "network_connection" },
    { source: "pid_4520", target: "ip_45.33.32.156:4444", type: "network_connection" },
    { source: "pid_4680", target: "ip_203.0.113.22:443", type: "network_connection" },
    { source: "pid_5720", target: "ip_162.159.135.232:443", type: "network_connection" },
    { source: "pid_4100", target: "inject_4100", type: "injection" },
    { source: "pid_4520", target: "inject_4520", type: "injection" },
  ],
};

const MOCK_TIMELINE: TimelineEvent[] = [
  { timestamp: "06:33:10", event_type: "process_start", pid: "1388", process_name: "explorer.exe", severity: "LOW", is_suspicious: false, description: "explorer.exe (PID 1388) started — user session initialized." },
  { timestamp: "07:01:05", event_type: "process_start", pid: "2256", process_name: "OUTLOOK.EXE", severity: "LOW", is_suspicious: false, description: "OUTLOOK.EXE (PID 2256) started — user opened email client." },
  { timestamp: "07:15:22", event_type: "process_start", pid: "2412", process_name: "EXCEL.EXE", severity: "LOW", is_suspicious: false, description: "EXCEL.EXE (PID 2412) opened — Q1_Financials_FINAL.xlsx." },
  { timestamp: "09:18:44", event_type: "process_start", pid: "3340", process_name: "chrome.exe", severity: "MEDIUM", is_suspicious: true, description: "chrome.exe (PID 3340) launched — browsed offensive security resources." },
  { timestamp: "11:42:18", event_type: "process_start", pid: "4100", process_name: "powershell.exe", severity: "HIGH", is_suspicious: true, description: "powershell.exe (PID 4100) spawned by EXCEL.EXE macro — encoded command detected." },
  { timestamp: "11:42:45", event_type: "network_connect", pid: "4100", process_name: "powershell.exe", severity: "HIGH", is_suspicious: true, description: "powershell.exe (PID 4100) connected to C2 at 198.51.100.14:4443." },
  { timestamp: "11:43:05", event_type: "process_start", pid: "4264", process_name: "certutil.exe", severity: "HIGH", is_suspicious: true, description: "certutil.exe (PID 4264) spawned — downloading encoded payload from C2." },
  { timestamp: "11:44:30", event_type: "process_start", pid: "4388", process_name: "cmd.exe", severity: "MEDIUM", is_suspicious: true, description: "cmd.exe (PID 4388) spawned by powershell.exe — command execution." },
  { timestamp: "11:45:12", event_type: "process_start", pid: "4520", process_name: "rundll32.exe", severity: "HIGH", is_suspicious: true, description: "rundll32.exe (PID 4520) executing DLL with suspicious entry point." },
  { timestamp: "11:45:30", event_type: "injection", pid: "4100", process_name: "powershell.exe", severity: "HIGH", is_suspicious: true, description: "Cobalt Strike beacon injected into powershell.exe (PID 4100) — PAGE_EXECUTE_READWRITE." },
  { timestamp: "11:46:00", event_type: "injection", pid: "4520", process_name: "rundll32.exe", severity: "HIGH", is_suspicious: true, description: "Reflective DLL injection detected in rundll32.exe (PID 4520)." },
  { timestamp: "11:46:55", event_type: "process_start", pid: "4680", process_name: "mshta.exe", severity: "HIGH", is_suspicious: true, description: "mshta.exe (PID 4680) executing HTA with embedded VBScript — LOLBin abuse." },
  { timestamp: "11:48:20", event_type: "process_start", pid: "4812", process_name: "wscript.exe", severity: "HIGH", is_suspicious: true, description: "wscript.exe (PID 4812) running dropper script — persistence mechanism." },
  { timestamp: "11:49:40", event_type: "process_start", pid: "4960", process_name: "regsvr32.exe", severity: "HIGH", is_suspicious: true, description: "regsvr32.exe (PID 4960) loading unsigned DLL via /s /n /u flags." },
  { timestamp: "11:50:30", event_type: "process_start", pid: "5104", process_name: "schtasks.exe", severity: "MEDIUM", is_suspicious: true, description: "schtasks.exe (PID 5104) creating scheduled task for persistence." },
  { timestamp: "12:10:22", event_type: "process_start", pid: "5560", process_name: "ncat.exe", severity: "HIGH", is_suspicious: true, description: "ncat.exe (PID 5560) opened reverse shell listener on port 4444." },
  { timestamp: "12:10:30", event_type: "network_connect", pid: "5560", process_name: "ncat.exe", severity: "HIGH", is_suspicious: true, description: "ncat.exe (PID 5560) — inbound C2 connection from 198.51.100.14:48210." },
  { timestamp: "12:15:48", event_type: "process_start", pid: "5720", process_name: "rclone.exe", severity: "HIGH", is_suspicious: true, description: "rclone.exe (PID 5720) started — bulk data exfiltration to MEGA cloud storage." },
  { timestamp: "12:16:00", event_type: "network_connect", pid: "5720", process_name: "rclone.exe", severity: "HIGH", is_suspicious: true, description: "rclone.exe transferring 2.4GB to MEGA via 162.159.135.232:443 — 847 files." },
];

const MOCK_ALERTS: Alert[] = [
  { PID: 4680, ImageFileName: "mshta.exe", "Process Name": "mshta.exe", severity: "HIGH", correlation_score: 9.1, explanation: "mshta.exe (PID 4680) executing HTA payload with embedded VBScript. Spawned wscript.exe child process. Connected to known staging server 203.0.113.22. Classic LOLBin proxy execution." },
  { PID: 5560, ImageFileName: "ncat.exe", "Process Name": "ncat.exe", severity: "HIGH", correlation_score: 9.5, explanation: "ncat.exe (PID 5560) listening on 0.0.0.0:4444 with active inbound connection from C2 IP 198.51.100.14. STDIN/STDOUT pipe to cmd.exe detected — active reverse shell." },
  { PID: 5720, ImageFileName: "rclone.exe", "Process Name": "rclone.exe", severity: "HIGH", correlation_score: 8.7, explanation: "rclone.exe (PID 5720) transferring 2.4GB (847 files) from C:\\Users\\jthompson\\Documents\\Finance\\Confidential\\ to MEGA cloud. Bandwidth throttle disabled." },
  { PID: 4520, ImageFileName: "rundll32.exe", "Process Name": "rundll32.exe", severity: "HIGH", correlation_score: 8.4, explanation: "rundll32.exe (PID 4520) reflective DLL injection detected. IAT hooks on kernel32.dll!CreateRemoteThread. Connected to 45.33.32.156:4444." },
  { PID: 4100, ImageFileName: "powershell.exe", "Process Name": "powershell.exe", severity: "HIGH", correlation_score: 7.8, explanation: "powershell.exe (PID 4100) spawned by EXCEL.EXE macro. Cobalt Strike beacon detected. C2 connections to 198.51.100.14:4443 and 203.0.113.88:8080. Mimikatz strings in memory." },
  { PID: 4812, ImageFileName: "wscript.exe", "Process Name": "wscript.exe", severity: "HIGH", correlation_score: 7.3, explanation: "wscript.exe (PID 4812) running VBScript dropper. Registry persistence via Run key. Downloaded stage2 payload from 203.0.113.22." },
  { PID: 4960, ImageFileName: "regsvr32.exe", "Process Name": "regsvr32.exe", severity: "MEDIUM", correlation_score: 6.8, explanation: "regsvr32.exe (PID 4960) loading unsigned DLL with /s /n /u flags — Squiblydoo attack pattern." },
  { PID: 4264, ImageFileName: "certutil.exe", "Process Name": "certutil.exe", severity: "MEDIUM", correlation_score: 6.2, explanation: "certutil.exe (PID 4264) used as download cradle — fetched base64-encoded payload from 198.51.100.14:443." },
];

const MOCK_SUMMARY = {
  summary: "CRITICAL: Active insider threat detected on workstation DESKTOP-JT7X9R2 (user: jthompson). Attack chain: malicious Excel macro → PowerShell C2 beacon → credential harvesting (Mimikatz) → lateral movement tools → data exfiltration (2.4GB via rclone to MEGA). 9 high-risk processes identified. Active reverse shell on port 4444. Immediate containment recommended."
};

const MOCK_HUNT_RESULTS: HuntResultItem[] = [
  { case_id: 1, timestamp: '2026-04-28T11:42:18Z', process_name: 'powershell.exe', severity: 'HIGH', source: 'DESKTOP-JT7X9R2', pid: 4100, event_type: 'injection', ip: '198.51.100.14' },
  { case_id: 1, timestamp: '2026-04-28T11:43:05Z', process_name: 'certutil.exe', severity: 'HIGH', source: 'DESKTOP-JT7X9R2', pid: 4264, event_type: 'network_connect', ip: '198.51.100.14' },
  { case_id: 1, timestamp: '2026-04-28T11:45:12Z', process_name: 'rundll32.exe', severity: 'HIGH', source: 'DESKTOP-JT7X9R2', pid: 4520, event_type: 'injection', ip: '45.33.32.156' },
  { case_id: 1, timestamp: '2026-04-28T11:46:55Z', process_name: 'mshta.exe', severity: 'HIGH', source: 'DESKTOP-JT7X9R2', pid: 4680, event_type: 'process_start', ip: '203.0.113.22' },
  { case_id: 1, timestamp: '2026-04-28T12:10:22Z', process_name: 'ncat.exe', severity: 'CRITICAL', source: 'DESKTOP-JT7X9R2', pid: 5560, event_type: 'network_connect', ip: '198.51.100.14' },
  { case_id: 1, timestamp: '2026-04-28T12:15:48Z', process_name: 'rclone.exe', severity: 'CRITICAL', source: 'DESKTOP-JT7X9R2', pid: 5720, event_type: 'network_connect', ip: '162.159.135.232' },
  { case_id: 2, timestamp: '2026-04-28T08:15:30Z', process_name: 'powershell.exe', severity: 'HIGH', source: 'SRV-DC01', pid: 7712, event_type: 'process_start', ip: '10.0.15.1' },
  { case_id: 2, timestamp: '2026-04-28T08:22:10Z', process_name: 'mimikatz.exe', severity: 'CRITICAL', source: 'SRV-DC01', pid: 7890, event_type: 'process_start', ip: '10.0.15.1' },
  { case_id: 3, timestamp: '2026-04-27T14:05:00Z', process_name: 'wscript.exe', severity: 'HIGH', source: 'DESKTOP-HR04', pid: 3310, event_type: 'process_start', ip: '203.0.113.22' },
  { case_id: 3, timestamp: '2026-04-27T14:12:00Z', process_name: 'cmd.exe', severity: 'MEDIUM', source: 'DESKTOP-HR04', pid: 3455, event_type: 'process_start', ip: '203.0.113.22' },
  { case_id: 4, timestamp: '2026-04-26T09:30:00Z', process_name: 'chrome.exe', severity: 'LOW', source: 'DESKTOP-DEV12', pid: 9912, event_type: 'dns_query', ip: '1.1.1.1' },
  { case_id: 4, timestamp: '2026-04-26T11:45:00Z', process_name: 'svchost.exe', severity: 'LOW', source: 'DESKTOP-DEV12', pid: 1024, event_type: 'network_connect', ip: '20.190.159.71' },
];

const MOCK_HUNT_SAVED: SavedHuntQuery[] = [
  { id: 1, name: 'LOLBin Execution Chain', query: "process_name == 'mshta.exe' OR process_name == 'regsvr32.exe' OR process_name == 'rundll32.exe'", created_at: '2026-04-27T08:12:00Z' },
  { id: 2, name: 'C2 Beaconing IPs', query: "ip == '198.51.100.14' OR ip == '203.0.113.22' OR ip == '45.33.32.156'", created_at: '2026-04-27T14:32:00Z' },
  { id: 3, name: 'High severity script engines', query: "process_name == 'powershell.exe' AND severity == 'HIGH'", created_at: '2026-04-25T08:12:00Z' },
  { id: 4, name: 'Data exfiltration tools', query: "process_name == 'rclone.exe' OR process_name == 'ncat.exe'", created_at: '2026-04-28T13:00:00Z' },
  { id: 5, name: 'Credential harvesting', query: "process_name == 'mimikatz.exe' AND severity >= 'HIGH'", created_at: '2026-04-28T09:15:00Z' },
];

const MOCK_HUNT_STATS: HuntStatsResponse = {
  stats: {
    most_common_processes: {
      'powershell.exe': 34, 'cmd.exe': 22, 'rundll32.exe': 18, 'certutil.exe': 15,
      'wscript.exe': 12, 'mshta.exe': 9, 'regsvr32.exe': 7, 'schtasks.exe': 6,
    },
    top_hosts: {
      'DESKTOP-JT7X9R2': 47, 'SRV-DC01': 28, 'DESKTOP-HR04': 19,
      'DESKTOP-DEV12': 8, 'SRV-FILE02': 6,
    },
    frequent_ips: {
      '198.51.100.14': 31, '203.0.113.22': 18, '45.33.32.156': 14,
      '162.159.135.232': 11, '192.0.2.100': 7, '185.204.1.235': 5,
    },
    total_events: 214,
    active_hosts: 5,
    high_severity_count: 83,
  },
  patterns: {
    repeated_processes_across_hosts: [
      { process_name: 'powershell.exe', host_count: 4 },
      { process_name: 'cmd.exe', host_count: 3 },
      { process_name: 'wscript.exe', host_count: 2 },
      { process_name: 'certutil.exe', host_count: 2 },
    ],
    rare_single_occurrences: [
      { process_name: 'mimikatz.exe', count: 1 },
      { process_name: 'ncat.exe', count: 1 },
      { process_name: 'rclone.exe', count: 1 },
      { process_name: 'bitsadmin.exe', count: 1 },
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
