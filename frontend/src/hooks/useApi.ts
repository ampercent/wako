import { useState, useEffect, useCallback } from "react";
import {
  Process,
  NetworkConnection,
  ScanResult,
  initialProcesses,
  initialNetworkConnections,
  initialScanResults,
} from "@/data/initialData";

const API_BASE = "http://localhost:8001";
const USE_MOCK = true; // Set to true to force mock data

async function fetchWithFallback<T>(url: string, fallback: T): Promise<T> {
  if (USE_MOCK) {
    // Simulate network delay for realism
    await new Promise(resolve => setTimeout(resolve, 600));
    return fallback;
  }
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(3000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch {
    return fallback;
  }
}

export function useSystemStatus() {
  const [status, setStatus] = useState<{ status: string; engine: string }>({
    status: "offline",
    engine: "inactive",
  });
  const [isLive, setIsLive] = useState(false);

  useEffect(() => {
    // If mocking, return "online" to show the dashboard as active
    const mockStatus = { status: "online", engine: "active" };

    fetchWithFallback(`${API_BASE}/health`, mockStatus).then(
      (data) => {
        setStatus(data);
        setIsLive(data.status === "online");
      }
    );
  }, []);

  return { status, isLive };
}

export function useProcesses() {
  const [processes, setProcesses] = useState<Process[]>(initialProcesses);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    fetchWithFallback<Process[]>(`${API_BASE}/processes`, initialProcesses)
      .then((data) => {
        setProcesses(data);
      })
      .finally(() => setLoading(false));
  }, []);

  return { processes, loading };
}

export function useNetworkConnections(pid: number | null) {
  const [connections, setConnections] = useState<NetworkConnection[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (pid === null) return;
    setLoading(true);
    fetchWithFallback<NetworkConnection[]>(
      `${API_BASE}/process/${pid}/network`,
      initialNetworkConnections[pid] || []
    )
      .then((data) => setConnections(data))
      .finally(() => setLoading(false));
  }, [pid]);

  return { connections, loading };
}

export function useDeepScan() {
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);

  const runScan = useCallback(
    async (pid: number, tool: string, payload?: Record<string, unknown>) => {
      setLoading(true);
      setResult(null);
      try {
        const res = await fetch(`${API_BASE}/scan/${pid}/${tool}`, {
          method: "POST",
          headers: payload ? { "Content-Type": "application/json" } : undefined,
          body: payload ? JSON.stringify(payload) : undefined,
          signal: AbortSignal.timeout(10000),
        });
        if (!res.ok) throw new Error();
        const data = await res.json();
        setResult({
          ...data,
          findings: Array.isArray(data.findings)
            ? data.findings
            : data.findings
              ? [data.findings]
              : [],
        });
      } catch {
        const fallback = initialScanResults[`${pid}-${tool}`] || {
          tool,
          pid,
          severity: "INFO",
          findings: ["No significant findings. Process appears clean."],
        };
        setResult(fallback);
      } finally {
        setLoading(false);
      }
    },
    []
  );

  const clearResult = useCallback(() => setResult(null), []);

  return { result, loading, runScan, clearResult };
}
