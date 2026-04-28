import { useState, useCallback, useEffect } from "react";
import {
  BrowserArtifact,
  UnifiedHistoryEntry,
  initialBrowserArtifacts,
  initialUnifiedHistory,
} from "@/data/browserData";

const API_BASE = "http://localhost:8001";

async function fetchWithFallback<T>(url: string, fallback: T, method = "GET"): Promise<T> {
  try {
    const res = await fetch(url, { method, signal: AbortSignal.timeout(3000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch {
    return fallback;
  }
}

export function useBrowserScan() {
  const [artifacts, setArtifacts] = useState<BrowserArtifact[]>([]);
  const [loading, setLoading] = useState(false);
  const [scanned, setScanned] = useState(false);

  const runChracer = useCallback(async (pid: number) => {
    setLoading(true);
    setScanned(false);
    try {
      const res = await fetch(`${API_BASE}/scan/${pid}/chracer`, {
        method: "POST",
        signal: AbortSignal.timeout(10000),
      });
      if (!res.ok) throw new Error();
      const data = await res.json();
      // API may return { findings: [...] } or direct array
      setArtifacts(Array.isArray(data) ? data : data.artifacts || initialBrowserArtifacts);
    } catch {
      setArtifacts(initialBrowserArtifacts);
    } finally {
      setLoading(false);
      setScanned(true);
    }
  }, []);

  return { artifacts, loading, scanned, runChracer };
}

export function useUnifiedHistory() {
  const [history, setHistory] = useState<UnifiedHistoryEntry[]>(initialUnifiedHistory);
  const [loading, setLoading] = useState(false);

  const fetchHistory = useCallback(async () => {
    setLoading(true);
    await new Promise(resolve => setTimeout(resolve, 300)); // Simulate loading
    setHistory(initialUnifiedHistory);
    setLoading(false);
  }, []);

  useEffect(() => {
    // Already set to initial data on mount
  }, []);

  return { history, loading, refetch: fetchHistory };
}
