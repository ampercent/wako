import { useState, useEffect } from "react";
import { X, Wifi, Search, AlertTriangle, Shield, Loader2 } from "lucide-react";
import type { Process } from "@/data/initialData";
import { useNetworkConnections, useDeepScan } from "@/hooks/useApi";
import { toast } from "sonner";

interface ProcessDrawerProps {
  process: Process | null;
  onClose: () => void;
}

export default function ProcessDrawer({ process, onClose }: ProcessDrawerProps) {
  const { connections, loading: netLoading } = useNetworkConnections(process?.PID ?? null);
  const { result: scanResult, loading: scanLoading, runScan, clearResult } = useDeepScan();
  const [activeTab, setActiveTab] = useState<"network" | "scan">("network");
  const [selectedTool, setSelectedTool] = useState<"malfind" | "yara">("malfind");
  const [yaraPattern, setYaraPattern] = useState("powershell");

  useEffect(() => {
    if (!process) return;
    clearResult();
    setSelectedTool("malfind");
  }, [process?.PID, clearResult]);

  // Toast on scan completion
  useEffect(() => {
    if (scanResult && !scanLoading) {
      const severity = scanResult.severity || "INFO";
      if (severity === "CRITICAL" || severity === "HIGH") {
        toast.error("Scan Complete — Threats Found", {
          description: `${scanResult.findings.length} finding(s) at ${severity} severity`,
        });
      } else {
        toast.success("Scan Complete", {
          description: `${scanResult.findings.length} finding(s) — ${severity}`,
        });
      }
    }
  }, [scanResult, scanLoading]);

  function formatFinding(finding: unknown) {
    if (typeof finding === "string") return finding;
    if (finding && typeof finding === "object") {
      const record = finding as Record<string, unknown>;
      if (record.Type && record.Details) {
        return `${String(record.Type)}: ${String(record.Details)}`;
      }
      if (record.Title || record.URL) {
        const title = record.Title ? String(record.Title) : "Artifact";
        const url = record.URL ? String(record.URL) : "";
        return url ? `${title} — ${url}` : title;
      }
      return JSON.stringify(record);
    }
    return String(finding);
  }

  function handleScan() {
    if (!process) return;
    if (selectedTool === "yara" && !yaraPattern.trim()) {
      toast.error("YARA pattern required", {
        description: "Enter a string to search for in process memory.",
      });
      return;
    }
    clearResult();
    runScan(
      process.PID,
      selectedTool,
      selectedTool === "yara" ? { pattern: yaraPattern.trim() } : undefined
    );
    toast.info(`Running ${selectedTool.toUpperCase()}...`, {
      description:
        selectedTool === "malfind"
          ? `Scanning PID ${process.PID} for code injection`
          : `Searching PID ${process.PID} for "${yaraPattern.trim()}"`,
    });
  }

  if (!process) return null;

  const threatLevel =
    process.ThreatScore >= 7
      ? "CRITICAL"
      : process.ThreatScore > 3
        ? "HIGH"
        : process.ThreatScore > 1.5
          ? "MEDIUM"
          : "LOW";

  const threatColor =
    process.ThreatScore >= 7
      ? "text-threat-critical"
      : process.ThreatScore > 3
        ? "text-threat-high"
        : process.ThreatScore > 1.5
          ? "text-warning"
          : "text-primary";

  return (
    <>
      {/* Overlay */}
      <div
        className="fixed inset-0 z-40 bg-background/60 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Drawer */}
      <div className="fixed right-0 top-0 z-50 flex h-full w-full max-w-lg flex-col border-l glass-strong shadow-2xl animate-in slide-in-from-right duration-300">
        {/* Header */}
        <div className="flex items-center justify-between border-b p-5">
          <div>
            <h2 className="font-mono text-lg font-bold text-foreground">
              {process.ImageFileName}
            </h2>
            <p className="mt-0.5 font-mono text-xs text-muted-foreground">PID: {process.PID}</p>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-2 text-muted-foreground transition-colors hover:bg-secondary hover:text-foreground"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Process Info */}
        <div className="border-b p-5">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-xs uppercase tracking-wider text-muted-foreground">Threat Score</p>
              <p className={`mt-1 font-mono text-2xl font-bold ${threatColor}`}>
                {process.ThreatScore.toFixed(1)}
              </p>
            </div>
            <div>
              <p className="text-xs uppercase tracking-wider text-muted-foreground">Level</p>
              <p className={`mt-1 font-mono text-sm font-bold ${threatColor}`}>{threatLevel}</p>
            </div>
            <div>
              <p className="text-xs uppercase tracking-wider text-muted-foreground">Type</p>
              <p className="mt-1 font-mono text-sm text-foreground">
                {process.IsBrowser ? "Browser" : "System"}
              </p>
            </div>
            <div>
              <p className="text-xs uppercase tracking-wider text-muted-foreground">Created</p>
              <p className="mt-1 font-mono text-sm text-foreground">
                {new Date(process.CreateTime).toLocaleString()}
              </p>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex border-b">
          <button
            className={`flex items-center gap-2 px-5 py-3 text-sm font-medium transition-colors ${activeTab === "network"
                ? "border-b-2 border-primary text-primary"
                : "text-muted-foreground hover:text-foreground"
              }`}
            onClick={() => setActiveTab("network")}
          >
            <Wifi className="h-4 w-4" /> Network
          </button>
          <button
            className={`flex items-center gap-2 px-5 py-3 text-sm font-medium transition-colors ${activeTab === "scan"
                ? "border-b-2 border-primary text-primary"
                : "text-muted-foreground hover:text-foreground"
              }`}
            onClick={() => setActiveTab("scan")}
          >
            <Search className="h-4 w-4" /> Deep Scan
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-5">
          {activeTab === "network" && (
            <div>
              {netLoading ? (
                <div className="flex items-center gap-2 text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span className="font-mono text-xs">Fetching connections...</span>
                </div>
              ) : connections.length === 0 ? (
                <p className="font-mono text-xs text-muted-foreground">
                  No network connections found.
                </p>
              ) : (
                <div className="space-y-2">
                  {connections.map((conn, i) => (
                    <div
                      key={i}
                      className="rounded-md border bg-secondary/30 p-3"
                    >
                      <div className="flex items-center gap-2">
                        <span
                          className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${conn.Proto === "TCP"
                              ? "bg-primary/15 text-primary"
                              : "bg-warning/15 text-warning"
                            }`}
                        >
                          {conn.Proto}
                        </span>
                        <span
                          className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${conn.State === "ESTABLISHED"
                              ? "bg-success/15 text-success"
                              : "bg-muted text-muted-foreground"
                            }`}
                        >
                          {conn.State}
                        </span>
                      </div>
                      <div className="mt-2 space-y-1 font-mono text-xs">
                        <p>
                          <span className="text-muted-foreground">Local: </span>
                          <span className="text-foreground">{conn.LocalAddr}</span>
                        </p>
                        <p>
                          <span className="text-muted-foreground">Remote: </span>
                          <span className="text-foreground">{conn.ForeignAddr}</span>
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === "scan" && (
            <div>
              {/* Tool Selection */}
              <div className="mb-4 space-y-3">
                <div className="flex flex-wrap gap-2">
                  <button
                    onClick={() => setSelectedTool("malfind")}
                    className={`rounded-lg px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wider transition-colors ${selectedTool === "malfind"
                        ? "border border-destructive/40 bg-destructive/15 text-destructive"
                        : "border border-transparent bg-secondary text-muted-foreground hover:text-foreground"
                      }`}
                  >
                    Malfind
                  </button>
                  <button
                    onClick={() => setSelectedTool("yara")}
                    className={`rounded-lg px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wider transition-colors ${selectedTool === "yara"
                        ? "border border-primary/40 bg-primary/15 text-primary"
                        : "border border-transparent bg-secondary text-muted-foreground hover:text-foreground"
                      }`}
                  >
                    YARA
                  </button>
                </div>

                {selectedTool === "yara" && (
                  <div className="space-y-2">
                    <label className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                      YARA Pattern
                    </label>
                    <input
                      value={yaraPattern}
                      onChange={(e) => setYaraPattern(e.target.value)}
                      placeholder="Enter string to scan for"
                      className="w-full rounded-lg border border-border bg-background px-3 py-2 font-mono text-xs text-foreground placeholder:text-muted-foreground focus:border-primary/50 focus:outline-none focus:ring-1 focus:ring-primary/30"
                    />
                    <p className="font-mono text-[10px] text-muted-foreground">
                      Searches process memory for the specified string.
                    </p>
                  </div>
                )}

                <button
                  onClick={handleScan}
                  disabled={scanLoading}
                  className="flex items-center justify-center gap-2 rounded-lg border border-primary/30 bg-primary/10 px-4 py-2 text-sm font-medium text-primary transition-colors hover:bg-primary/20 disabled:opacity-50"
                >
                  {selectedTool === "malfind" ? <Shield className="h-4 w-4" /> : <Search className="h-4 w-4" />}
                  Scan
                </button>
              </div>

              {scanLoading && (
                <div className="flex items-center gap-2 text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span className="font-mono text-xs">Running deep scan...</span>
                </div>
              )}

              {scanResult && !scanLoading && (
                <div className="rounded-lg border bg-secondary/30 p-4">
                  <div className="mb-3 flex items-center gap-2">
                    <AlertTriangle
                      className={`h-4 w-4 ${scanResult.severity === "CRITICAL"
                          ? "text-threat-critical"
                          : scanResult.severity === "HIGH"
                            ? "text-threat-high"
                            : scanResult.severity === "MEDIUM"
                              ? "text-warning"
                              : "text-primary"
                        }`}
                    />
                    <span className="font-mono text-xs font-bold uppercase text-foreground">
                      {scanResult.tool} — {scanResult.severity || "INFO"}
                    </span>
                  </div>
                  {scanResult.findings.length === 0 ? (
                    <p className="font-mono text-xs text-muted-foreground">
                      No findings reported.
                    </p>
                  ) : (
                    <ul className="space-y-2">
                      {scanResult.findings.map((f, i) => (
                        <li
                          key={i}
                          className="rounded bg-background/50 p-2 font-mono text-xs leading-relaxed text-foreground/80"
                        >
                          {formatFinding(f)}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </>
  );
}
