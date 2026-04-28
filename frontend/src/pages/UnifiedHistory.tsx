import { useState, useMemo } from "react";
import {
  Search,
  AlertTriangle,
  Database,
  Cpu,
  RefreshCw,
  ExternalLink,
  HardDrive,
} from "lucide-react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import DashboardLayout from "@/components/dashboard/DashboardLayout";
import RadarLoader from "@/components/dashboard/RadarLoader";
import { useUnifiedHistory } from "@/hooks/useBrowserForensics";
import { extractDomain } from "@/data/browserData";

export default function UnifiedHistory() {
  const { history, loading, refetch } = useUnifiedHistory();
  const [searchQuery, setSearchQuery] = useState("");
  const [filterMode, setFilterMode] = useState<"all" | "standard" | "private">("all");

  const normalizedHistory = useMemo(() => {
    return history.map((entry) => {
      const record = entry as Record<string, unknown>;
      const time = String(record.Time ?? record.time ?? "");
      const url = String(record.URL ?? record.url ?? "");
      const title = String(record.Title ?? record.title ?? "");
      const sourceRaw = String(record.Source ?? record.source ?? "");
      const typeRaw = String(record.Type ?? record.type ?? "");

      const isRamSource = /ram|memory|artifact/i.test(sourceRaw);
      const isPrivateType = /incognito|private|inprivate|artifact/i.test(typeRaw);
      const isPrivate = isRamSource || isPrivateType;

      return {
        time,
        url,
        title,
        sourceRaw,
        typeRaw,
        isPrivate,
        sourceLabel: isPrivate ? "RAM (Private)" : "Disk",
        modeLabel: isPrivate ? "Private Mode" : "Standard",
      };
    });
  }, [history]);

  const filteredHistory = useMemo(() => {
    let items = normalizedHistory;
    if (filterMode !== "all") {
      items = items.filter((h) => (filterMode === "private" ? h.isPrivate : !h.isPrivate));
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      items = items.filter(
        (h) =>
          h.title.toLowerCase().includes(q) ||
          h.url.toLowerCase().includes(q) ||
          h.sourceRaw.toLowerCase().includes(q)
      );
    }
    return items;
  }, [normalizedHistory, searchQuery, filterMode]);

  // Activity heatmap data - group by hour
  const heatmapData = useMemo(() => {
    const hours: Record<string, { hour: string; disk: number; private: number; total: number }> = {};
    normalizedHistory.forEach((h) => {
      const date = new Date(h.time);
      if (Number.isNaN(date.getTime())) return;
      const hourKey = `${date.getHours().toString().padStart(2, "0")}:00`;
      if (!hours[hourKey]) hours[hourKey] = { hour: hourKey, disk: 0, private: 0, total: 0 };
      hours[hourKey].total++;
      if (h.isPrivate) hours[hourKey].private++;
      else hours[hourKey].disk++;
    });
    return Object.values(hours).sort((a, b) => a.hour.localeCompare(b.hour));
  }, [normalizedHistory]);

  const privateCount = normalizedHistory.filter((h) => h.isPrivate).length;
  const diskCount = normalizedHistory.length - privateCount;

  if (loading) {
    return (
      <DashboardLayout>
        <RadarLoader label="Loading unified history..." />
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Page Header */}
        <div className="flex items-center justify-between">
          <div>
            <h2 className="font-mono text-sm font-bold uppercase tracking-wider text-foreground">
              Unified History — Disk + RAM Analysis
            </h2>
            <p className="mt-1 font-mono text-xs text-muted-foreground">
              Merged view of disk-based browser history and memory-recovered artifacts
            </p>
          </div>
          <button
            onClick={() => refetch()}
            className="group flex items-center gap-2 rounded-lg border border-primary/20 bg-primary/10 px-3 py-1.5 font-mono text-xs text-primary transition-all hover:bg-primary/20 hover:shadow-[0_0_10px_rgba(0,243,255,0.2)]"
          >
            <RefreshCw className="h-3.5 w-3.5 transition-transform group-hover:rotate-180" />
            REFRESH
          </button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div className="glass rounded-lg p-4">
            <div className="flex items-center gap-3">
              <div className="rounded-lg bg-primary/10 p-2.5">
                <Database className="h-5 w-5 text-primary" />
              </div>
              <div>
                <p className="font-mono text-2xl font-bold text-foreground">{normalizedHistory.length}</p>
                <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                  Total Entries
                </p>
              </div>
            </div>
          </div>
          <div className="glass rounded-lg border-incognito/20 p-4 glow-incognito">
            <div className="flex items-center gap-3">
              <div className="rounded-lg bg-incognito/10 p-2.5">
                <Cpu className="h-5 w-5 text-incognito" />
              </div>
              <div>
                <p className="font-mono text-2xl font-bold text-incognito">{privateCount}</p>
                <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                  Private Mode (RAM)
                </p>
              </div>
            </div>
          </div>
          <div className="glass rounded-lg p-4">
            <div className="flex items-center gap-3">
              <div className="rounded-lg bg-primary/10 p-2.5">
                <HardDrive className="h-5 w-5 text-primary" />
              </div>
              <div>
                <p className="font-mono text-2xl font-bold text-primary">{diskCount}</p>
                <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                  Standard (Disk)
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Activity Heatmap */}
        <div className="glass rounded-lg p-5">
          <h3 className="mb-4 font-mono text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Activity Intensity by Hour
          </h3>
          <div className="h-[200px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={heatmapData} margin={{ left: 0, right: 10 }}>
                <XAxis
                  dataKey="hour"
                  tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 10, fontFamily: "JetBrains Mono" }}
                  axisLine={{ stroke: "hsl(var(--border))" }}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 10, fontFamily: "JetBrains Mono" }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "hsl(var(--card))",
                    border: "1px solid hsl(var(--border))",
                    borderRadius: "8px",
                    fontFamily: "JetBrains Mono",
                    fontSize: "12px",
                    color: "hsl(var(--foreground))",
                  }}
                />
                <Bar dataKey="disk" stackId="a" fill="hsl(200, 100%, 50%)" radius={[0, 0, 0, 0]} name="Disk" />
                <Bar dataKey="private" stackId="a" fill="hsl(25, 95%, 55%)" radius={[4, 4, 0, 0]} name="Private Mode (RAM)" />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-3 flex gap-4">
            <div className="flex items-center gap-2">
              <div className="h-2.5 w-2.5 rounded-sm bg-primary" />
              <span className="font-mono text-[10px] text-muted-foreground">Disk</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="h-2.5 w-2.5 rounded-sm bg-incognito" />
              <span className="font-mono text-[10px] text-muted-foreground">Private Mode (RAM)</span>
            </div>
          </div>
        </div>

        {/* Filter Bar */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative max-w-xs flex-1">
            <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search URLs, titles..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full rounded-lg border border-border bg-background py-2 pl-9 pr-3 font-mono text-xs text-foreground placeholder:text-muted-foreground focus:border-primary/50 focus:outline-none focus:ring-1 focus:ring-primary/30"
            />
          </div>
          <div className="flex gap-1">
            {(["all", "standard", "private"] as const).map((f) => (
              <button
                key={f}
                onClick={() => setFilterMode(f)}
                className={`rounded-lg px-3 py-2 font-mono text-[10px] uppercase tracking-wider transition-all ${filterMode === f
                  ? f === "private"
                    ? "bg-incognito/15 text-incognito border border-incognito/30"
                    : "bg-primary/15 text-primary border border-primary/30"
                  : "bg-secondary text-muted-foreground border border-transparent hover:text-foreground"
                  }`}
              >
                {f === "all" ? "All" : f === "private" ? "Private Mode" : "Standard"}
              </button>
            ))}
          </div>
        </div>

        {/* Unified History Table */}
        <div className="glass rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b bg-secondary/30">
                  <th className="px-4 py-3 text-left font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Time</th>
                  <th className="px-4 py-3 text-left font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Title</th>
                  <th className="px-4 py-3 text-left font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">URL</th>
                  <th className="px-4 py-3 text-left font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Source</th>
                  <th className="px-4 py-3 text-left font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Type</th>
                </tr>
              </thead>
              <tbody>
                {filteredHistory.length === 0 ? (
                  <tr>
                    <td
                      colSpan={5}
                      className="px-4 py-6 text-center font-mono text-xs text-muted-foreground"
                    >
                      No history entries match the current filters.
                    </td>
                  </tr>
                ) : (
                  filteredHistory.map((entry, i) => {
                    const isPrivate = entry.isPrivate;
                    const timeLabel = (() => {
                      const date = new Date(entry.time);
                      return Number.isNaN(date.getTime())
                        ? entry.time || "Unknown"
                        : date.toLocaleTimeString();
                    })();
                    const domain = extractDomain(entry.url);
                    const isLink = entry.url.startsWith("http");
                    return (
                      <tr
                        key={i}
                        className={`border-b border-border/30 transition-colors hover:bg-secondary/20 ${isPrivate ? "bg-incognito-row" : ""
                          }`}
                      >
                        <td className="px-4 py-2.5 font-mono text-xs text-muted-foreground whitespace-nowrap">
                          {timeLabel}
                        </td>
                        <td className="max-w-[200px] truncate px-4 py-2.5 font-mono text-xs text-foreground">
                          {entry.title || "Untitled"}
                        </td>
                        <td className="max-w-[250px] px-4 py-2.5">
                          <div className="flex items-center gap-2">
                            {isLink && (
                              <img
                                src={`https://www.google.com/s2/favicons?domain=${domain}&sz=32`}
                                alt="favicon"
                                className="h-4 w-4 rounded-sm opacity-70"
                                onError={(e) => {
                                  (e.target as HTMLImageElement).style.display = "none";
                                }}
                              />
                            )}
                            {isLink ? (
                              <a
                                href={entry.url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="truncate font-mono text-[11px] text-neon hover:underline hover:text-neon/80 flex items-center gap-1"
                              >
                                {domain}
                                <ExternalLink className="h-2.5 w-2.5 opacity-50" />
                              </a>
                            ) : (
                              <span className="truncate font-mono text-[11px] text-muted-foreground">
                                {domain || entry.url || "Unknown"}
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-2.5">
                          <span
                            className={`inline-flex items-center gap-1 rounded px-2 py-0.5 font-mono text-[10px] font-medium ${isPrivate
                                ? "bg-incognito/15 text-incognito"
                                : "bg-primary/10 text-primary"
                              }`}
                          >
                            {isPrivate ? <Cpu className="h-2.5 w-2.5" /> : <Database className="h-2.5 w-2.5" />}
                            {entry.sourceLabel}
                          </span>
                          {entry.sourceRaw && (
                            <p className="mt-1 font-mono text-[9px] text-muted-foreground">
                              {entry.sourceRaw}
                            </p>
                          )}
                        </td>
                        <td className="px-4 py-2.5">
                          {isPrivate ? (
                            <span className="inline-flex items-center gap-1 rounded bg-destructive/15 px-2 py-0.5 font-mono text-[10px] font-bold text-destructive animate-pulse-glow">
                              <AlertTriangle className="h-2.5 w-2.5" />
                              PRIVATE MODE
                            </span>
                          ) : (
                            <span className="rounded bg-success/10 px-2 py-0.5 font-mono text-[10px] text-success">
                              Standard
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
