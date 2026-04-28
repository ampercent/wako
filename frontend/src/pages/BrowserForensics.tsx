import { useState, useMemo } from "react";
import { Search, Globe, Clock, ExternalLink } from "lucide-react";
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
import { useBrowserScan } from "@/hooks/useBrowserForensics";
import { useProcesses } from "@/hooks/useApi";
import { extractDomain } from "@/data/browserData";
import { toast } from "sonner";

export default function BrowserForensics() {
  const { processes } = useProcesses();
  const { artifacts, loading, scanned, runChracer } = useBrowserScan();
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedPid, setSelectedPid] = useState<number | null>(null);

  const browserProcesses = useMemo(
    () => processes.filter((p) => p.IsBrowser),
    [processes]
  );

  const filteredArtifacts = useMemo(() => {
    if (!searchQuery) return artifacts;
    const q = searchQuery.toLowerCase();
    return artifacts.filter(
      (a) =>
        a.Title.toLowerCase().includes(q) ||
        a.URL.toLowerCase().includes(q) ||
        a.SessionID.toLowerCase().includes(q)
    );
  }, [artifacts, searchQuery]);

  // Domain analysis
  const domainData = useMemo(() => {
    const counts: Record<string, number> = {};
    artifacts.forEach((a) => {
      const domain = extractDomain(a.URL);
      counts[domain] = (counts[domain] || 0) + 1;
    });
    return Object.entries(counts)
      .map(([domain, count]) => ({ domain, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }, [artifacts]);

  function handleScan(pid: number) {
    setSelectedPid(pid);
    runChracer(pid);
    toast.info("Running Chracer scan...", { description: `Scanning PID ${pid} for browser artifacts` });
  }

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Page Header */}
        <div>
          <h2 className="font-mono text-sm font-bold uppercase tracking-wider text-foreground">
            Browser Forensics — Chracer Analysis
          </h2>
          <p className="mt-1 font-mono text-xs text-muted-foreground">
            Recover browsing artifacts from browser process memory including incognito/private sessions
          </p>
        </div>

        {/* Browser Process Selector */}
        <div className="glass rounded-lg p-5">
          <h3 className="mb-3 font-mono text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Select Browser Process to Scan
          </h3>
          <div className="flex flex-wrap gap-2">
            {browserProcesses.length === 0 ? (
              <p className="font-mono text-xs text-muted-foreground">No browser processes found</p>
            ) : (
              browserProcesses.map((p) => (
                <button
                  key={p.PID}
                  onClick={() => handleScan(p.PID)}
                  disabled={loading}
                  className={`flex items-center gap-2 rounded-lg border px-4 py-2.5 font-mono text-xs transition-all hover:scale-105 disabled:opacity-50 ${selectedPid === p.PID
                      ? "border-primary/50 bg-primary/10 text-primary glow-primary"
                      : "border-border bg-card text-foreground hover:border-primary/30"
                    }`}
                >
                  <Globe className="h-3.5 w-3.5" />
                  {p.ImageFileName}
                  <span className="text-muted-foreground">PID:{p.PID}</span>
                </button>
              ))
            )}
          </div>
        </div>

        {loading && <RadarLoader label="Extracting browser artifacts..." />}

        {scanned && !loading && (
          <>
            {/* Timeline */}
            <div className="glass rounded-lg p-5">
              <h3 className="mb-4 flex items-center gap-2 font-mono text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                <Clock className="h-4 w-4 text-primary" />
                Activity Timeline
              </h3>
              <div className="relative border-l-2 border-primary/20 pl-6 space-y-4">
                {artifacts.slice(0, 8).map((a, i) => (
                  <div key={i} className="relative">
                    <div className="absolute -left-[31px] top-1 h-3 w-3 rounded-full border-2 border-primary bg-background" />
                    <div className="rounded-lg border border-border/50 bg-card/50 p-3 transition-colors hover:border-primary/30">
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0 flex-1">
                          <p className="truncate font-mono text-xs font-medium text-foreground">
                            {a.Title}
                          </p>
                          <p className="mt-0.5 truncate font-mono text-[10px] text-neon">
                            {a.URL}
                          </p>
                        </div>
                        <span className="shrink-0 font-mono text-[10px] text-muted-foreground">
                          {new Date(a.Time).toLocaleTimeString()}
                        </span>
                      </div>
                      <div className="mt-1.5 flex gap-2">
                        <span className="rounded bg-secondary px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
                          {a.SessionID}
                        </span>
                        <span className="rounded bg-primary/10 px-1.5 py-0.5 font-mono text-[10px] text-primary">
                          Tab {a.Tab}
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Search & Data Grid */}
            <div className="glass rounded-lg p-5">
              <div className="mb-4 flex items-center justify-between gap-4">
                <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Recovered Artifacts
                </h3>
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
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b bg-secondary/30">
                      <th className="px-3 py-2.5 text-left font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Session</th>
                      <th className="px-3 py-2.5 text-left font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Tab</th>
                      <th className="px-3 py-2.5 text-left font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Title</th>
                      <th className="px-3 py-2.5 text-left font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">URL</th>
                      <th className="px-3 py-2.5 text-left font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredArtifacts.map((a, i) => (
                      <tr
                        key={i}
                        className="border-b border-border/30 transition-colors hover:bg-secondary/20"
                      >
                        <td className="px-3 py-2 font-mono text-xs text-primary">{a.SessionID}</td>
                        <td className="px-3 py-2 font-mono text-xs text-muted-foreground">{a.Tab}</td>
                        <td className="max-w-[200px] truncate px-3 py-2 font-mono text-xs text-foreground">{a.Title}</td>
                        <td className="max-w-[250px] truncate px-3 py-2">
                          <a
                            href={a.URL}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 font-mono text-[11px] text-neon hover:underline"
                          >
                            {extractDomain(a.URL)}
                            <ExternalLink className="h-2.5 w-2.5" />
                          </a>
                        </td>
                        <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground whitespace-nowrap">
                          {new Date(a.Time).toLocaleTimeString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Domain Analysis Chart */}
            <div className="glass rounded-lg p-5">
              <h3 className="mb-4 font-mono text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Top Domains Visited
              </h3>
              <div className="h-[280px]">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={domainData} layout="vertical" margin={{ left: 10, right: 20 }}>
                    <XAxis
                      type="number"
                      tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 11, fontFamily: "JetBrains Mono" }}
                      axisLine={{ stroke: "hsl(var(--border))" }}
                      tickLine={false}
                    />
                    <YAxis
                      type="category"
                      dataKey="domain"
                      width={180}
                      tick={{ fill: "hsl(185, 100%, 50%)", fontSize: 11, fontFamily: "JetBrains Mono" }}
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
                      formatter={(value: number) => [value, "Visits"]}
                      cursor={{ fill: "hsl(var(--primary) / 0.05)" }}
                    />
                    <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={16}>
                      {domainData.map((_, i) => (
                        <Cell key={i} fill={`hsl(${185 + i * 8}, 80%, ${55 - i * 3}%)`} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </>
        )}

        {!scanned && !loading && (
          <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-border py-20">
            <Globe className="mb-4 h-12 w-12 text-muted-foreground/30" />
            <p className="font-mono text-sm text-muted-foreground">
              Select a browser process above to begin artifact recovery
            </p>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
