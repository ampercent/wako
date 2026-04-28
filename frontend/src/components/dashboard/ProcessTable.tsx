import { useState, useMemo, useEffect } from "react";
import { ArrowUpDown, ChevronDown, ChevronUp } from "lucide-react";
import type { Process } from "@/data/initialData";

interface ProcessTableProps {
  processes: Process[];
  loading: boolean;
  onSelectProcess: (process: Process) => void;
  onSortedChange?: (processes: Process[]) => void;
}

type SortField = "PID" | "ImageFileName" | "ThreatScore" | "CreateTime";
type SortDir = "asc" | "desc";

function getThreatBadge(score: number) {
  if (score >= 7)
    return (
      <span className="inline-flex items-center rounded-full bg-destructive/20 px-2 py-0.5 text-xs font-semibold text-destructive animate-pulse-glow">
        CRITICAL
      </span>
    );
  if (score > 3)
    return (
      <span className="inline-flex items-center rounded-full bg-destructive/15 px-2 py-0.5 text-xs font-semibold text-threat-high">
        HIGH
      </span>
    );
  if (score > 1.5)
    return (
      <span className="inline-flex items-center rounded-full bg-warning/15 px-2 py-0.5 text-xs font-semibold text-warning">
        MEDIUM
      </span>
    );
  return (
    <span className="inline-flex items-center rounded-full bg-primary/10 px-2 py-0.5 text-xs font-semibold text-primary">
      LOW
    </span>
  );
}

export default function ProcessTable({
  processes,
  loading,
  onSelectProcess,
  onSortedChange,
}: ProcessTableProps) {
  const [sortField, setSortField] = useState<SortField>("ThreatScore");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const sorted = useMemo(() => {
    return [...processes].sort((a, b) => {
      const aVal = a[sortField];
      const bVal = b[sortField];
      const cmp = typeof aVal === "string" ? aVal.localeCompare(bVal as string) : (aVal as number) - (bVal as number);
      return sortDir === "asc" ? cmp : -cmp;
    });
  }, [processes, sortField, sortDir]);

  useEffect(() => {
    onSortedChange?.(sorted);
  }, [sorted, onSortedChange]);

  function toggleSort(field: SortField) {
    if (sortField === field) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortField(field);
      setSortDir("desc");
    }
  }

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field)
      return <ArrowUpDown className="ml-1 inline h-3 w-3 text-muted-foreground" />;
    return sortDir === "asc" ? (
      <ChevronUp className="ml-1 inline h-3 w-3 text-primary" />
    ) : (
      <ChevronDown className="ml-1 inline h-3 w-3 text-primary" />
    );
  };

  const headers: { label: string; field: SortField }[] = [
    { label: "PID", field: "PID" },
    { label: "Process Name", field: "ImageFileName" },
    { label: "Threat Score", field: "ThreatScore" },
    { label: "Created", field: "CreateTime" },
  ];

  if (loading) {
    return (
      <div className="glass rounded-lg p-8">
        <div className="flex items-center justify-center gap-3 text-muted-foreground">
          <div className="h-5 w-5 animate-spin rounded-full border-2 border-primary border-t-transparent" />
          <span className="font-mono text-sm">Scanning memory...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="glass rounded-lg overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b bg-secondary/50">
              {headers.map((h) => (
                <th
                  key={h.field}
                  className="cursor-pointer px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground hover:text-foreground transition-colors select-none"
                  onClick={() => toggleSort(h.field)}
                >
                  {h.label}
                  <SortIcon field={h.field} />
                </th>
              ))}
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Type
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Status
              </th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((proc) => (
              <tr
                key={proc.PID}
                onClick={() => onSelectProcess(proc)}
                className={`cursor-pointer border-b border-border/50 transition-colors hover:bg-secondary/30 ${proc.ThreatScore > 3 ? "bg-threat-row" : ""
                  }`}
              >
                <td className="px-4 py-3 font-mono text-xs text-muted-foreground">{proc.PID}</td>
                <td className="px-4 py-3 font-mono font-medium text-foreground">
                  {proc.ImageFileName}
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <div className="h-1.5 w-16 overflow-hidden rounded-full bg-secondary">
                      <div
                        className="h-full rounded-full transition-all"
                        style={{
                          width: `${Math.min(proc.ThreatScore * 10, 100)}%`,
                          backgroundColor:
                            proc.ThreatScore >= 7
                              ? "hsl(var(--threat-critical))"
                              : proc.ThreatScore > 3
                                ? "hsl(var(--threat-high))"
                                : proc.ThreatScore > 1.5
                                  ? "hsl(var(--threat-medium))"
                                  : "hsl(var(--threat-low))",
                        }}
                      />
                    </div>
                    <span className="font-mono text-xs text-muted-foreground">
                      {proc.ThreatScore.toFixed(1)}
                    </span>
                  </div>
                </td>
                <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                  {new Date(proc.CreateTime).toLocaleTimeString()}
                </td>
                <td className="px-4 py-3">
                  {proc.IsBrowser ? (
                    <span className="inline-flex items-center rounded bg-primary/10 px-2 py-0.5 text-xs font-medium text-primary">
                      Browser
                    </span>
                  ) : (
                    <span className="text-xs text-muted-foreground">System</span>
                  )}
                </td>
                <td className="px-4 py-3">{getThreatBadge(proc.ThreatScore)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
