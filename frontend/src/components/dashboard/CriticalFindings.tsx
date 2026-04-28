import { AlertTriangle } from "lucide-react";
import type { CriticalFinding } from "@/utils/reporting";

interface CriticalFindingsProps {
  findings: CriticalFinding[];
}

function severityColor(level: CriticalFinding["Level"]) {
  return level === "CRITICAL" ? "text-threat-critical" : "text-threat-high";
}

export default function CriticalFindings({ findings }: CriticalFindingsProps) {
  const topFindings = findings.slice(0, 6);

  return (
    <div className="glass rounded-lg p-5">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Critical Findings
          </h3>
          <p className="mt-1 font-mono text-[10px] text-muted-foreground">
            High-risk processes requiring immediate review
          </p>
        </div>
        <span className="font-mono text-xs text-muted-foreground">
          {findings.length} flagged
        </span>
      </div>

      {findings.length === 0 ? (
        <div className="rounded-lg border border-dashed border-border/60 bg-secondary/20 p-4">
          <p className="font-mono text-xs text-muted-foreground">
            No critical findings detected in the current process list.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {topFindings.map((finding) => (
            <div
              key={finding.PID}
              className="flex items-center justify-between rounded-lg border border-border/60 bg-secondary/30 p-3"
            >
              <div>
                <p className="font-mono text-xs font-semibold text-foreground">
                  {finding.ImageFileName}
                </p>
                <p className="font-mono text-[10px] text-muted-foreground">
                  PID {finding.PID} • {finding.CreatedLabel}
                </p>
              </div>
              <div className="flex items-center gap-2">
                <AlertTriangle className={`h-3.5 w-3.5 ${severityColor(finding.Level)}`} />
                <span className={`font-mono text-[10px] font-bold ${severityColor(finding.Level)}`}>
                  {finding.Level} {finding.ThreatScore.toFixed(1)}
                </span>
              </div>
            </div>
          ))}
          {findings.length > topFindings.length && (
            <p className="pt-1 font-mono text-[10px] text-muted-foreground">
              Showing top {topFindings.length} of {findings.length} findings.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
