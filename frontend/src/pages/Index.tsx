import { useMemo, useState } from "react";
import type { Process } from "@/data/initialData";
import { useProcesses } from "@/hooks/useApi";
import StatCards from "@/components/dashboard/StatCards";
import ProcessTable from "@/components/dashboard/ProcessTable";
import ProcessDrawer from "@/components/dashboard/ProcessDrawer";
import ThreatChart from "@/components/dashboard/ThreatChart";
import DashboardLayout from "@/components/dashboard/DashboardLayout";
import { useSystemStatus } from "@/hooks/useApi";
import CriticalFindings from "@/components/dashboard/CriticalFindings";
import { buildCriticalFindings, exportProcessReport } from "@/utils/reporting";
import { FileDown } from "lucide-react";
import { toast } from "sonner";

const Index = () => {
  const { isLive } = useSystemStatus();
  const { processes, loading } = useProcesses();
  const [selectedProcess, setSelectedProcess] = useState<Process | null>(null);
  const [sortedProcesses, setSortedProcesses] = useState<Process[]>([]);

  const processesForReport = sortedProcesses.length ? sortedProcesses : processes;
  const criticalFindings = useMemo(
    () => buildCriticalFindings(processesForReport),
    [processesForReport]
  );

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <StatCards processes={processes} isLive={isLive} />

        <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
          <div className="xl:col-span-2">
            <div className="mb-3 flex items-center justify-between">
              <h2 className="font-mono text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Process Memory Analysis
              </h2>
              <div className="flex items-center gap-3">
                <span className="font-mono text-xs text-muted-foreground">
                  {processes.length} processes
                </span>
                <button
                  onClick={() => {
                    const ok = exportProcessReport({
                      processes: processesForReport,
                      findings: criticalFindings,
                      title: "Digital Forensics Report",
                    });
                    if (!ok) {
                      toast.error("Report blocked", {
                        description: "Allow pop-ups to download the PDF report.",
                      });
                    } else {
                      toast.success("Report ready", {
                        description: "Use the print dialog to save as PDF.",
                      });
                    }
                  }}
                  className="flex items-center gap-2 rounded-lg border border-primary/30 bg-primary/10 px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-primary transition-colors hover:bg-primary/20"
                >
                  <FileDown className="h-3.5 w-3.5" />
                  Export PDF
                </button>
              </div>
            </div>
            <ProcessTable
              processes={processes}
              loading={loading}
              onSelectProcess={setSelectedProcess}
              onSortedChange={setSortedProcesses}
            />
          </div>
          <div className="xl:col-span-1 space-y-6">
            <div>
              <div className="mb-3">
                <h2 className="font-mono text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Threat Distribution
                </h2>
              </div>
              <ThreatChart processes={processes} />
            </div>
            <CriticalFindings findings={criticalFindings} />
          </div>
        </div>
      </div>

      {/* Process Drawer */}
      <ProcessDrawer
        process={selectedProcess}
        onClose={() => setSelectedProcess(null)}
      />
    </DashboardLayout>
  );
};

export default Index;
