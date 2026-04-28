import { Activity, Shield, Globe, AlertTriangle } from "lucide-react";
import type { Process } from "@/data/initialData";

interface StatCardsProps {
  processes: Process[];
  isLive: boolean;
}

interface StatCardProps {
  label: string;
  value: number;
  icon: React.ReactNode;
  variant: "primary" | "danger" | "warning" | "success";
}

function StatCard({ label, value, icon, variant }: StatCardProps) {
  const variantStyles = {
    primary: "border-glow glow-primary",
    danger: "border-destructive/30 glow-danger",
    warning: "border-warning/30",
    success: "border-success/30 glow-success",
  };

  const iconStyles = {
    primary: "text-primary",
    danger: "text-destructive",
    warning: "text-warning",
    success: "text-success",
  };

  return (
    <div
      className={`glass rounded-lg p-5 transition-all hover:scale-[1.02] ${variantStyles[variant]}`}
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            {label}
          </p>
          <p className="mt-2 text-3xl font-bold font-mono text-card-foreground">{value}</p>
        </div>
        <div className={`rounded-lg bg-secondary p-3 ${iconStyles[variant]}`}>
          {icon}
        </div>
      </div>
    </div>
  );
}

export default function StatCards({ processes, isLive }: StatCardsProps) {
  const total = processes.length;
  const highRisk = processes.filter((p) => p.ThreatScore > 3).length;
  const browsers = processes.filter((p) => p.IsBrowser).length;

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <StatCard
        label="Total Processes"
        value={total}
        icon={<Activity className="h-5 w-5" />}
        variant="primary"
      />
      <StatCard
        label="High Risk"
        value={highRisk}
        icon={<AlertTriangle className="h-5 w-5" />}
        variant="danger"
      />
      <StatCard
        label="Active Browsers"
        value={browsers}
        icon={<Globe className="h-5 w-5" />}
        variant="warning"
      />
      <StatCard
        label={isLive ? "Engine Online" : "System Active"}
        value={1}
        icon={<Shield className="h-5 w-5" />}
        variant="success"
      />
    </div>
  );
}
