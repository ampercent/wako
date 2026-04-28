import { NavLink } from "react-router-dom";
import StatusIndicator from "./StatusIndicator";
import { useSystemStatus } from "@/hooks/useApi";
import { ModeToggle } from "@/components/ModeToggle";

interface DashboardLayoutProps {
  children: React.ReactNode;
}

const navItems = [
  { to: "/", label: "Overview" },
  { to: "/browser-forensics", label: "Browser Forensics" },
  { to: "/unified-history", label: "Unified History" },
];

export default function DashboardLayout({ children }: DashboardLayoutProps) {
  const { isLive } = useSystemStatus();

  return (
    <div className="min-h-screen bg-background scanline">
      {/* Header */}
      <header className="border-b glass-strong sticky top-0 z-30">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3">
            <div>
              <h1 className="font-mono text-lg font-bold tracking-tight text-foreground">
                WAKO
              </h1>
              <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                Digital Forensics Dashboard
              </p>
            </div>
          </div>
          <div className="flex items-center gap-4">
             <ModeToggle />
          </div>
        </div>

        {/* Navigation */}
        <nav className="mx-auto flex max-w-7xl gap-1 px-6">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) =>
                `nav-link ${isActive ? "active" : ""}`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
      </header>

      {/* Main Content */}
      <main className="mx-auto max-w-7xl px-6 py-6">
        {children}
      </main>
    </div>
  );
}
