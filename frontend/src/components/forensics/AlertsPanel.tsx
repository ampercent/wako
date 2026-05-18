import React, { useMemo, useState } from 'react';
import { useStore } from '../store/useStore';
import { ShieldAlert, Crosshair, ArrowUpDown } from 'lucide-react';

export const AlertsPanel: React.FC<{ isFullScreen?: boolean }> = ({ isFullScreen = false }) => {
  const { alertsData, setSelectedNode, setSelectedPID } = useStore();
  const [sortBy, setSortBy] = useState<'severity' | 'score'>('score');

  const handleFocus = (pid: number) => {
    setSelectedPID(String(pid));
    setSelectedNode(`pid_${pid}`);
  };

  const sortedAlerts = useMemo(() => {
     let sorted = [...alertsData];
     if (sortBy === 'score') {
       sorted = sorted.sort((a, b) => b.correlation_score - a.correlation_score);
     } else {
       // HIGH over MEDIUM
       const rank = { 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0 };
       sorted = sorted.sort((a, b) => (rank[b.severity as 'HIGH'|'MEDIUM'|'LOW'] || 0) - (rank[a.severity as 'HIGH'|'MEDIUM'|'LOW'] || 0));
     }
     return sorted;
  }, [alertsData, sortBy]);

  const highCount = alertsData.filter(a => a.severity === 'HIGH').length;

  return (
    <div className={`h-full flex flex-col text-foreground transition-all ${isFullScreen ? 'w-full bg-background overflow-hidden' : 'bg-background border-t border-border'}`}>
      <div className={`border-b border-border bg-card flex items-center justify-between shadow-sm sticky top-0 z-10 ${isFullScreen ? 'p-8' : 'p-2'}`}>
        <div className="flex items-center gap-4">
          <ShieldAlert className={isFullScreen ? "w-10 h-10 text-destructive shadow-[0_0_20px_rgba(var(--destructive),0.2)]" : "w-4 h-4 text-destructive"} />
          <div>
            <h2 className={`${isFullScreen ? 'text-2xl tracking-[0.2em]' : 'text-xs'} font-bold uppercase text-foreground`}>Threat Detection Engine</h2>
            {isFullScreen && <p className="text-xs text-muted-foreground font-mono mt-1">Real-time Correlation & Automated Risk Attribution</p>}
          </div>
        </div>
        
        <div className="flex items-center gap-6">
           <div className="flex items-center gap-2 bg-muted/50 p-1.5 rounded-lg border border-border">
             <span className="text-[10px] text-muted-foreground font-bold uppercase px-3 font-mono">Order By</span>
             <button onClick={() => setSortBy('score')} className={`text-xs px-4 py-1.5 rounded-md transition-all font-bold ${sortBy === 'score' ? 'bg-primary text-primary-foreground shadow-lg scale-105' : 'text-muted-foreground hover:text-foreground hover:bg-muted'}`}>Score</button>
             <button onClick={() => setSortBy('severity')} className={`text-xs px-4 py-1.5 rounded-md transition-all font-bold ${sortBy === 'severity' ? 'bg-primary text-primary-foreground shadow-lg scale-105' : 'text-muted-foreground hover:text-foreground hover:bg-muted'}`}>Severity</button>
           </div>
           
           <div className={`flex flex-col items-end gap-1 ${isFullScreen ? 'block' : 'hidden md:flex'}`}>
              <span className="text-[10px] font-bold text-muted-foreground uppercase">Status</span>
              <span className={`font-mono font-bold bg-destructive/10 text-destructive px-4 py-1 rounded-full border border-destructive/20 shadow-[0_0_15px_rgba(var(--destructive),0.1)] ${isFullScreen ? 'text-sm' : 'text-xs'}`}>
                {highCount} CRITICAL ALERT{highCount !== 1 ? 'S' : ''}
              </span>
           </div>
        </div>
      </div>
      
      <div className={`flex-1 overflow-y-auto ${isFullScreen ? 'p-8' : 'p-2'} bg-background`}>
        {sortedAlerts.length === 0 ? (
          <div className="flex items-center justify-center h-full text-muted-foreground text-sm italic font-mono uppercase tracking-[0.2em] opacity-50">
            No active threat anomalies detected in current feed.
          </div>
        ) : (
          <div className={`overflow-x-auto ${isFullScreen ? 'max-w-[1400px] mx-auto' : ''}`}>
            <table className="w-full text-left border-collapse text-sm">
              <thead className="bg-muted/50 text-[10px] uppercase font-bold text-muted-foreground tracking-[0.2em] border-b border-border">
                <tr>
                  <th className={`${isFullScreen ? 'p-6' : 'p-3'} w-1/4`}>Source / Identity</th>
                  <th className={`${isFullScreen ? 'p-6' : 'p-3'} w-40 text-center`}>Severity</th>
                  <th className={`${isFullScreen ? 'p-6' : 'p-3'} w-32 text-center`}>Confidence</th>
                  <th className={`${isFullScreen ? 'p-6' : 'p-3'}`}>Forensic Narrative & Risk Summary</th>
                  <th className={`${isFullScreen ? 'p-6' : 'p-3'} w-40`}></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border font-mono text-xs">
                {sortedAlerts.map((alert, idx) => {
                  const isHigh = alert.severity === 'HIGH';
                  const name = alert["Process Name"] || alert.ImageFileName || "Unknown";
                  
                  return (
                    <tr key={idx} className={`hover:bg-primary/5 transition-all group ${isHigh ? 'bg-destructive/5' : ''}`}>
                      <td className={`${isFullScreen ? 'p-6' : 'p-3'}`}>
                        <div className="flex flex-col gap-1">
                          <span className={`font-bold tracking-normal ${isFullScreen ? 'text-lg' : ''} ${isHigh ? 'text-destructive group-hover:text-destructive' : 'text-warning'}`}>
                            {name}
                          </span>
                          <div className="flex items-center gap-2">
                            <span className="text-muted-foreground text-[10px] uppercase font-bold">PID</span>
                            <span className="text-muted-foreground/80">{alert.PID}</span>
                          </div>
                        </div>
                      </td>
                      <td className={`${isFullScreen ? 'p-6' : 'p-3'} text-center`}>
                        <span className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-[10px] font-black uppercase tracking-widest
                          ${isHigh ? 'bg-destructive/10 text-destructive border border-destructive/20 shadow-[0_0_10px_hsl(var(--destructive)/0.1)]' : 'bg-warning/10 text-warning border border-warning/20'}
                        `}>
                          <div className={`w-2 h-2 rounded-full ${isHigh ? 'bg-destructive' : 'bg-warning'}`}></div>
                          {alert.severity}
                        </span>
                      </td>
                      <td className={`${isFullScreen ? 'p-6' : 'p-3'} text-center`}>
                         <div className="flex flex-col items-center">
                           <span className={`font-black ${isFullScreen ? 'text-lg' : 'text-xs'} text-foreground`}>
                              {alert.correlation_score.toFixed(0)}
                           </span>
                           <div className="w-12 h-1 bg-muted rounded-full mt-1 overflow-hidden">
                              <div className={`h-full ${isHigh ? 'bg-destructive' : 'bg-warning'}`} style={{ width: `${Math.min(alert.correlation_score * 10, 100)}%` }}></div>
                           </div>
                         </div>
                      </td>
                      <td className={`${isFullScreen ? 'p-6' : 'p-3'}`}>
                        <p className={`text-muted-foreground leading-relaxed font-sans max-w-3xl ${isFullScreen ? 'text-sm' : 'text-xs'}`}>
                          {alert.explanation}
                        </p>
                      </td>
                      <td className={`${isFullScreen ? 'p-6' : 'p-3'} text-right`}>
                         <button
                           onClick={() => handleFocus(alert.PID)}
                           className="inline-flex items-center justify-center gap-2 bg-muted hover:bg-primary border border-border hover:border-primary px-5 py-2 rounded-lg text-muted-foreground hover:text-primary-foreground transition-all font-sans font-bold text-[10px] uppercase tracking-widest"
                         >
                            <Crosshair className="w-3.5 h-3.5" /> Execute Drilldown
                         </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

