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
    <div className={`h-full flex flex-col text-gray-300 transition-all ${isFullScreen ? 'w-full bg-[#0B0F19] overflow-hidden' : 'bg-gray-950 border-t border-gray-800'}`}>
      <div className={`border-b border-gray-800 bg-gray-900 flex items-center justify-between shadow-sm sticky top-0 z-10 ${isFullScreen ? 'p-8' : 'p-2'}`}>
        <div className="flex items-center gap-4">
          <ShieldAlert className={isFullScreen ? "w-10 h-10 text-orange-500 shadow-[0_0_20px_rgba(249,115,22,0.2)]" : "w-4 h-4 text-orange-500"} />
          <div>
            <h2 className={`${isFullScreen ? 'text-2xl tracking-[0.2em]' : 'text-xs'} font-bold uppercase text-white`}>Threat Detection Engine</h2>
            {isFullScreen && <p className="text-xs text-gray-500 font-mono mt-1">Real-time Correlation & Automated Risk Attribution</p>}
          </div>
        </div>
        
        <div className="flex items-center gap-6">
           <div className="flex items-center gap-2 bg-gray-800/50 p-1.5 rounded-lg border border-gray-700">
             <span className="text-[10px] text-gray-500 font-bold uppercase px-3 font-mono">Order By</span>
             <button onClick={() => setSortBy('score')} className={`text-xs px-4 py-1.5 rounded-md transition-all font-bold ${sortBy === 'score' ? 'bg-indigo-500 text-white shadow-lg scale-105' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-700'}`}>Score</button>
             <button onClick={() => setSortBy('severity')} className={`text-xs px-4 py-1.5 rounded-md transition-all font-bold ${sortBy === 'severity' ? 'bg-indigo-500 text-white shadow-lg scale-105' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-700'}`}>Severity</button>
           </div>
           
           <div className={`flex flex-col items-end gap-1 ${isFullScreen ? 'block' : 'hidden md:flex'}`}>
              <span className="text-[10px] font-bold text-gray-600 uppercase">Status</span>
              <span className={`font-mono font-bold bg-red-950/30 text-red-500 px-4 py-1 rounded-full border border-red-900/40 shadow-[0_0_15px_rgba(239,68,68,0.1)] ${isFullScreen ? 'text-sm' : 'text-xs'}`}>
                {highCount} CRITICAL ALERT{highCount !== 1 ? 'S' : ''}
              </span>
           </div>
        </div>
      </div>
      
      <div className={`flex-1 overflow-y-auto ${isFullScreen ? 'p-8' : 'p-2'} bg-[#0B0F19]`}>
        {sortedAlerts.length === 0 ? (
          <div className="flex items-center justify-center h-full text-gray-600 text-sm italic font-mono uppercase tracking-[0.2em] opacity-50">
            No active threat anomalies detected in current feed.
          </div>
        ) : (
          <div className={`overflow-x-auto ${isFullScreen ? 'max-w-[1400px] mx-auto' : ''}`}>
            <table className="w-full text-left border-collapse text-sm">
              <thead className="bg-[#111827]/50 text-[10px] uppercase font-bold text-gray-500 tracking-[0.2em] border-b border-gray-800">
                <tr>
                  <th className={`${isFullScreen ? 'p-6' : 'p-3'} w-1/4`}>Source / Identity</th>
                  <th className={`${isFullScreen ? 'p-6' : 'p-3'} w-40 text-center`}>Severity</th>
                  <th className={`${isFullScreen ? 'p-6' : 'p-3'} w-32 text-center`}>Confidence</th>
                  <th className={`${isFullScreen ? 'p-6' : 'p-3'}`}>Forensic Narrative & Risk Summary</th>
                  <th className={`${isFullScreen ? 'p-6' : 'p-3'} w-40`}></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800 font-mono text-xs">
                {sortedAlerts.map((alert, idx) => {
                  const isHigh = alert.severity === 'HIGH';
                  const name = alert["Process Name"] || alert.ImageFileName || "Unknown";
                  
                  return (
                    <tr key={idx} className={`hover:bg-indigo-500/5 transition-all group ${isHigh ? 'bg-red-500/[0.02]' : ''}`}>
                      <td className={`${isFullScreen ? 'p-6' : 'p-3'}`}>
                        <div className="flex flex-col gap-1">
                          <span className={`font-bold tracking-normal ${isFullScreen ? 'text-lg' : ''} ${isHigh ? 'text-red-400 group-hover:text-red-300' : 'text-orange-400'}`}>
                            {name}
                          </span>
                          <div className="flex items-center gap-2">
                            <span className="text-gray-600 text-[10px] uppercase font-bold">PID</span>
                            <span className="text-gray-400">{alert.PID}</span>
                          </div>
                        </div>
                      </td>
                      <td className={`${isFullScreen ? 'p-6' : 'p-3'} text-center`}>
                        <span className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-[10px] font-black uppercase tracking-widest
                          ${isHigh ? 'bg-red-500/10 text-red-500 border border-red-500/20 shadow-[0_0_10px_rgba(239,68,68,0.1)]' : 'bg-orange-500/10 text-orange-500 border border-orange-500/20'}
                        `}>
                          <div className={`w-2 h-2 rounded-full ${isHigh ? 'bg-red-500' : 'bg-orange-500'}`}></div>
                          {alert.severity}
                        </span>
                      </td>
                      <td className={`${isFullScreen ? 'p-6' : 'p-3'} text-center`}>
                         <div className="flex flex-col items-center">
                           <span className={`font-black ${isFullScreen ? 'text-lg' : 'text-xs'} text-gray-300`}>
                              {alert.correlation_score.toFixed(0)}
                           </span>
                           <div className="w-12 h-1 bg-gray-800 rounded-full mt-1 overflow-hidden">
                              <div className={`h-full ${isHigh ? 'bg-red-500' : 'bg-orange-500'}`} style={{ width: `${alert.correlation_score}%` }}></div>
                           </div>
                         </div>
                      </td>
                      <td className={`${isFullScreen ? 'p-6' : 'p-3'}`}>
                        <p className={`text-gray-400 leading-relaxed font-sans max-w-3xl ${isFullScreen ? 'text-sm' : 'text-xs'}`}>
                          {alert.explanation}
                        </p>
                      </td>
                      <td className={`${isFullScreen ? 'p-6' : 'p-3'} text-right`}>
                         <button
                           onClick={() => handleFocus(alert.PID)}
                           className="inline-flex items-center justify-center gap-2 bg-gray-900 hover:bg-indigo-500 border border-gray-700 hover:border-indigo-400 px-5 py-2 rounded-lg text-gray-400 hover:text-white transition-all font-sans font-bold text-[10px] uppercase tracking-widest"
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

