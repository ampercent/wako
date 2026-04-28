import React, { useMemo } from 'react';
import { useStore } from '../store/useStore';
import { X, Activity, Cpu, Network, ShieldAlert, BookOpen } from 'lucide-react';

export const ProcessDetailsPanel: React.FC<{ isFullScreen?: boolean }> = ({ isFullScreen = false }) => {
  const { selectedPID, setSelectedPID, setSelectedNode, alertsData, timelineData, graphData } = useStore();

  const details = useMemo(() => {
    if (!selectedPID) return null;

    const alert = alertsData.find((a) => String(a.PID) === selectedPID);
    const node = graphData?.nodes.find((n) => n.id === `pid_${selectedPID}`);
    const pidTimeline = timelineData.filter((t) => String(t.pid) === selectedPID);

    const networkTargets = graphData?.edges
      .filter((e) => (typeof e.source === 'object' ? (e.source as any).id : e.source) === `pid_${selectedPID}` && e.type === 'network_connection')
      .map(e => {
         const tgtId = typeof e.target === 'object' ? (e.target as any).id : e.target;
         return tgtId.replace('ip_', '');
      });
      
    const hasInjection = graphData?.edges.some(e => 
      (typeof e.source === 'object' ? (e.source as any).id : e.source) === `pid_${selectedPID}` && e.type === 'injection'
    );

    const procName = alert?.["Process Name"] || alert?.ImageFileName || node?.label || pidTimeline[0]?.process_name || 'Unknown Process';
    const severity = alert?.severity || node?.severity || 'LOW';
    const score = alert?.correlation_score || node?.correlation_score || 0;
    
    return {
      procName,
      severity,
      score,
      explanation: alert?.explanation || 'No high severity context flagged by risk scoring.',
      pidTimeline,
      networkTargets,
      hasInjection
    };
  }, [selectedPID, alertsData, timelineData, graphData]);

  if (!selectedPID || !details) return null;

  const isHigh = details.severity === 'HIGH';
  const isMed = details.severity === 'MEDIUM';

  return (
    <div className={`flex flex-col bg-gray-950 text-gray-300 shadow-[20px_0_50px_rgba(0,0,0,0.5)] z-20 transition-all ${isFullScreen ? 'w-full h-full' : 'h-full border-l border-gray-800 w-80'}`}>
      <div className={`border-b border-gray-800 flex items-center justify-between bg-gray-900/50 ${isFullScreen ? 'p-8' : 'p-4'}`}>
        <h2 className={`${isFullScreen ? 'text-lg tracking-widest' : 'text-sm'} font-bold uppercase flex items-center gap-2`}>
          <Cpu className={isFullScreen ? "w-6 h-6 text-indigo-400" : "w-4 h-4 text-indigo-400"} />
          Process Intel {isFullScreen && <span className="text-gray-600 font-mono text-sm tracking-normal ml-2">[{selectedPID}]</span>}
        </h2>
        {!isFullScreen && (
          <button 
            onClick={() => { setSelectedPID(null); setSelectedNode(null); }}
            className="p-1 hover:bg-gray-800 rounded text-gray-500 hover:text-white transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        )}
      </div>

      <div className={`overflow-y-auto ${isFullScreen ? 'p-8 flex flex-col md:flex-row gap-12 flex-1' : 'flex-1 p-4 space-y-6'}`}>
        
        {/* Left Column (or entire column in drawer) */}
        <div className={`space-y-6 ${isFullScreen ? 'flex-1 border-r border-gray-800/50 pr-8' : ''}`}>
          {/* Core Profile */}
          <div>
            <div className="flex items-center gap-3 mb-2">
               <div className={`rounded-full shadow-[0_0_8px] ${(isHigh) ? 'bg-red-500 shadow-red-500/50 w-4 h-4' : isMed ? 'bg-orange-500 shadow-orange-500/50 w-3 h-3' : 'bg-gray-500 shadow-gray-500/50 w-3 h-3'}`}></div>
               <h3 className={`${isFullScreen ? 'text-3xl font-bold' : 'text-xl'} font-mono text-white tracking-tight`}>{details.procName}</h3>
            </div>
            <div className={`bg-gray-900 border border-gray-800 px-3 py-2 rounded grid grid-cols-2 gap-2 mt-4 ${isFullScreen ? 'text-sm p-4' : 'text-xs'}`}>
               <div className="flex flex-col">
                  <span className="text-gray-500 uppercase font-semibold">PID</span>
                  <span className="text-gray-200 font-mono text-lg">{selectedPID}</span>
               </div>
               <div className="flex flex-col">
                  <span className="text-gray-500 uppercase font-semibold">Threat Score</span>
                  <span className={`font-mono font-bold text-lg ${isHigh ? 'text-red-400' : isMed ? 'text-orange-400' : 'text-gray-400'}`}>{details.score}</span>
               </div>
            </div>
          </div>

          {/* Behavior Tags */}
          {(details.networkTargets?.length || details.hasInjection) ? (
            <div>
              <h4 className="text-xs font-semibold uppercase text-gray-500 mb-2 tracking-wider">Behavior Tags</h4>
              <div className="flex flex-wrap gap-2">
                 {details.networkTargets?.map((ip, i) => (
                   <div key={i} className={`flex items-center gap-1 bg-blue-900/20 text-blue-400 border border-blue-800/30 rounded ${isFullScreen ? 'px-3 py-1.5 text-sm font-semibold' : 'px-2 py-1 text-xs'}`}>
                      <Network className="w-4 h-4" />
                      {ip}
                   </div>
                 ))}
                 {details.hasInjection && (
                   <div className={`flex items-center gap-1 bg-purple-900/20 text-purple-400 border border-purple-800/30 rounded ${isFullScreen ? 'px-3 py-1.5 text-sm font-semibold' : 'px-2 py-1 text-xs'}`}>
                      <Activity className="w-4 h-4" />
                      Memory Injection
                   </div>
                 )}
              </div>
            </div>
          ) : null}

          {/* Narrative / Explanation */}
          <div>
              <h4 className="text-xs font-semibold uppercase text-gray-500 mb-2 flex items-center gap-2 tracking-wider"><BookOpen className="w-4 h-4"/> Contextual Intelligence</h4>
              
              <div className={`bg-gray-900 rounded border-l-4 border-indigo-500 p-4 leading-relaxed text-gray-300 flex flex-col gap-4 shadow-lg ${isFullScreen ? 'text-sm' : 'text-xs'}`}>
                 <div>
                    <span className="text-indigo-400 font-bold uppercase tracking-wider text-[10px] block mb-1">Initial Trigger</span>
                    <p>{details.explanation.includes('spawned') ? details.explanation.split(',')[0] : `${details.procName} instantiated securely or from an unknown system context.`}</p>
                 </div>
                 <div>
                    <span className="text-indigo-400 font-bold uppercase tracking-wider text-[10px] block mb-1">Execution Phase</span>
                    <p>PID {selectedPID} acquired runtime resources and began active memory execution vectors.</p>
                 </div>
                 {details.networkTargets && details.networkTargets.length > 0 && (
                    <div>
                       <span className="text-indigo-400 font-bold uppercase tracking-wider text-[10px] block mb-1">Network Activity</span>
                       <p>Initiated outgoing connections resolving to targets: {details.networkTargets.join(', ')}</p>
                    </div>
                 )}
                 {details.hasInjection && (
                    <div>
                       <span className="text-indigo-400 font-bold uppercase tracking-wider text-[10px] block mb-1">Persistence / Injection</span>
                       <p className="text-purple-400 font-semibold bg-purple-500/10 inline-block px-2 py-0.5 rounded">Exhibited critical memory injection indicators typical of living-off-the-land techniques.</p>
                    </div>
                 )}
              </div>
              
              <button className={`mt-4 w-full flex items-center justify-center gap-2 text-xs py-3 bg-indigo-500/10 hover:bg-indigo-500 shadow hover:shadow-indigo-500/50 text-indigo-400 hover:text-white rounded transition-all border border-indigo-500/30 uppercase tracking-widest font-bold`}>
                <ShieldAlert className="w-4 h-4" /> Machine Assessment Complete
              </button>
          </div>
        </div>

        {/* Right Column (or bottom in drawer) */}
        <div className={isFullScreen ? 'w-1/3 min-w-[300px]' : ''}>
          {details.pidTimeline.length > 0 ? (
            <>
               <h4 className="text-xs font-semibold uppercase text-gray-500 mb-4 tracking-wider">Process Chronology</h4>
               <div className="space-y-4 relative before:absolute before:inset-0 before:ml-[5px] before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-gradient-to-b before:from-transparent before:via-gray-700 before:to-transparent">
                  {details.pidTimeline.map((item, idx) => (
                    <div key={idx} className="relative flex items-center justify-between md:justify-normal md:odd:flex-row-reverse group is-active">
                       <div className="flex items-center justify-center w-3 h-3 rounded-full border border-gray-600 bg-gray-900 group-[.is-active]:bg-indigo-500 shadow-[0_0_8px_rgba(99,102,241,0.8)] shrink-0 z-10"></div>
                       <div className={`ml-3 text-xs bg-[#0B0F19] p-3 rounded-lg border shadow-lg w-[calc(100%-1.5rem)] ${isHigh ? 'border-red-900/50' : 'border-gray-800 hover:border-indigo-500/50 transition-colors'}`}>
                         <span className="block text-indigo-400 font-mono font-bold text-sm mb-1">{item.timestamp.split(' ')[1] || item.timestamp}</span>
                         <span className="text-gray-300 block font-semibold">{item.event_type}</span>
                         {item.description && <p className="text-gray-500 mt-2 leading-relaxed">{item.description}</p>}
                       </div>
                    </div>
                  ))}
               </div>
            </>
          ) : (
            <div className="flex flex-col items-center justify-center h-full text-gray-600 space-y-3 opacity-50">
               <Activity className="w-12 h-12" />
               <p className="text-sm font-mono">No sequence events traced</p>
            </div>
          )}
        </div>

      </div>
    </div>
  );
};
