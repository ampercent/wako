import React, { useEffect, useMemo, useRef } from 'react';
import { useStore } from '../store/useStore';
import { Clock, ShieldAlert, SkipBack, SkipForward, Play } from 'lucide-react';

export const TimelinePanel: React.FC<{ isFullScreen?: boolean }> = ({ isFullScreen = false }) => {
  const { timelineData, selectedPID, setSelectedPID, setSelectedNode, setPlaybackIndex, playbackIndex } = useStore();
  const eventRefs = useRef<Array<HTMLDivElement | null>>([]);

  const handleEventClick = (pid: string | number) => {
    setSelectedPID(String(pid));
    setSelectedNode(`pid_${pid}`);
  };

  useEffect(() => {
    if (playbackIndex === null || !timelineData[playbackIndex]) return;
    const event = timelineData[playbackIndex];
    setSelectedPID(String(event.pid));
    setSelectedNode(`pid_${event.pid}`);
    eventRefs.current[playbackIndex]?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }, [playbackIndex, timelineData, setSelectedPID, setSelectedNode]);

  const threatCount = useMemo(() => {
     return timelineData.filter(t => t.severity === 'HIGH' || t.severity === 'MEDIUM').length;
  }, [timelineData]);

  return (
    <div className={`flex flex-col h-full text-gray-300 w-full bg-[#0B0F19] overflow-hidden`}>
      <div className={`border-b border-gray-800 flex items-center justify-between shadow z-10 sticky top-0 bg-gray-900/90 backdrop-blur ${isFullScreen ? 'p-8' : 'p-4'}`}>
        <h2 className={`${isFullScreen ? 'text-2xl tracking-widest' : 'text-sm'} font-bold uppercase flex items-center gap-3`}>
          <Clock className={isFullScreen ? "w-8 h-8 text-indigo-500" : "w-4 h-4 text-indigo-500"} />
          Event Sequence
        </h2>
        <div className="flex items-center gap-3">
           <span className="text-xs text-gray-500 font-mono hidden md:block uppercase tracking-widest">Forensic Timeline</span>
           <span className="text-sm bg-indigo-500/10 border border-indigo-500/30 px-3 py-1.5 rounded text-indigo-400 font-mono font-bold">
             {threatCount} Detected Anomaly Events
           </span>
        </div>
      </div>
      
      {/* VCR Controls */}
      <div className="flex border-b border-gray-800 bg-gray-950/50 justify-center py-4 px-4 gap-12 shadow-inner">
         <button className="flex flex-col items-center gap-1 group" onClick={() => setPlaybackIndex(0)}>
            <SkipBack className="w-6 h-6 text-gray-600 group-hover:text-indigo-400 transition-colors" />
            <span className="text-[10px] uppercase font-bold text-gray-600 group-hover:text-indigo-500">Reset</span>
         </button>
         <button className="flex flex-col items-center gap-1 group bg-indigo-500/10 px-8 py-2 rounded-full border border-indigo-500/20 hover:bg-indigo-500/20 transition-all shadow-[0_0_20px_rgba(99,102,241,0.1)]" onClick={() => {}}>
            <Play className="w-6 h-6 text-indigo-500 group-hover:scale-110 transition-transform" />
            <span className="text-[10px] uppercase font-bold text-indigo-400">Initialize Replay</span>
         </button>
         <button className="flex flex-col items-center gap-1 group" onClick={() => setPlaybackIndex(null)}>
            <SkipForward className="w-6 h-6 text-gray-600 group-hover:text-indigo-400 transition-colors" />
            <span className="text-[10px] uppercase font-bold text-gray-600 group-hover:text-indigo-500">Forward</span>
         </button>
      </div>

      <div className={`flex-1 overflow-y-auto ${isFullScreen ? 'p-12 space-y-8 max-w-[1200px] mx-auto w-full' : 'p-4 space-y-4'}`}>
        {timelineData.map((event, idx) => {
          const isSelected = selectedPID === String(event.pid);
          const isPlaybackFocused = playbackIndex === idx;
          const isHigh = event.severity === 'HIGH';
          const isMed = event.severity === 'MEDIUM';

          return (
            <div 
              key={idx}
              ref={(node) => {
                eventRefs.current[idx] = node;
              }}
              onClick={() => handleEventClick(event.pid)}
              className={`relative pl-6 border-l-4 cursor-pointer transition-all duration-200 group
                ${isSelected || isPlaybackFocused ? 'border-indigo-500 ml-2 scale-[1.01]' : isHigh ? 'border-red-500 hover:border-red-400' : isMed ? 'border-orange-500 hover:border-orange-400' : 'border-gray-700 hover:border-gray-500'}
              `}
            >
              {(isSelected || isPlaybackFocused) && (
                <div className="absolute -left-[7px] top-1 w-3 h-3 rounded-full bg-indigo-500 shadow-[0_0_15px_rgba(99,102,241,1)] animate-pulse"></div>
              )}
              
              <div className={`text-xs font-mono mb-2 ${isSelected ? 'text-indigo-400 font-bold' : 'text-gray-500'}`}>
                {event.timestamp} | {event.event_type}
              </div>
              
              <div className={`bg-gray-950 rounded-xl border border-gray-800 group-hover:bg-[#0F172A] group-hover:border-indigo-500/30 transition-all shadow-lg ${isFullScreen ? 'p-6' : 'p-4'}`}>
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-4">
                    <span className={`${isFullScreen ? 'text-xl' : 'text-base'} font-bold tracking-tight ${isHigh ? 'text-red-400' : isMed ? 'text-orange-400' : 'text-gray-300'}`}>
                      {event.process_name}
                    </span>
                    <span className="text-xs bg-gray-900 border border-gray-800 px-3 py-1 rounded text-gray-500 font-mono font-bold">PID: {event.pid}</span>
                  </div>
                  
                  {event.is_suspicious && (
                    <div className="flex items-center gap-2 text-red-500 text-xs font-black uppercase bg-red-500/10 px-3 py-1.5 rounded-full border border-red-500/20 shadow-[0_0_10px_rgba(239,68,68,0.2)]">
                      <ShieldAlert className="w-4 h-4" />
                      Critical Anomaly Detected
                    </div>
                  )}
                </div>
                
                <p className={`text-gray-400 leading-relaxed ${isFullScreen ? 'text-base' : 'text-sm'}`}>
                  {event.description}
                </p>
              </div>
            </div>
          );
        })}

        {timelineData.length === 0 && (
          <div className="text-center text-gray-500 text-sm mt-10">
            No timeline events generated.
          </div>
        )}
      </div>
    </div>
  );
};
