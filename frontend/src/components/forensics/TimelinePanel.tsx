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
    <div className={`flex flex-col h-full text-foreground w-full bg-background overflow-hidden`}>
      <div className={`border-b border-border flex items-center justify-between shadow z-10 sticky top-0 bg-background/90 backdrop-blur ${isFullScreen ? 'p-8' : 'p-4'}`}>
        <h2 className={`${isFullScreen ? 'text-2xl tracking-widest' : 'text-sm'} font-bold uppercase flex items-center gap-3`}>
          <Clock className={isFullScreen ? "w-8 h-8 text-primary" : "w-4 h-4 text-primary"} />
          Event Sequence
        </h2>
        <div className="flex items-center gap-3">
           <span className="text-xs text-muted-foreground font-mono hidden md:block uppercase tracking-widest">Forensic Timeline</span>
           <span className="text-sm bg-primary/10 border border-primary/30 px-3 py-1.5 rounded text-primary font-mono font-bold">
             {threatCount} Detected Anomaly Events
           </span>
        </div>
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
                ${isSelected || isPlaybackFocused ? 'border-primary ml-2 scale-[1.01]' : isHigh ? 'border-destructive hover:border-destructive/80' : isMed ? 'border-warning hover:border-warning/80' : 'border-border hover:border-muted-foreground'}
              `}
            >
              {(isSelected || isPlaybackFocused) && (
                <div className="absolute -left-[7px] top-1 w-3 h-3 rounded-full bg-primary shadow-[0_0_15px_hsl(var(--primary))] animate-pulse"></div>
              )}
              
              <div className={`text-xs font-mono mb-2 ${isSelected ? 'text-primary font-bold' : 'text-muted-foreground'}`}>
                {event.timestamp} | {event.event_type}
              </div>
              
              <div className={`bg-card rounded-xl border border-border group-hover:bg-muted group-hover:border-primary/30 transition-all shadow-lg ${isFullScreen ? 'p-6' : 'p-4'}`}>
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-4">
                    <span className={`${isFullScreen ? 'text-xl' : 'text-base'} font-bold tracking-tight ${isHigh ? 'text-destructive' : isMed ? 'text-warning' : 'text-foreground'}`}>
                      {event.process_name}
                    </span>
                    <span className="text-xs bg-muted border border-border px-3 py-1 rounded text-muted-foreground font-mono font-bold">PID: {event.pid}</span>
                  </div>
                  
                  {event.is_suspicious && (
                    <div className="flex items-center gap-2 text-destructive text-xs font-black uppercase bg-destructive/10 px-3 py-1.5 rounded-full border border-destructive/20 shadow-[0_0_10px_hsl(var(--destructive)/0.2)]">
                      <ShieldAlert className="w-4 h-4" />
                      Critical Anomaly Detected
                    </div>
                  )}
                </div>
                
                <p className={`text-muted-foreground leading-relaxed ${isFullScreen ? 'text-base' : 'text-sm'}`}>
                  {event.description}
                </p>
              </div>
            </div>
          );
        })}

        {timelineData.length === 0 && (
          <div className="text-center text-muted-foreground text-sm mt-10">
            No timeline events generated.
          </div>
        )}
      </div>
    </div>
  );
};
