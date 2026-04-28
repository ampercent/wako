import React, { useEffect, useState } from 'react';
import { useStore } from '../store/useStore';
import { Play, Pause, Square, FastForward, Rewind } from 'lucide-react';

export const PathReplayController: React.FC = () => {
  const { timelineData, playbackIndex, setPlaybackIndex, setSelectedPID, setSelectedNode } = useStore();
  const [isPlaying, setIsPlaying] = useState(false);

  // Replay Logic Engine
  useEffect(() => {
    let interval: ReturnType<typeof setTimeout>;

    if (isPlaying) {
       interval = setInterval(() => {
          setPlaybackIndex(prev => {
             const nextIdx = prev !== null ? prev + 1 : 0;
             if (nextIdx >= timelineData.length) {
                setIsPlaying(false);
                return null;
             }
             return nextIdx;
          });
       }, 2000); // Step every 2 seconds
    }
    
    return () => clearInterval(interval);
  }, [isPlaying, timelineData.length, setPlaybackIndex]);

  // Sync Graph Focus
  useEffect(() => {
     if (playbackIndex !== null && timelineData[playbackIndex]) {
        const event = timelineData[playbackIndex];
        setSelectedPID(String(event.pid));
        setSelectedNode(`pid_${event.pid}`);
     }
  }, [playbackIndex, timelineData, setSelectedPID, setSelectedNode]);

  if (timelineData.length === 0) return null;

  return (
    <div className="absolute bottom-6 left-1/2 -translate-x-1/2 z-20 bg-[#0B0F19] border border-gray-700 p-2 rounded-full shadow-[0_10px_30px_rgba(0,0,0,0.8)] flex items-center gap-2">
       <span className="text-[10px] uppercase font-bold text-gray-500 tracking-wider ml-3 mr-2 bg-gray-900 border border-gray-800 px-2 py-1 rounded-full">Path Replay</span>
       
       <button 
          onClick={() => {
             setPlaybackIndex(prev => prev !== null && prev > 0 ? prev - 1 : 0);
             setIsPlaying(false);
          }} 
          className="p-2 hover:bg-gray-800 rounded-full transition-colors group"
       >
          <Rewind className="w-4 h-4 text-gray-400 group-hover:text-indigo-400" />
       </button>
       
       <button 
          onClick={() => setIsPlaying(!isPlaying)} 
          className="p-2.5 bg-indigo-500 hover:bg-indigo-600 shadow-[0_0_15px_rgba(99,102,241,0.5)] rounded-full transition-all group"
       >
          {isPlaying ? <Pause className="w-5 h-5 text-white" /> : <Play className="w-5 h-5 text-white ml-0.5" />}
       </button>

       <button 
          onClick={() => {
             setPlaybackIndex(prev => prev !== null && prev < timelineData.length - 1 ? prev + 1 : prev);
             setIsPlaying(false);
          }} 
          className="p-2 hover:bg-gray-800 rounded-full transition-colors group"
       >
          <FastForward className="w-4 h-4 text-gray-400 group-hover:text-indigo-400" />
       </button>
       
       <button 
          onClick={() => {
             setIsPlaying(false);
             setPlaybackIndex(null);
          }} 
          className="p-2 hover:bg-red-500/20 rounded-full transition-colors group ml-2 mr-1"
          title="Stop Replay"
       >
          <Square className="w-4 h-4 text-gray-500 group-hover:text-red-400" />
       </button>
       
       {/* Timeline Tracking Dots */}
       <div className="flex gap-1 bg-gray-900 px-3 py-2 rounded-full border border-gray-800 mr-1">
          {timelineData.map((_, i) => (
             <div 
                key={i} 
                className={`w-1.5 h-1.5 rounded-full transition-all ${playbackIndex === i ? 'bg-indigo-400 scale-150 shadow-[0_0_5px_rgba(99,102,241,0.8)]' : playbackIndex !== null && i < playbackIndex ? 'bg-gray-500' : 'bg-gray-800'}`} 
             />
          ))}
       </div>
    </div>
  );
};
