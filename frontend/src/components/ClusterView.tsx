import React from 'react';
import { useStore } from '../store/useStore';
import { Network, MousePointerClick } from 'lucide-react';

export const ClusterView: React.FC = () => {
  const { clusters, setSelectedNode, setSelectedPID } = useStore();

  if (clusters.length === 0) return null;

  return (
    <div className="mt-4 p-4 border-t border-gray-800 bg-gray-900/50">
       <h3 className="text-[10px] uppercase font-bold text-gray-500 tracking-wider mb-3">Grouped Network Clusters</h3>
       <div className="space-y-2">
         {clusters.map((c, idx) => (
            <div key={idx} className="bg-gray-950 border border-gray-800 p-2 rounded flex flex-col gap-1 overflow-hidden group">
               <div className="flex items-center gap-2 text-indigo-400 font-mono text-[10px] break-all">
                  <Network className="w-3 h-3 shrink-0" />
                  <span>{c.label}</span>
               </div>
               <div className="text-[10px] text-gray-500 mt-1 flex justify-between items-center">
                  <span>{c.count} Linked Process{c.count > 1 ? 'es' : ''}</span>
                  <button 
                     className="bg-indigo-500/20 text-indigo-400 hover:bg-indigo-500 hover:text-white px-2 py-0.5 rounded transition-colors hidden group-hover:block"
                     onClick={() => {
                        // Focus the first member of this cluster
                        if (c.members.length > 0) {
                           setSelectedNode(c.members[0]);
                           setSelectedPID(c.members[0].replace('pid_', ''));
                        }
                     }}
                  >
                     Trace
                  </button>
               </div>
            </div>
         ))}
       </div>
    </div>
  );
};
