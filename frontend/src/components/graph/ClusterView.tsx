import React from 'react';
import { useStore } from '../store/useStore';
import { Network, MousePointerClick } from 'lucide-react';

export const ClusterView: React.FC = () => {
  const { clusters, setSelectedNode, setSelectedPID } = useStore();

  if (clusters.length === 0) return null;

  return (
    <div className="mt-4 p-4 border-t border-border bg-card/50">
       <h3 className="text-[10px] uppercase font-bold text-muted-foreground tracking-wider mb-3">Grouped Network Clusters</h3>
       <div className="space-y-2">
         {clusters.map((c, idx) => (
            <div key={idx} className="bg-card border border-border p-2 rounded flex flex-col gap-1 overflow-hidden group">
               <div className="flex items-center gap-2 text-primary font-mono text-[10px] break-all">
                  <Network className="w-3 h-3 shrink-0" />
                  <span>{c.label}</span>
               </div>
               <div className="text-[10px] text-muted-foreground mt-1 flex justify-between items-center">
                  <span>{c.count} Linked Process{c.count > 1 ? 'es' : ''}</span>
                  <button 
                     className="bg-primary/20 text-primary hover:bg-primary hover:text-primary-foreground px-2 py-0.5 rounded transition-colors hidden group-hover:block"
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
