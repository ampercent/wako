import React, { useMemo } from 'react';
import { useStore } from '../store/useStore';
import { Route, Crosshair, ArrowRight } from 'lucide-react';

export const AttackPathPanel: React.FC = () => {
  const { graphData, selectedPID, setHighlighted } = useStore();

  const attackPath = useMemo(() => {
    if (!selectedPID || !graphData) {
       setHighlighted(new Set(), new Set());
       return null;
    }

    const pathNodes: string[] = [];
    const pathEdges: string[] = [];
    
    // We trace back to the top-most parent.
    // Graph edges: source -> target. If type is parent_child, source is parent, target is child.
    let currentPID = `pid_${selectedPID}`;
    let parentFound = true;
    
    const lineage = [currentPID];
    
    // Trace upwards
    while(parentFound) {
       const parentEdge = graphData.edges.find(e => 
         (typeof e.target === 'object' ? (e.target as any).id : e.target) === currentPID && e.type === 'parent_child'
       );
       if (parentEdge) {
           currentPID = typeof parentEdge.source === 'object' ? (parentEdge.source as any).id : parentEdge.source;
           lineage.unshift(currentPID); // Add to front
       } else {
           parentFound = false;
       }
    }
    
    // Lineage now contains root -> child -> currentPID
    pathNodes.push(...lineage);
    
    // Now any outgoing edges for currentPID (network, injection)
    const behaviors = graphData.edges.filter(e => 
       (typeof e.source === 'object' ? (e.source as any).id : e.source) === `pid_${selectedPID}` && 
       (e.type === 'network_connection' || e.type === 'injection')
    );
    
    behaviors.forEach(b => {
        pathNodes.push(typeof b.target === 'object' ? (b.target as any).id : b.target);
    });

    // Translate to Node labels so we can render them
    const renderedPath = pathNodes.map(nodeId => {
       const n = graphData.nodes.find(node => node.id === nodeId);
       return n ? n.label : nodeId;
    });

    // Set highlighting state for Force Graph 
    setHighlighted(new Set(pathNodes), new Set()); // Need edge mapping but nodes is enough for basic focus
    
    return renderedPath;

  }, [selectedPID, graphData, setHighlighted]);

  if (!attackPath || attackPath.length <= 1) return null;

  return (
    <div className="absolute top-4 left-1/2 -translate-x-1/2 z-20 bg-gray-900/90 backdrop-blur border border-gray-700 p-3 rounded-lg shadow-2xl flex items-center gap-3">
      <div className="flex items-center gap-2 bg-indigo-500/20 px-2 py-1 rounded text-indigo-400 font-semibold text-xs tracking-wider border border-indigo-500/30">
         <Route className="w-3 h-3" /> ATTACK PATH RECONSTRUCTION
      </div>
      <div className="flex items-center gap-2">
         {attackPath.map((step, idx) => (
            <React.Fragment key={idx}>
               <span className={`text-sm font-mono ${idx === attackPath.length - 1 ? 'text-red-400 font-bold' : 'text-gray-300'}`}>
                 {step}
               </span>
               {idx < attackPath.length - 1 && <ArrowRight className="w-4 h-4 text-gray-600" />}
            </React.Fragment>
         ))}
      </div>
    </div>
  );
};
