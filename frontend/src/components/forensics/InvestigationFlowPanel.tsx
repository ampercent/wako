import React from 'react';
import { useStore } from '../store/useStore';
import { Target, CheckCircle2, Circle, AlertTriangle, ArrowRight, ShieldCheck } from 'lucide-react';

export const InvestigationFlowPanel: React.FC = () => {
  const { investigationSteps, completeStep, setSelectedPID, setSelectedNode, rootCause, confidenceScore } = useStore();

  if (investigationSteps.length === 0) return null;

  return (
    <div className="bg-background/80 backdrop-blur-md border-b border-border p-4 shadow-md z-10 flex flex-col items-center justify-center w-full shrink-0">
      
      {/* Root Cause & Confidence Deck */}
      <div className="w-full max-w-4xl flex flex-col md:flex-row gap-4">
          <div className="bg-card border border-border rounded p-4 flex-1 flex flex-col justify-center min-h-[100px]">
             <h3 className="text-[10px] uppercase font-bold text-muted-foreground tracking-wider flex items-center gap-1.5 mb-2">
                <AlertTriangle className="w-3 h-3 text-orange-400" /> Root Cause Analysis
             </h3>
             <div className="bg-orange-500/10 border border-orange-500/20 px-4 py-3 rounded text-sm font-mono text-orange-400 break-words leading-relaxed text-center">
                {rootCause || "Computing..."}
             </div>
          </div>
          
          <div className="bg-card border border-border rounded p-4 flex-1 flex flex-col justify-center min-h-[100px]">
             <h3 className="text-[10px] uppercase font-bold text-muted-foreground tracking-wider flex items-center gap-1.5 mb-3">
                <ShieldCheck className="w-3 h-3 text-primary" /> Investigation Confidence
             </h3>
             <div className="flex items-center justify-between px-2">
                <span className="text-xs text-muted-foreground">Likelihood of Infection</span>
                <span className={`text-3xl font-mono font-bold ${confidenceScore > 75 ? 'text-red-400' : confidenceScore > 40 ? 'text-orange-400' : 'text-emerald-400'}`}>
                   {confidenceScore}%
                </span>
             </div>
             {/* Simple visual progress bar */}
             <div className="mt-4 w-full h-1.5 bg-muted rounded-full overflow-hidden">
                <div 
                  className={`h-full transition-all duration-1000 ${confidenceScore > 75 ? 'bg-destructive' : confidenceScore > 40 ? 'bg-warning' : 'bg-emerald-500'}`}
                  style={{ width: `${confidenceScore}%` }}
                />
             </div>
          </div>
      </div>

    </div>
  );
};
