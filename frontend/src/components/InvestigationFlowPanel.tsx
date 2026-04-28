import React from 'react';
import { useStore } from '../store/useStore';
import { Target, CheckCircle2, Circle, AlertTriangle, ArrowRight, ShieldCheck } from 'lucide-react';

export const InvestigationFlowPanel: React.FC = () => {
  const { investigationSteps, completeStep, setSelectedPID, setSelectedNode, rootCause, confidenceScore } = useStore();

  if (investigationSteps.length === 0) return null;

  return (
    <div className="bg-gray-900/80 border-b border-gray-800 p-4 shadow-md z-10 flex flex-col xl:flex-row gap-6 w-full shrink-0">
      
      {/* Recommended Steps Panel */}
      <div className="flex-1 min-w-0">
         <div className="flex items-center gap-2 mb-3">
           <Target className="w-4 h-4 text-emerald-400" />
           <h2 className="text-xs font-bold uppercase tracking-widest text-emerald-100 truncate">Recommended Investigation Flow</h2>
         </div>
         <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            {investigationSteps.map((step, idx) => (
              <div 
                key={step.id} 
                className={`bg-[#0B0F19] border ${step.completed ? 'border-emerald-500/30 opacity-60' : 'border-gray-700 hover:border-gray-500'} rounded p-3 flex flex-col justify-between cursor-pointer transition-all group`}
                onClick={() => {
                   if (step.actionPid) {
                      setSelectedPID(step.actionPid);
                      setSelectedNode(`pid_${step.actionPid}`);
                   }
                }}
              >
                 <div className="flex gap-2">
                    <span className="text-gray-500 font-mono font-bold text-xs">{idx + 1}.</span>
                    <span className={`text-xs ${step.completed ? 'text-gray-500 line-through' : 'text-gray-300'} leading-relaxed group-hover:text-white transition-colors`}>{step.label}</span>
                 </div>
                 <div className="mt-3 flex items-center justify-between">
                    {step.actionPid ? (
                       <span className="bg-gray-800 text-[10px] px-1.5 py-0.5 rounded text-gray-400 border border-gray-700 group-hover:border-indigo-500/50">Focus</span>
                    ) : <span></span>}
                    <button 
                       className="p-1 rounded hover:bg-gray-800 transition-colors"
                       onClick={(e) => { e.stopPropagation(); completeStep(step.id); }}
                    >
                       {step.completed ? <CheckCircle2 className="w-4 h-4 text-emerald-500" /> : <Circle className="w-4 h-4 text-gray-600 group-hover:text-emerald-400" />}
                    </button>
                 </div>
              </div>
            ))}
         </div>
      </div>

      {/* Root Cause & Confidence Deck */}
      <div className="w-full xl:w-1/3 flex flex-col gap-3 shrink-0">
          <div className="bg-[#0B0F19] border border-gray-800 rounded p-3 flex-1 flex flex-col justify-center">
             <h3 className="text-[10px] uppercase font-bold text-gray-500 tracking-wider flex items-center gap-1.5 mb-2">
                <AlertTriangle className="w-3 h-3 text-orange-400" /> Root Cause Analysis
             </h3>
             <div className="bg-orange-500/10 border border-orange-500/20 px-3 py-2 rounded text-xs font-mono text-orange-400 break-words leading-relaxed">
                {rootCause || "Computing..."}
             </div>
          </div>
          
          <div className="bg-[#0B0F19] border border-gray-800 rounded p-3 flex items-center justify-between">
             <h3 className="text-[10px] uppercase font-bold text-gray-500 tracking-wider flex items-center gap-1.5">
                <ShieldCheck className="w-3 h-3 text-indigo-400" /> Investigation Confidence
             </h3>
             <div className="flex items-center gap-3">
                <span className="text-xs text-gray-400">Likelihood of Infection</span>
                <span className={`text-xl font-mono font-bold ${confidenceScore > 75 ? 'text-red-400' : confidenceScore > 40 ? 'text-orange-400' : 'text-emerald-400'}`}>
                   {confidenceScore}%
                </span>
             </div>
          </div>
      </div>

    </div>
  );
};
