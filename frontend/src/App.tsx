import React, { useEffect, useCallback } from 'react';
import { getGraph, getTimeline, getAlerts, getSummary } from './api/client';
import { useStore, InvStep, ClusterNode } from './store/useStore';
import { Sidebar } from './components/layout/Sidebar';
import { GraphView } from './components/graph/GraphView';
import { TimelinePanel } from './components/forensics/TimelinePanel';
import { AlertsPanel } from './components/forensics/AlertsPanel';
import { ProcessDetailsPanel } from './components/forensics/ProcessDetailsPanel';
import { InvestigationFlowPanel } from './components/forensics/InvestigationFlowPanel';
import { HuntingWorkspace } from './components/hunting/HuntingWorkspace';
import { Loader2, Shield } from 'lucide-react';

const App: React.FC = () => {
  const { 
    setGraphData, 
    setTimelineData, 
    setAlertsData, 
    setSummary, 
    isLoading, 
    setIsLoading, 
    error, 
    setError,
    selectedPID,
    setSelectedPID,
    setSelectedNode,
    setInvestigationSteps,
    setRootCause,
    setConfidenceScore,
    setClusters,
    setActivePage,
    activePage
  } = useStore();

  // Compute Machine Intel based on fetched arrays
  const computeIntelligence = (graphRes: any, alertsRes: any) => {
     let confScore = 0;
     const steps: InvStep[] = [];
     const clustersMap: Record<string, string[]> = {};
     let likelyRoot = "Unable to determine root cause.";

     // 1. Root Cause & Confidence
     if (alertsRes.length > 0) {
        // Find highest score alert
        const highest = [...alertsRes].sort((a,b) => b.correlation_score - a.correlation_score)[0];
        confScore = Math.min(Math.round((highest.correlation_score / 10) * 100), 99);
        
        // Find parent if possible
        const highestEdges = graphRes.edges.filter((e: any) => e.target === `pid_${highest.PID}` && e.type === "parent_child");
        if (highestEdges.length > 0) {
            const parentId = highestEdges[0].source;
            const parentNode = graphRes.nodes.find((n: any) => n.id === parentId);
            likelyRoot = `Likely Entry Point: ${parentNode?.label || 'Parent Process'} \u2192 ${highest["Process Name"] || highest.ImageFileName}`;
        } else {
            likelyRoot = `Primary Suspect: ${highest["Process Name"]}`;
        }

        // 2. Generate Steps
        steps.push({ id: '1', label: `Inspect ${highest["Process Name"] || highest.ImageFileName} (HIGH risk)`, actionPid: String(highest.PID), completed: false });
        
        const hasExternal = graphRes.edges.some((e: any) => e.source === `pid_${highest.PID}` && e.type === "network_connection");
        const hasInjection = graphRes.edges.some((e: any) => e.source === `pid_${highest.PID}` && e.type === "injection");
        
        if (highestEdges.length > 0) {
           steps.push({ id: '2', label: `Trace parent process lineage`, actionPid: highestEdges[0].source.replace('pid_',''), completed: false });
        }
        if (hasExternal) {
           steps.push({ id: '3', label: `Analyze external network connection mapping`, actionPid: String(highest.PID), completed: false });
        }
        if (hasInjection) {
           steps.push({ id: '4', label: `Confirm memory injection behavior`, actionPid: String(highest.PID), completed: false });
        }
     } else {
        steps.push({ id: '1', label: `Perform routine hunting on standard processes`, actionPid: null, completed: false });
        confScore = 12;
     }

     // 3. Risk Clustering
     graphRes.edges.forEach((edge: any) => {
        if (edge.type === 'network_connection') {
           const ip = edge.target.replace('ip_', '');
           if(!clustersMap[`Network to ${ip}`]) clustersMap[`Network to ${ip}`] = [];
           clustersMap[`Network to ${ip}`].push(edge.source);
        }
     });

     const clustersArray: ClusterNode[] = Object.keys(clustersMap).map(k => ({
        label: k,
        count: clustersMap[k].length,
        members: clustersMap[k]
     })).filter(c => c.count > 0);

     setRootCause(likelyRoot);
     setConfidenceScore(confScore);
     setInvestigationSteps(steps);
     setClusters(clustersArray);
  };

  useEffect(() => {
    const fetchData = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const [graphRes, timelineRes, alertsRes, summaryRes] = await Promise.all([
          getGraph(),
          getTimeline(),
          getAlerts(),
          getSummary()
        ]);
        
        setGraphData(graphRes);
        setTimelineData(timelineRes);
        setAlertsData(alertsRes);
        setSummary(summaryRes.summary);

        computeIntelligence(graphRes, alertsRes);

      } catch (err: any) {
        console.error("API Error:", err);
        setError("Telemetry Feed Offline. " + err.message);
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
  }, []);

  // Global Hotkeys
  const handleKeyDown = useCallback((e: KeyboardEvent) => {
     if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;

     if (e.key === 't' || e.key === 'T') {
        setActivePage('TIMELINE');
     } else if (e.key === 'a' || e.key === 'A') {
        setActivePage('ALERTS');
     } else if ((e.key === 'f' || e.key === 'F') && selectedPID) {
        // Quick focus
        setSelectedNode(`pid_${selectedPID}`);
     }
  }, [selectedPID, setActivePage, setSelectedNode]);

  useEffect(() => {
     window.addEventListener('keydown', handleKeyDown);
     return () => window.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);

  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center bg-background text-foreground flex-col gap-6">
        <div className="relative">
           <Shield className="w-16 h-16 text-primary absolute opacity-50 blur-[20px] animate-pulse" />
           <Shield className="w-16 h-16 text-primary relative z-10" />
        </div>
        <Loader2 className="w-8 h-8 text-primary animate-spin absolute z-20" />
        <p className="text-muted-foreground font-mono tracking-widest uppercase text-sm animate-pulse mt-4">Initializing Guided Workflow...</p>
      </div>
    );
  }

  // Dynamic Main Content
  let MainContent;
  if (activePage === 'GRAPH') {
     MainContent = (
      <div className="flex-1 flex flex-col h-full relative min-w-0">
        {/* RECOMMENDED INVESTIGATION FLOW */}
        <InvestigationFlowPanel />
        {/* GRAPH VIEW */}
        <div id="graph" className="flex-1 relative shadow-inner overflow-hidden">
          <GraphView />
        </div>
      </div>
     );
  } else if (activePage === 'PROCESS_INTEL') {
     if (!selectedPID) {
       MainContent = (
         <div className="flex-1 h-full flex flex-col items-center justify-center text-muted-foreground bg-background">
           <div className="relative mb-8">
              <Shield className="w-24 h-24 opacity-5 blur-xl absolute" />
              <Shield className="w-24 h-24 opacity-20 relative z-10" />
           </div>
           <p className="font-mono text-sm tracking-widest uppercase opacity-40 text-foreground">Intelligence Matrix Standby</p>
           <p className="mt-2 text-xs text-muted-foreground">Select a process node to initialize deep forensic analysis.</p>
         </div>
       );
     } else {
       MainContent = <ProcessDetailsPanel isFullScreen={true} />;
     }
  } else if (activePage === 'ALERTS') {
     MainContent = <AlertsPanel isFullScreen={true} />;
  } else if (activePage === 'TIMELINE') {
     MainContent = <TimelinePanel isFullScreen={true} />;
  } else if (activePage === 'HUNTING') {
     MainContent = <HuntingWorkspace />;
  }

  // Right Drawer logic (only overlays on graph view)
  let DrawerComponent = null;
  if (selectedPID && activePage === 'GRAPH') {
     DrawerComponent = <ProcessDetailsPanel />;
  }

  return (
    <div className="w-full flex h-screen bg-background font-sans text-foreground overflow-hidden selection:bg-primary/30">
      <Sidebar />
      <div className="flex-1 flex flex-col h-full relative min-w-0">
        <main className="flex-1 relative flex flex-col h-full overflow-hidden">
           {MainContent}
        </main>
      </div>
      
      {/* Dynamic Right Side Container (Drawer) */}
      {DrawerComponent && (
        <div id="right-panel" className="relative flex shrink-0 h-full shadow-[ -20px_0_40px_rgba(0,0,0,0.4)] animate-in slide-in-from-right duration-300">
            {DrawerComponent}
        </div>
      )}
    </div>
  );
};

export default App;
