import { create } from 'zustand';
import { GraphData, TimelineEvent, Alert } from '../api/client';
import type { HuntResultItem, SavedHuntQuery, HuntStatsResponse } from '../api/client';

export type FilterConfig = {
  isSuspiciousOnly: boolean;
  showNetworkOnly: boolean;
  showInjectionOnly: boolean;
};

export interface InvStep {
  id: string;
  label: string;
  actionPid: string | null;
  completed: boolean;
}

export interface ClusterNode {
  label: string;
  count: number;
  members: string[];
}

interface AppState {
  graphData: GraphData | null;
  timelineData: TimelineEvent[];
  alertsData: Alert[];
  summary: string;
  
  // Investigation Logic
  investigationSteps: InvStep[];
  rootCause: string | null;
  confidenceScore: number;
  clusters: ClusterNode[];
  
  selectedNode: string | null;
  selectedPID: string | null;
  selectedCaseId: string | number | null;
  hoveredNode: string | null;
  
  highlightedNodes: Set<string>;
  highlightedEdges: Set<string>;
  
  searchQuery: string;
  filters: FilterConfig;
  
  playbackIndex: number | null;
  replayPathSequence: string[];
  
  // UI States
  activePage: 'GRAPH' | 'PROCESS_INTEL' | 'ALERTS' | 'TIMELINE' | 'HUNTING';
  isLoading: boolean;
  error: string | null;
  
  // Threat Hunting State
  huntingQuery: string;
  huntingResults: HuntResultItem[];
  savedQueries: SavedHuntQuery[];
  huntingStats: HuntStatsResponse | null;
  isLiveHunt: boolean;

  setGraphData: (data: GraphData) => void;
  setTimelineData: (data: TimelineEvent[]) => void;
  setAlertsData: (data: Alert[]) => void;
  setSummary: (summary: string) => void;
  
  setInvestigationSteps: (steps: InvStep[]) => void;
  completeStep: (id: string) => void;
  setRootCause: (cause: string | null) => void;
  setConfidenceScore: (score: number) => void;
  setClusters: (clusters: ClusterNode[]) => void;
  
  setSelectedNode: (nodeId: string | null) => void;
  setSelectedPID: (pid: string | null) => void;
  setSelectedCaseId: (caseId: string | number | null) => void;
  setHoveredNode: (nodeId: string | null) => void;
  
  setHighlighted: (nodes: Set<string>, edges: Set<string>) => void;
  
  setSearchQuery: (query: string) => void;
  setFilters: (filters: Partial<FilterConfig>) => void;
  
  setPlaybackIndex: (index: number | null | ((prev: number | null) => number | null)) => void;
  setReplayPathSequence: (seq: string[]) => void;
  
  setActivePage: (page: 'GRAPH' | 'PROCESS_INTEL' | 'ALERTS' | 'TIMELINE' | 'HUNTING') => void;
  
  setIsLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  
  // Hunting setters
  setHuntingQuery: (query: string) => void;
  setHuntingResults: (results: HuntResultItem[]) => void;
  setSavedQueries: (queries: SavedHuntQuery[]) => void;
  setHuntingStats: (stats: HuntStatsResponse | null) => void;
  setIsLiveHunt: (isLive: boolean) => void;
}

const initialFilters: FilterConfig = {
  isSuspiciousOnly: false,
  showNetworkOnly: false,
  showInjectionOnly: false,
};

export const useStore = create<AppState>((set) => ({
  graphData: null,
  timelineData: [],
  alertsData: [],
  summary: '',
  
  investigationSteps: [],
  rootCause: null,
  confidenceScore: 0,
  clusters: [],
  
  selectedNode: null,
  selectedPID: null,
  selectedCaseId: null,
  hoveredNode: null,
  
  highlightedNodes: new Set(),
  highlightedEdges: new Set(),
  
  searchQuery: '',
  filters: initialFilters,
  
  playbackIndex: null,
  replayPathSequence: [],
  
  activePage: 'GRAPH',
  isLoading: false,
  error: null,
  
  huntingQuery: '',
  huntingResults: [],
  savedQueries: [],
  huntingStats: null,
  isLiveHunt: false,
  
  setGraphData: (data) => set({ graphData: data }),
  setTimelineData: (data) => set({ timelineData: data }),
  setAlertsData: (data) => set({ alertsData: data }),
  setSummary: (summary) => set({ summary }),
  
  setInvestigationSteps: (steps) => set({ investigationSteps: steps }),
  completeStep: (id) => set((state) => ({
    investigationSteps: state.investigationSteps.map(s => s.id === id ? { ...s, completed: true } : s)
  })),
  setRootCause: (cause) => set({ rootCause: cause }),
  setConfidenceScore: (score) => set({ confidenceScore: score }),
  setClusters: (clusters) => set({ clusters }),
  
  setSelectedNode: (nodeId) => set({ selectedNode: nodeId, activePage: 'PROCESS_INTEL' }),
  setSelectedPID: (pid) => set({ selectedPID: pid }),
  setSelectedCaseId: (caseId) => set({ selectedCaseId: caseId }),
  setHoveredNode: (nodeId) => set({ hoveredNode: nodeId }),
  
  setHighlighted: (nodes, edges) => set({ highlightedNodes: nodes, highlightedEdges: edges }),
  
  setSearchQuery: (query) => set({ searchQuery: query }),
  setFilters: (updates) => set((state) => ({ ...state, filters: { ...state.filters, ...updates } })),
  
  setPlaybackIndex: (index) => set((state) => ({
    playbackIndex: typeof index === 'function' ? index(state.playbackIndex) : index,
  })),
  setReplayPathSequence: (seq) => set({ replayPathSequence: seq }),
  
  setActivePage: (page) => set({ activePage: page }),
  
  setIsLoading: (loading) => set({ isLoading: loading }),
  setError: (error) => set({ error }),
  
  setHuntingQuery: (query) => set({ huntingQuery: query }),
  setHuntingResults: (results) => set({ huntingResults: results }),
  setSavedQueries: (queries) => set({ savedQueries: queries }),
  setHuntingStats: (stats) => set({ huntingStats: stats }),
  setIsLiveHunt: (isLive) => set({ isLiveHunt: isLive }),
}));
