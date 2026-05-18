import React from 'react';
import { useStore } from '../store/useStore';
import { ShieldAlert, Network, Clock, Activity, Shield, Filter, Crosshair, Settings } from 'lucide-react';
import { ClusterView } from './ClusterView';
import { ModeToggle } from './ModeToggle';

export const Sidebar: React.FC = () => {
  const { summary, filters, setFilters, activePage, setActivePage } = useStore();

  return (
    <div className="w-64 bg-sidebar-background border-r border-sidebar-border text-sidebar-foreground flex flex-col h-full overflow-y-auto">
      <div className="p-4 border-b border-sidebar-border flex items-center gap-2 relative group">
        <div className="absolute inset-0 bg-primary opacity-0 group-hover:opacity-10 rounded-lg transition-opacity pointer-events-none"></div>
        <Shield className="w-6 h-6 text-primary drop-shadow-[0_0_8px_rgba(var(--primary),0.5)]" />
        <h1 className="text-xl font-bold text-foreground tracking-widest uppercase text-sm">Wako</h1>
      </div>
      
      <div className="p-4 border-b border-sidebar-border space-y-4">
        {/* Global Filters */}
        <div>
           <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider flex items-center gap-1 mb-2">
              <Filter className="w-3 h-3" /> Filters
           </label>
           <div className="space-y-3">
              <label className="flex items-center justify-between cursor-pointer group">
                 <span className="text-sm group-hover:text-foreground transition-colors">Suspicious Only</span>
                 <input type="checkbox" className="sr-only peer" checked={filters.isSuspiciousOnly} onChange={() => setFilters({ isSuspiciousOnly: !filters.isSuspiciousOnly })} />
                 <div className="w-8 h-4 bg-muted peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-3 after:w-3 after:transition-all peer-checked:bg-primary relative"></div>
              </label>

              <label className="flex items-center justify-between cursor-pointer group">
                 <span className="text-sm group-hover:text-foreground transition-colors">Network Activity</span>
                 <input type="checkbox" className="sr-only peer" checked={filters.showNetworkOnly} onChange={() => setFilters({ showNetworkOnly: !filters.showNetworkOnly })} />
                 <div className="w-8 h-4 bg-muted peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-3 after:w-3 after:transition-all peer-checked:bg-blue-500 relative"></div>
              </label>

              <label className="flex items-center justify-between cursor-pointer group">
                 <span className="text-sm group-hover:text-foreground transition-colors">Memory Injection</span>
                 <input type="checkbox" className="sr-only peer" checked={filters.showInjectionOnly} onChange={() => setFilters({ showInjectionOnly: !filters.showInjectionOnly })} />
                 <div className="w-8 h-4 bg-muted peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-3 after:w-3 after:transition-all peer-checked:bg-purple-500 relative"></div>
              </label>
           </div>
        </div>
      </div>
      
      <nav className="flex-1 p-2 space-y-1">
        <div className="px-3 py-2 text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          Views
        </div>
         <button 
          onClick={() => setActivePage('GRAPH')} 
          className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors ${activePage === 'GRAPH' ? 'bg-primary/10 text-primary border border-primary/20' : 'hover:bg-muted hover:text-foreground'}`}
        >
          <Network className="w-4 h-4" />
          Attack Graph
        </button>
        <button 
          onClick={() => setActivePage('PROCESS_INTEL')} 
          className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors ${activePage === 'PROCESS_INTEL' ? 'bg-primary/10 text-primary border border-primary/20' : 'hover:bg-muted hover:text-foreground'}`}
        >
          <Activity className="w-4 h-4" />
          Process Intel
        </button>
        <button 
          onClick={() => setActivePage('TIMELINE')} 
          className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors ${activePage === 'TIMELINE' ? 'bg-primary/10 text-primary border border-primary/20' : 'hover:bg-muted hover:text-foreground'}`}
        >
          <Clock className="w-4 h-4" />
          Timeline
        </button>
        <button 
          onClick={() => setActivePage('ALERTS')} 
          className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors ${activePage === 'ALERTS' ? 'bg-primary/10 text-primary border border-primary/20' : 'hover:bg-muted hover:text-foreground'}`}
        >
          <ShieldAlert className="w-4 h-4" />
          Alerts
        </button>
        <button 
          onClick={() => setActivePage('HUNTING')} 
          className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors ${activePage === 'HUNTING' ? 'bg-primary/10 text-primary border border-primary/20' : 'hover:bg-muted hover:text-foreground'}`}
        >
          <Crosshair className="w-4 h-4" />
          Threat Hunting
        </button>
      </nav>

      {/* Dynamic Clusters View */}
      <div className="flex-1 overflow-y-auto">
        <ClusterView />
      </div>

      {/* Theme Toggle and Footer */}
      <div className="p-4 border-t border-sidebar-border mt-auto flex items-center justify-between">
        <div className="flex items-center gap-2 text-muted-foreground">
          <Settings className="w-4 h-4" />
          <span className="text-xs font-medium uppercase tracking-wider">Settings</span>
        </div>
        <ModeToggle />
      </div>
    </div>
  );
};
