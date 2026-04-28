import React from 'react';
import { useStore } from '../store/useStore';
import { ShieldAlert, Network, Clock, Activity, Search, Shield, Filter, Crosshair } from 'lucide-react';
import { ClusterView } from './ClusterView';

export const Sidebar: React.FC = () => {
  const { summary, filters, setFilters, searchQuery, setSearchQuery, activePage, setActivePage } = useStore();

  return (
    <div className="w-64 bg-gray-900 border-r border-gray-800 text-gray-300 flex flex-col h-full overflow-y-auto">
      <div className="p-4 border-b border-gray-800 flex items-center gap-2 relative group">
        <div className="absolute inset-0 bg-indigo-500 opacity-0 group-hover:opacity-10 rounded-lg transition-opacity pointer-events-none"></div>
        <Shield className="w-6 h-6 text-indigo-500 drop-shadow-[0_0_8px_rgba(99,102,241,0.5)]" />
        <h1 className="text-xl font-bold text-white tracking-widest uppercase text-sm">Wako</h1>
      </div>
      
      <div className="p-4 border-b border-gray-800 space-y-4">
        {/* Global Search */}
        <div>
           <label className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2 block">Global Search</label>
           <div className="relative">
             <Search className="w-4 h-4 absolute left-3 top-2.5 text-gray-500" />
             <input 
               type="text" 
               placeholder="PID, Process, IP..." 
               className="w-full bg-gray-950 border border-gray-800 rounded text-sm px-9 py-2 focus:outline-none focus:border-indigo-500 text-gray-200 transition-colors"
               value={searchQuery}
               onChange={(e) => setSearchQuery(e.target.value)}
             />
           </div>
        </div>

        {/* Global Filters */}
        <div>
           <label className="text-xs font-semibold text-gray-500 uppercase tracking-wider flex items-center gap-1 mb-2">
              <Filter className="w-3 h-3" /> Filters
           </label>
           <div className="space-y-3">
              <label className="flex items-center justify-between cursor-pointer group">
                 <span className="text-sm group-hover:text-white transition-colors">Suspicious Only</span>
                 <input type="checkbox" className="sr-only peer" checked={filters.isSuspiciousOnly} onChange={() => setFilters({ isSuspiciousOnly: !filters.isSuspiciousOnly })} />
                 <div className="w-8 h-4 bg-gray-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-3 after:w-3 after:transition-all peer-checked:bg-indigo-500 relative"></div>
              </label>

              <label className="flex items-center justify-between cursor-pointer group">
                 <span className="text-sm group-hover:text-white transition-colors">Network Activity</span>
                 <input type="checkbox" className="sr-only peer" checked={filters.showNetworkOnly} onChange={() => setFilters({ showNetworkOnly: !filters.showNetworkOnly })} />
                 <div className="w-8 h-4 bg-gray-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-3 after:w-3 after:transition-all peer-checked:bg-blue-500 relative"></div>
              </label>

              <label className="flex items-center justify-between cursor-pointer group">
                 <span className="text-sm group-hover:text-white transition-colors">Memory Injection</span>
                 <input type="checkbox" className="sr-only peer" checked={filters.showInjectionOnly} onChange={() => setFilters({ showInjectionOnly: !filters.showInjectionOnly })} />
                 <div className="w-8 h-4 bg-gray-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-3 after:w-3 after:transition-all peer-checked:bg-purple-500 relative"></div>
              </label>
           </div>
        </div>
      </div>
      
      <nav className="flex-1 p-2 space-y-1">
        <div className="px-3 py-2 text-xs font-semibold text-gray-500 uppercase tracking-wider">
          Views
        </div>
        <button 
          onClick={() => setActivePage('GRAPH')} 
          className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors ${activePage === 'GRAPH' ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20' : 'hover:bg-gray-800 hover:text-white'}`}
        >
          <Network className="w-4 h-4" />
          Attack Graph
        </button>
        <button 
          onClick={() => setActivePage('PROCESS_INTEL')} 
          className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors ${activePage === 'PROCESS_INTEL' ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20' : 'hover:bg-gray-800 hover:text-white'}`}
        >
          <Activity className="w-4 h-4" />
          Process Intel
        </button>
        <button 
          onClick={() => setActivePage('TIMELINE')} 
          className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors ${activePage === 'TIMELINE' ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20' : 'hover:bg-gray-800 hover:text-white'}`}
        >
          <Clock className="w-4 h-4" />
          Timeline
        </button>
        <button 
          onClick={() => setActivePage('ALERTS')} 
          className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors ${activePage === 'ALERTS' ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20' : 'hover:bg-gray-800 hover:text-white'}`}
        >
          <ShieldAlert className="w-4 h-4" />
          Alerts
        </button>
        <button 
          onClick={() => setActivePage('HUNTING')} 
          className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors ${activePage === 'HUNTING' ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20' : 'hover:bg-gray-800 hover:text-white'}`}
        >
          <Crosshair className="w-4 h-4" />
          Threat Hunting
        </button>
      </nav>

      {/* Dynamic Clusters View */}
      <ClusterView />
    </div>
  );
};
