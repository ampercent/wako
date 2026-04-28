import pandas as pd
from typing import List, Dict, Any

class PatternDetector:
    """ Computes cross-case heuristics for hunting pipelines """

    def __init__(self, query_engine):
        self.query_engine = query_engine

    def _get_full_corpus(self) -> pd.DataFrame:
        # Hack to extract everything via QueryEngine mapping logic
        # by passing an AST that returns True for everything.
        # However, to be cleaner, we access query_engine's loading block
        results = self.query_engine.execute("process_name != '!!INVALID!!'")
        if not results:
            return pd.DataFrame()
        return pd.DataFrame(results)

    def find_repeated_processes(self) -> List[Dict[str, Any]]:
        """ Flags process names spawning identically across multiple distinct hosts """
        df = self._get_full_corpus()
        if df.empty or "process_name" not in df.columns or "source" not in df.columns:
            return []
            
        # Group by proc name, count unique sources (hosts)
        grouped = df.dropna(subset=['process_name', 'source']).groupby('process_name')['source'].nunique()
        # Find procs appearing on > 1 host
        multi_host = grouped[grouped > 1].reset_index()
        multi_host.columns = ['process_name', 'host_count']
        
        return multi_host.to_dict('records')

    def detect_rare_processes(self) -> List[Dict[str, Any]]:
        """ Flags extreme long-tail processes (occurring only once globally) """
        df = self._get_full_corpus()
        if df.empty or "process_name" not in df.columns:
            return []
            
        counts = df['process_name'].value_counts()
        rare = counts[counts == 1].reset_index()
        rare.columns = ['process_name', 'global_occurrences']
        
        return rare.to_dict('records')

    def get_hunting_stats(self) -> Dict[str, Any]:
        """ Aggregate insights block for global case topology """
        df = self._get_full_corpus()
        if df.empty:
            return {
                "total_events": 0,
                "active_hosts": 0,
                "most_common_processes": [],
                "high_severity_count": 0
            }
            
        stats = {}
        stats["total_events"] = len(df)
        
        if "source" in df.columns:
            stats["active_hosts"] = int(df["source"].nunique())
            
        if "process_name" in df.columns:
            stats["most_common_processes"] = df["process_name"].value_counts().head(5).to_dict()
            
        if "severity" in df.columns:
            stats["high_severity_count"] = int(df["severity"].astype(str).str.upper().isin(["HIGH", "CRITICAL"]).sum())
            
        return stats
