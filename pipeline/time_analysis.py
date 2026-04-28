import pandas as pd
from typing import Dict, List, Any

class TimeBehaviorAnalyzer:
    def __init__(self, time_window_seconds: int = 5):
        self.window = pd.Timedelta(seconds=time_window_seconds)

    def detect_bursts(self, timeline_df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Scans a chronologically sorted timeline for rapid bursts of events.
        """
        bursts = []
        if timeline_df is None or timeline_df.empty or 'timestamp' not in timeline_df.columns:
            return bursts

        # Ensure datetime and drop rows without valid timestamps
        df = timeline_df.copy()
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        valid_df = df.dropna(subset=['timestamp']).sort_values('timestamp')

        if valid_df.empty:
            return bursts

        # Find Process Spawning Bursts
        process_events = valid_df[valid_df['event_type'] == 'process_start']
        if not process_events.empty:
            # We can use a rolling window to count
            process_events = process_events.set_index('timestamp')
            # Count events in the rolling 5-second window
            counts = process_events.rolling(self.window).count()['event_type']
            peak_time = counts.idxmax()
            peak_val = counts.max()
            
            if peak_val >= 5: # Threshold: 5 processes in 5 seconds
                bursts.append({
                    "burst_type": "Rapid Process Spawning",
                    "peak_time": str(peak_time),
                    "count": peak_val,
                    "description": f"Detected a burst of {int(peak_val)} process starts within {self.window.seconds} seconds around {peak_time}."
                })

        # Find Network Spikes
        net_events = valid_df[valid_df['event_type'] == 'network_connect']
        if not net_events.empty:
            net_events = net_events.set_index('timestamp')
            counts = net_events.rolling(self.window).count()['event_type']
            peak_time = counts.idxmax()
            peak_val = counts.max()
            
            if peak_val >= 10: # Threshold: 10 connections in 5 seconds
                bursts.append({
                    "burst_type": "Sudden Network Spike",
                    "peak_time": str(peak_time),
                    "count": peak_val,
                    "description": f"Detected a spike of {int(peak_val)} network connections within {self.window.seconds} seconds around {peak_time}."
                })

        return bursts
