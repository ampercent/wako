import pandas as pd
import numpy as np
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# Lightweight ML Model
try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn is not installed. Anomaly Detection will gracefully degrade.")

class AnomalyDetector:
    def __init__(self, contamination=0.05):
        """
        contamination: proportion of outliers in the data set
        """
        self.contamination = contamination
        if SKLEARN_AVAILABLE:
            self.model = IsolationForest(contamination=self.contamination, random_state=42)
        else:
            self.model = None

    def detect_anomalies(self, pslist_df: pd.DataFrame, netscan_df: pd.DataFrame = None) -> List[Dict[str, Any]]:
        """
        Runs Isolation Forest on thread counts, handles, and connection counts context.
        """
        if not SKLEARN_AVAILABLE:
            return [{"error": "scikit-learn not available. Please install it."}]
            
        if pslist_df is None or pslist_df.empty:
            return []

        # Feature Extraction
        features_df = pslist_df[['PID', 'ImageFileName']].copy()
        
        # 1. Threads and Handles (from pslist)
        features_df['Threads'] = pd.to_numeric(pslist_df.get('Threads', 0), errors='coerce').fillna(1)
        features_df['Handles'] = pd.to_numeric(pslist_df.get('Handles', 0), errors='coerce').fillna(1)
        
        # 2. Connection Counts Context (from netscan)
        conn_counts = {}
        if netscan_df is not None and not netscan_df.empty and 'PID' in netscan_df.columns:
            conn_counts = netscan_df['PID'].value_counts().to_dict()
            
        features_df['ConnectionCount'] = features_df['PID'].map(lambda p: conn_counts.get(p, 0))

        # Matrix for training
        X = features_df[['Threads', 'Handles', 'ConnectionCount']].values
        
        if len(X) < 10:
            logger.info("Not enough data points for IsolationForest, skipping.")
            return []

        # Fit & Predict (-1 is anomaly, 1 is normal)
        preds = self.model.fit_predict(X)
        scores = self.model.decision_function(X) # lower score -> more abnormal
        
        features_df['is_anomaly'] = preds == -1
        features_df['anomaly_score'] = scores # Continuous score

        # Isolate true anomalies
        anomalies = features_df[features_df['is_anomaly']].copy()
        
        results = []
        for _, row in anomalies.iterrows():
            results.append({
                "pid": row['PID'],
                "process": row['ImageFileName'],
                "threads": row['Threads'],
                "handles": row['Handles'],
                "connections": row['ConnectionCount'],
                "score": float(row['anomaly_score']),
                "reason": f"Statistical outlier based on {row['Threads']} threads, {row['Handles']} handles, {row['ConnectionCount']} conns"
            })
            
        return sorted(results, key=lambda x: x['score']) # Lowest (most anomalous) first
