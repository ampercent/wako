
import sqlite3
import shutil
import tempfile
import os
from pathlib import Path
from datetime import datetime, timedelta

def get_chrome_history():
    """Reads Chrome history from the default profile."""
    # Path to History file
    # First priority: Evidence folder (User provided)
    evidence_history = Path("C:/Major_Project/Evidence/History")
    if evidence_history.exists():
        history_path = evidence_history
    else:
        # Fallback: Default Edge Profile (User Requested)
        history_path = Path.home() / "AppData/Local/Microsoft/Edge/User Data/Default/History"
    
    if not history_path.exists():
        return [{"url": "No Edge History Found", "title": "Place 'History' file in C:/Major_Project/Evidence/", "time": str(datetime.now())}]

    # Copy to temp file to avoid locking issues if browser is open
    temp_dir = tempfile.gettempdir()
    temp_path = os.path.join(temp_dir, "Edge_History_Copy")
    
    try:
        shutil.copy2(history_path, temp_path)
    except PermissionError:
        return [{"url": "Error: Browser Locked", "title": "Close Browser to Scan Disk", "time": str(datetime.now())}]

    # Query
    try:
        conn = sqlite3.connect(temp_path)
        cursor = conn.cursor()
        
        # Chrome stores time as microseconds since 1601. Conversion needed.
        query = """
        SELECT url, title, last_visit_time 
        FROM urls 
        ORDER BY last_visit_time DESC 
        LIMIT 100
        """
        
        cursor.execute(query)
        rows = cursor.fetchall()
        
        results = []
        for url, title, micro in rows:
            # Convert Chrome timestamp
            seconds = micro / 1000000
            timestamp = datetime(1601, 1, 1) + timedelta(seconds=seconds)
            
            results.append({
                "source": "Disk (Chrome)",
                "url": url,
                "title": title,
                "time": timestamp.isoformat(),
                "type": "standard"
            })
            
        conn.close()
        return results
    except Exception as e:
        return [{"url": "Error", "title": str(e), "time": str(datetime.now())}]
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
