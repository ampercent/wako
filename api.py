
from fastapi import FastAPI, HTTPException, Body, Depends
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional
from pydantic import BaseModel
import logging

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
from pathlib import Path
import pandas as pd
import json

# Import Engine & Monitor
from pipeline.engine import ForensicsEngine
from pipeline.browser_monitor import get_chrome_history
from pipeline.correlation import correlate_artifacts, explain_process, export_graph_json
from pipeline.risk_scoring import enrich_with_explanations, generate_alerts, explain_summary
from pipeline.timeline import build_timeline, summarize_timeline
from pipeline.decision_engine import (
    generate_investigation_plan,
    detect_root_cause,
    reconstruct_attack_chain,
    compute_confidence,
    generate_attack_summary,
)

# --- Advanced Forensics Modules ---
from case_management.manager import CaseManager
from core.security import get_current_user, get_password_hash, verify_password, create_access_token

class UserAuth(BaseModel):
    username: str
    password: str
    role: str = "analyst"
from reporting.engine import ReportGenerator
from ioc_extraction.extractor import IOCExtractor
from intel_enrichment.provider import ThreatIntelProvider
from diff_analysis.analyzer import DiffAnalyzer
from pipeline.behavior_signatures import BehaviorSignatureEngine
from pipeline.process_tree import build_process_tree
from pipeline.anomaly_detector import AnomalyDetector
from pipeline.time_analysis import TimeBehaviorAnalyzer
from playbooks.engine import PlaybookEngine
from core.actions.engine import ActionEngine
from core.actions.actions import BlockIPAction, TerminateProcessAction, ExportEvidenceAction, TagMaliciousAction
from core.actions.recommender import recommend_actions
from core.rules.engine import DetectionEngine
from core.ingestion.service import IngestionService

# --- Production Hardening Modules ---
from core.jobs import JobManager, JobStatus, AnalyzeRequest, MultiAnalyzeRequest
from core.jobs.worker import JobWorker
from core.storage import CacheManager
from core.audit import AuditLogger
from core.validation import DataValidator
from core.metrics import MetricsCollector
from core.plugins import PluginRegistry
from core.plugins.volatility import VolatilityPlugin
from core.plugins.bulk_extractor import BulkExtractorPlugin
from core.plugins.chracer import ChracerPlugin

# --- Observability Modules ---
from core.observability import RequestLogger, HuntingMetrics, RateLimiter, CircuitBreaker

# Init Modules
case_manager = CaseManager()

# Continuous Monitoring Initialization
rule_engine = DetectionEngine()
ingestion_service = IngestionService(rule_engine=rule_engine, case_manager=case_manager)

# Threat Hunting Initialization
from core.hunting.query_engine import QueryEngine
from core.hunting.patterns import PatternDetector
hunting_engine = QueryEngine(case_manager=case_manager)
pattern_detector = PatternDetector(query_engine=hunting_engine)

# Action Engine Initialization
action_engine = ActionEngine(case_manager=case_manager)
action_engine.register_action(BlockIPAction())
action_engine.register_action(TerminateProcessAction())
action_engine.register_action(ExportEvidenceAction())
action_engine.register_action(TagMaliciousAction())
report_generator = ReportGenerator()
ioc_extractor = IOCExtractor()
intel_provider = ThreatIntelProvider()
diff_analyzer = DiffAnalyzer()
behavior_engine = BehaviorSignatureEngine()
anomaly_detector = AnomalyDetector()
time_analyzer = TimeBehaviorAnalyzer()
playbook_engine = PlaybookEngine()

# --- Production Hardening Init ---
job_manager = JobManager()
cache_manager = CacheManager()
audit_logger = AuditLogger()
data_validator = DataValidator()
metrics_collector = MetricsCollector()
job_worker = JobWorker(
    job_manager=job_manager,
    max_workers=2,
    cache_manager=cache_manager,
    audit_logger=audit_logger,
    validator=data_validator,
    metrics_collector=metrics_collector,
)

# --- Observability Init ---
request_logger = RequestLogger(buffer_size=2000)
hunting_metrics = HuntingMetrics(window_seconds=300)
rate_limiter = RateLimiter(default_capacity=10, default_rate=1.0)
query_circuit_breaker = CircuitBreaker(failure_threshold=3, cooldown_seconds=5.0)

# Plugin Registry
plugin_registry = PluginRegistry()

# --- Configuration ---
MEMORY_DUMP = "C:/Major_Project/Evidence/msedge.DMP"
TOOLS_DIR = "C:/Major_Project/Tools"
OUTPUT_DIR = "C:/Major_Project/Layer1_Output_Edge"

# Register plugins (best-effort, non-fatal)
try:
    plugin_registry.register(VolatilityPlugin(tools_dir=TOOLS_DIR, output_dir=OUTPUT_DIR))
except Exception:
    pass
try:
    plugin_registry.register(BulkExtractorPlugin(tools_dir=TOOLS_DIR, output_dir=OUTPUT_DIR))
except Exception:
    pass
try:
    plugin_registry.register(ChracerPlugin(tools_dir=TOOLS_DIR, output_dir=OUTPUT_DIR))
except Exception:
    pass

# Init App
app = FastAPI(title="Antigravity Forensics API", version="2.0.0")

# CORS (configurable via CORS_ORIGINS env var)
import os as _os
_cors_origins = _os.environ.get("CORS_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _cors_origins],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Init Engine
try:
    engine = ForensicsEngine(MEMORY_DUMP, TOOLS_DIR, OUTPUT_DIR)
except Exception as e:
    logging.error(f"Engine init failed: {e}")
    engine = None

# --- Models ---
class Process(BaseModel):
    PID: int
    PPID: int
    ImageFileName: str
    ThreatScore: float
    CreateTime: Optional[str] = None
    IsBrowser: bool

class Connection(BaseModel):
    Proto: str
    LocalAddr: str
    ForeignAddr: str
    State: str
    PID: Optional[int]

class HistoryItem(BaseModel):
    source: str
    url: str
    title: str
    time: str
    type: str

# --- Helpers ---
def get_mock_ps_df():
    return pd.DataFrame({
        "PID": [1000, 2010, 3010, 4010, 5010],
        "PPID": [500, 1000, 3010, 2010, 1000], 
        "ImageFileName": ["explorer.exe", "certutil.exe", "powershell.exe", "cmd.exe", "chrome.exe"],
        "CreateTime": [
            "2026-04-10 10:00:00", "2026-04-10 10:05:00", 
            "2026-04-10 10:06:00", "2026-04-10 10:07:00", "2026-04-10 10:01:00"
        ]
    })

def get_mock_net_df():
    return pd.DataFrame({
        "PID": [2010, 3010, 5010],
        "Proto": ["TCPv4", "TCPv4", "TCPv4"],
        "LocalAddr": ["192.168.1.10", "192.168.1.10", "192.168.1.10"],
        "ForeignAddr": ["8.8.8.8", "198.51.100.1", "142.250.190.46"],
        "ForeignPort": ["443", "4444", "443"],
        "State": ["ESTABLISHED", "ESTABLISHED", "ESTABLISHED"],
        "Owner": ["certutil.exe", "powershell.exe", "chrome.exe"],
        "Created": ["2026-04-10 10:05:30", "2026-04-10 10:06:15", "2026-04-10 10:02:00"]
    })

def get_mock_malfind_df():
    return pd.DataFrame({
        "PID": [3010],
        "Process": ["powershell.exe"],
        "Protection": ["PAGE_EXECUTE_READWRITE"]
    })

def get_ps_df():
    pslist_path = Path(OUTPUT_DIR) / "pslist.txt"
    if not pslist_path.exists(): return get_mock_ps_df()
    df = engine.parse_pslist(pslist_path)
    if not df.empty:
        scores = []
        for _, row in df.iterrows():
            s, _ = engine.calculate_threat_score(row)
            scores.append(s)
        df['Threat Score'] = scores
    return df

def get_net_df():
    netscan_path = Path(OUTPUT_DIR) / "netscan.txt"
    if not netscan_path.exists(): return get_mock_net_df()
    return engine.parse_netscan(netscan_path)
    
def get_malfind_df():
    return get_mock_malfind_df()

# --- Endpoints ---

# --- Startup & Analysis ---
@app.get("/")
def read_root():
    return {"message": "Antigravity Forensics API is running", "status": "online"}

@app.on_event("startup")
async def startup_event():
    """Runs initial analysis on startup in a background thread."""
    global engine
    if not engine: return
    
    import threading
    
    def run_startup_scan():
        logger.info("Deep Scan Engine Starting in Background...")
        
        # 1. Try Process List
        pslist_path = Path(OUTPUT_DIR) / "pslist.txt"
        if not pslist_path.exists():
            logger.info("Running Volatility pslist...")
            try:
                engine.run_volatility("windows.pslist", output_name="pslist.txt")
            except Exception as e:
                logger.warning(f"Standard pslist failed: {e}")
                if "msedge" in MEMORY_DUMP.lower():
                    logger.info("Detected process dump. Creating synthetic process list.")
                    with open(pslist_path, "w") as f:
                        f.write("PID\tPPID\tImageFileName\tOffset\tThreads\tHandles\tSessionId\tWow64\tCreateTime\tExitTime\n")
                        f.write("1337\t1\tmsedge.exe\t0x0\t1\t1\t1\tFalse\t2026-01-01 00:00:00\tN/A\n")

        # 2. Try Network Scan
        netscan_path = Path(OUTPUT_DIR) / "netscan.txt"
        if not netscan_path.exists():
            logger.info("Running Volatility netscan...")
            try:
                 engine.run_volatility("windows.netscan", output_name="netscan.txt")
            except:
                pass 
                
    # Start thread
    thread = threading.Thread(target=run_startup_scan)
    thread.daemon = True
    thread.start() 

@app.get("/health")
def health_check():
    """Enhanced health check with subsystem status."""
    db_ok = True
    try:
        case_manager.get_all_cases()
    except Exception:
        db_ok = False

    return {
        "status": "ok" if (engine and db_ok) else "degraded",
        "db": "connected" if db_ok else "error",
        "query_engine": "ready" if query_circuit_breaker.state.value != "open" else "circuit_open",
        "engine": "active" if engine else "offline",
        "circuit_breaker": query_circuit_breaker.get_status(),
        "rate_limiter_buckets": rate_limiter.get_bucket_count(),
    }


@app.get("/readiness")
def readiness_check():
    """Readiness probe — returns 503 if system cannot serve traffic."""
    db_ok = True
    try:
        case_manager.get_all_cases()
    except Exception:
        db_ok = False

    cb_state = query_circuit_breaker.state.value
    ready = db_ok and cb_state != "open"

    if not ready:
        raise HTTPException(
            status_code=503,
            detail={
                "ready": False,
                "db": "connected" if db_ok else "error",
                "circuit_breaker": cb_state,
            },
        )

    return {
        "ready": True,
        "db": "connected",
        "circuit_breaker": cb_state,
    }

@app.get("/processes", response_model=List[Process])
def listed_processes():
    df = get_ps_df()
    if df.empty: return []
    
    # Safe conversion
    df = df.fillna("")
    result = []
    for _, row in df.iterrows():
        is_browser = row['ImageFileName'].lower() in ["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe"]
        result.append({
            "PID": row['PID'],
            "PPID": row['PPID'],
            "ImageFileName": row['ImageFileName'],
            "ThreatScore": row.get('Threat Score', 0.0),
            "CreateTime": str(row['CreateTime']),
            "IsBrowser": is_browser
        })
    return result

@app.get("/network", response_model=List[Connection])
def list_connections():
    df = get_net_df()
    if df.empty: return []
    return df.to_dict(orient="records")

@app.get("/process/{pid}/network")
def process_network(pid: int):
    df_net = get_net_df()
    context = engine.match_process_artifacts(pid, df_net)
    return context['connections']

@app.post("/scan/{pid}/{tool}")
def run_tool(pid: int, tool: str):
    """Tools: malfind, yara, chracer"""
    if tool == "malfind":
        out = engine.run_volatility_pid("windows.malfind", pid)
        findings = engine.parse_malfind(out)
        return {"tool": "malfind", "pid": pid, "findings": findings}
    
    elif tool == "chracer":
        out = engine.run_chracer(pid)
        df = engine.parse_chracer_output(out)
        return {"tool": "chracer", "pid": pid, "findings": df.to_dict(orient="records")}
    
    else:
        raise HTTPException(status_code=400, detail="Unknown tool")

@app.get("/history/unified", response_model=List[HistoryItem])
def get_unified_history(pid: int = None):
    """
    Returns disk history (persistent) + simulated/active memory artifacts.
    If 'pid' is provided, filters MEMORY artifacts to that PID (if possible).
    Disk history is always global.
    """
    # 1. Get Disk History (Global)
    disk_history = get_chrome_history()
    
    # 2. Get Memory Artifacts (PID specific or Global)
    memory_history = []
    
    # Strategy: If PID is provided, we TRY to run Chracer on it.
    # If not, we fall back to global bulk extractor artifacts.
    
    if pid:
        # Try active scan first
        try:
            # Check if it's a browser process before scanning
            # (Simple heuristic: image name check from pslist)
            # For now, just try the scan.
            out = engine.run_chracer(pid)
            df = engine.parse_chracer_output(out)
            if not df.empty:
                for _, row in df.iterrows():
                    memory_history.append({
                        "source": f"Active RAM (PID {pid})",
                        "url": str(row.get('URL', '')),
                        "title": str(row.get('Title', 'Unknown Tab')),
                        "time": str(row.get('Time', 'Unknown')),
                        "type": "incognito_active"
                    })
        except:
             # If active scan fails, fall back to global artifacts? 
             # No, if PID is specific, we want specific results.
             pass
    
    # If no PID specific results (or no PID provided), add global artifacts
    if not memory_history:
        url_file = Path(OUTPUT_DIR) / "bulk_extractor_report" / "url.txt"
        if url_file.exists():
            try:
                 # Limit to recent 50 for speed
                 df = pd.read_csv(url_file, sep="\t", names=["Offset", "URL"], engine='python', on_bad_lines='skip', nrows=50)
                 for _, row in df.iterrows():
                     memory_history.append({
                         "source": "Global Memory Artifact",
                         "url": str(row['URL']),
                         "title": "Artifact",
                         "time": "Unknown",
                         "type": "artifact"
                     })
            except:
                pass

    return disk_history + memory_history

@app.get("/stats")
def get_stats():
    df_ps = get_ps_df()
    df_net = get_net_df()
    
    return {
        "total_processes": len(df_ps),
        "active_connections": len(df_net),
        "high_risk_count": len(df_ps[df_ps['Threat Score'] >= 3]) if not df_ps.empty else 0,
        "browsers_active": len(df_ps[df_ps['ImageFileName'].str.lower().isin(["chrome.exe", "msedge.exe"])]) if not df_ps.empty else 0
    }

@app.get("/correlate")
def get_correlated_data():
    """Returns the fully correlated process DataFrame with behavioral flags."""
    df_ps = get_ps_df()
    df_net = get_net_df()
    if df_ps.empty:
        return []
    result = correlate_artifacts(df_ps, df_net, get_malfind_df())
    return result.fillna("").to_dict(orient="records")

@app.get("/correlate/{pid}/explain")
def get_process_explanation(pid: int):
    """Returns a human-readable explanation for a specific process."""
    df_ps = get_ps_df()
    df_net = get_net_df()
    if df_ps.empty:
        raise HTTPException(status_code=404, detail="No process data available.")
    result = correlate_artifacts(df_ps, df_net, get_malfind_df())
    explanation = explain_process(pid, result, df_net)
    return {"pid": pid, "explanation": explanation}

@app.get("/graph")
def get_process_graph():
    """Returns the process/network graph as JSON for frontend visualization."""
    df_ps = get_ps_df()
    df_net = get_net_df()
    if df_ps.empty:
        return {"nodes": [], "edges": []}
        
    correlated = correlate_artifacts(df_ps, df_net, get_malfind_df())
    enriched = enrich_with_explanations(correlated)
    timeline = build_timeline(df_ps, df_net, get_malfind_df(), enriched)
    
    from pipeline.graph_engine import build_attack_graph
    graph = build_attack_graph(enriched, timeline)
    return graph

@app.get("/alerts")
def get_alerts():
    """Returns alert-ready JSON with only HIGH and MEDIUM severity processes."""
    df_ps = get_ps_df()
    df_net = get_net_df()
    if df_ps.empty:
        return []
    correlated = correlate_artifacts(df_ps, df_net, get_malfind_df())
    enriched = enrich_with_explanations(correlated)
    alerts = generate_alerts(enriched)
    return alerts.fillna("").to_dict(orient="records")

@app.get("/alerts/summary")
def get_alerts_summary():
    """Returns a short investigation summary string."""
    df_ps = get_ps_df()
    df_net = get_net_df()
    if df_ps.empty:
        return {"summary": "No process data available."}
    correlated = correlate_artifacts(df_ps, df_net, get_malfind_df())
    enriched = enrich_with_explanations(correlated)
    return {"summary": explain_summary(enriched)}

@app.get("/timeline")
def get_timeline():
    """Returns the unified forensic timeline as JSON."""
    df_ps = get_ps_df()
    df_net = get_net_df()
    if df_ps.empty:
        return []
    correlated = correlate_artifacts(df_ps, df_net, get_malfind_df())
    enriched = enrich_with_explanations(correlated)
    tl = build_timeline(df_ps, df_net, get_malfind_df(), enriched)
    # Convert timestamps to strings for JSON serialization
    tl_out = tl.copy()
    if "timestamp" in tl_out.columns:
        tl_out["timestamp"] = tl_out["timestamp"].astype(str)
    return tl_out.fillna("").to_dict(orient="records")

@app.get("/timeline/summary")
def get_timeline_summary():
    """Returns a narrative summary of the forensic timeline."""
    df_ps = get_ps_df()
    df_net = get_net_df()
    if df_ps.empty:
        return {"summary": "No timeline data available."}
    correlated = correlate_artifacts(df_ps, df_net, get_malfind_df())
    enriched = enrich_with_explanations(correlated)
    tl = build_timeline(df_ps, df_net, get_malfind_df(), enriched)
    return {"summary": summarize_timeline(tl)}

# --- Auth Endpoints ---

@app.post("/auth/register")
def register(user: UserAuth):
    hashed_pw = get_password_hash(user.password)
    user_id = case_manager.register_user(user.username, hashed_pw, user.role)
    if not user_id:
        raise HTTPException(status_code=400, detail="Username already registered")
    return {"id": user_id, "username": user.username, "role": user.role}

@app.post("/auth/login")
def login(user: UserAuth):
    db_user = case_manager.get_user_by_username(user.username)
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    token = create_access_token(data={"sub": db_user["username"], "id": db_user["id"], "role": db_user["role"]})
    return {"access_token": token, "token_type": "bearer"}


# --- Advanced Forensics Endpoints ---

@app.post("/cases")
def create_case(data: dict = Body(...), current_user: dict = Depends(get_current_user)):
    return case_manager.create_case(data, owner_id=current_user["id"])

@app.get("/cases")
def get_cases(current_user: dict = Depends(get_current_user)):
    cases = case_manager.get_all_cases()
    # Filter cases for the current user unless they are admin
    if current_user["role"] == "admin" or current_user["role"] == "system":
        return cases
    
    auth_cases = []
    for c in cases:
        if c.get("owner_id") == current_user["id"]:
            auth_cases.append(c)
        else:
            shared = case_manager.db.get_case_users(c["id"])
            if any(u["id"] == current_user["id"] for u in shared):
                auth_cases.append(c)
    return auth_cases

@app.get("/cases/{case_id}")
def get_case(case_id: int, current_user: dict = Depends(get_current_user)):
    case = case_manager.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
        
    # Access control
    is_owner = case.get("owner_id") == current_user["id"]
    is_admin = current_user["role"] in ["admin", "system"]
    if not is_owner and not is_admin:
        shared = case_manager.db.get_case_users(case_id)
        if not any(u["id"] == current_user["id"] for u in shared):
            raise HTTPException(status_code=403, detail="Not authorized to view case")
            
    # Include shared users and activity
    case["shared_users"] = case_manager.db.get_case_users(case_id)
    case["comments"] = case_manager.get_comments(case_id)
    return case

@app.post("/cases/{case_id}/share")
def share_case(case_id: int, data: dict = Body(...), current_user: dict = Depends(get_current_user)):
    # data: {"username": "...", "role": "analyst"}
    target_username = data.get("username")
    role = data.get("role", "viewer")
    if not target_username:
        raise HTTPException(status_code=400, detail="username required")
        
    res = case_manager.share_case(case_id, current_user["id"], target_username, role)
    if res.get("status") == "error":
        raise HTTPException(status_code=400, detail=res["message"])
    return res

@app.post("/cases/{case_id}/comments")
def add_comment(case_id: int, data: dict = Body(...), current_user: dict = Depends(get_current_user)):
    # data: {"entity_type": "...", "entity_id": "...", "comment": "..."}
    entity_type = data.get("entity_type")
    entity_id = data.get("entity_id")
    comment_text = data.get("comment")
    if not all([entity_type, entity_id, comment_text]):
        raise HTTPException(status_code=400, detail="Missing fields")
    return case_manager.add_comment(case_id, current_user["id"], entity_type, entity_id, comment_text)

@app.post("/cases/{case_id}/notes")
def add_case_note(case_id: int, data: dict = Body(...), current_user: dict = Depends(get_current_user)):
    entity_type = data.get("entity_type", "case")
    entity_id = data.get("entity_id", str(case_id))
    note_text = data.get("note_text")
    if not note_text:
        raise HTTPException(status_code=400, detail="Missing note_text")
    return case_manager.add_note(case_id, entity_type, entity_id, note_text, user_id=current_user["id"])

@app.get("/cases/{case_id}/activity")
def get_case_activity(case_id: int, current_user: dict = Depends(get_current_user)):
    return {"activity": case_manager.get_activity_log(case_id)}

@app.get("/cases/{case_id}/summary")
def get_case_dashboard_summary(case_id: int, current_user: dict = Depends(get_current_user)):
    case = case_manager.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
        
    num_alerts = 0
    high_risk_processes = []
    
    alerts_state = case.get("alerts_state")
    if alerts_state and isinstance(alerts_state, list):
        num_alerts = len(alerts_state)
        # Extract high risk processes
        high_risk_processes = [a.get("Process Name", "Unknown") for a in alerts_state if a.get("Severity") == "HIGH"]
        
    return {
        "case_id": case_id,
        "name": case.get("name"),
        "status": case.get("status", "OPEN"),
        "alert_count": num_alerts,
        "high_risk_processes": list(set(high_risk_processes))
    }

@app.get("/report/{case_id}/{format}")
def generate_report(case_id: int, format: str):
    case_data = case_manager.get_case(case_id) or {}
    alerts = get_alerts()
    timeline = get_timeline()
    if format.lower() == "pdf":
        path = report_generator.generate_pdf_report(case_id, case_data, alerts, timeline)
    else:
        path = report_generator.generate_json_report(case_id, case_data, alerts, timeline)
    return {"status": "success", "report_path": path}

@app.get("/ioc")
def get_iocs():
    df_ps = get_ps_df()
    df_net = get_net_df()
    correlated = correlate_artifacts(df_ps, df_net, get_malfind_df()) if not df_ps.empty else pd.DataFrame()
    enriched = enrich_with_explanations(correlated) if not correlated.empty else pd.DataFrame()
    return ioc_extractor.extract_from_df(enriched, df_net, get_malfind_df())

@app.get("/intel/ip/{ip}")
def get_ip_reputation(ip: str):
    return intel_provider.check_ip(ip)

@app.get("/diff")
def perform_diff():
    return diff_analyzer.compare_dumps(get_ps_df(), get_ps_df(), get_net_df(), get_net_df())

@app.get("/signatures")
def get_signatures():
    df_ps = get_ps_df()
    df_net = get_net_df()
    correlated = correlate_artifacts(df_ps, df_net, get_malfind_df()) if not df_ps.empty else pd.DataFrame()
    enriched = enrich_with_explanations(correlated) if not correlated.empty else pd.DataFrame()
    return behavior_engine.evaluate_signatures(enriched)

@app.get("/tree")
def get_process_tree_endpoint():
    df_ps = get_ps_df()
    df_net = get_net_df()
    correlated = correlate_artifacts(df_ps, df_net, get_malfind_df()) if not df_ps.empty else pd.DataFrame()
    enriched = enrich_with_explanations(correlated) if not correlated.empty else pd.DataFrame()
    return build_process_tree(df_ps, enriched)

@app.get("/anomaly")
def get_anomalies():
    return anomaly_detector.detect_anomalies(get_ps_df(), get_net_df())

@app.get("/bursts")
def get_bursts():
    df_ps = get_ps_df()
    df_net = get_net_df()
    correlated = correlate_artifacts(df_ps, df_net, get_malfind_df()) if not df_ps.empty else pd.DataFrame()
    enriched = enrich_with_explanations(correlated) if not correlated.empty else pd.DataFrame()
    timeline_df = build_timeline(df_ps, df_net, get_malfind_df(), enriched)
    return time_analyzer.detect_bursts(timeline_df)

@app.get("/playbooks/suggest")
def suggest_playbooks():
    iocs = get_iocs()
    anomalies = get_anomalies()
    sigs = get_signatures()
    suggestions = playbook_engine.suggest_playbooks(iocs, anomalies, sigs)
    return suggestions

@app.get("/playbooks/{pb_id}")
def get_playbook(pb_id: str):
    pb = playbook_engine.get_playbook(pb_id)
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return pb


# =========================================================================
#  DECISION ENGINE ENDPOINTS
# =========================================================================

def _get_decision_data():
    """
    Fetch the latest analysis results for the active case.
    Returns (correlation_df, timeline_df, graph, alerts) from
    the most recent completed job, or falls back to live computation.
    """
    # Strategy 1: Try latest completed job
    jobs = job_manager.list_jobs()
    for job_info in jobs:
        if job_info.status == JobStatus.COMPLETED:
            result = job_manager.get_result(job_info.job_id)
            if result is not None:
                corr_df = pd.DataFrame(result.correlation) if result.correlation else pd.DataFrame()
                tl_df = pd.DataFrame(result.timeline) if result.timeline else pd.DataFrame()
                graph = result.graph if result.graph else {"nodes": [], "edges": []}
                alerts = result.alerts if result.alerts else []
                return corr_df, tl_df, graph, alerts

    # Strategy 2: Fall back to live computation from current data
    df_ps = get_ps_df()
    df_net = get_net_df()
    if df_ps.empty:
        return pd.DataFrame(), pd.DataFrame(), {"nodes": [], "edges": []}, []

    corr = correlate_artifacts(df_ps, df_net, get_malfind_df())
    enriched = enrich_with_explanations(corr)
    tl = build_timeline(df_ps, df_net, get_malfind_df(), enriched)
    alerts_df = generate_alerts(enriched)

    from pipeline.graph_engine import build_attack_graph
    graph = build_attack_graph(enriched, tl)
    alerts_list = alerts_df.fillna("").to_dict(orient="records") if not alerts_df.empty else []

    return enriched, tl, graph, alerts_list


@app.get("/decision/plan")
def get_decision_plan():
    """Returns an ordered list of investigation steps ranked by severity."""
    corr_df, tl_df, graph, _ = _get_decision_data()
    if corr_df.empty:
        raise HTTPException(status_code=404, detail="No analysis data available.")
    return generate_investigation_plan(corr_df, tl_df, graph)


@app.get("/decision/root-cause")
def get_decision_root_cause():
    """Returns the detected root cause / entry point of the attack."""
    corr_df, tl_df, _, _ = _get_decision_data()
    if tl_df.empty and corr_df.empty:
        raise HTTPException(status_code=404, detail="No analysis data available.")
    return detect_root_cause(tl_df, corr_df)


@app.get("/decision/chain")
def get_decision_chain():
    """Returns the reconstructed attack chain as an ordered list."""
    _, tl_df, graph, _ = _get_decision_data()
    if not graph.get("nodes"):
        raise HTTPException(status_code=404, detail="No graph data available.")
    return reconstruct_attack_chain(graph, tl_df)


@app.get("/decision/confidence")
def get_decision_confidence():
    """Returns the confidence score and contributing factors."""
    corr_df, _, graph, _ = _get_decision_data()
    if corr_df.empty:
        raise HTTPException(status_code=404, detail="No analysis data available.")
    return compute_confidence(corr_df, graph)


@app.get("/decision/summary")
def get_decision_summary():
    """Returns a concise natural-language summary of investigation findings."""
    corr_df, tl_df, graph, _ = _get_decision_data()
    if corr_df.empty:
        raise HTTPException(status_code=404, detail="No analysis data available.")
    return {"summary": generate_attack_summary(corr_df, tl_df, graph)}


# =========================================================================
#  PRODUCTION HARDENING ENDPOINTS
# =========================================================================

# --- Phase 1: Async Job System ---

@app.post("/jobs/analyze")
def create_analysis_job(request: AnalyzeRequest):
    """Submit a new asynchronous analysis job."""
    job_id = job_manager.create_job(request.dump_path, job_type="single")
    job_worker.submit(job_id, request.dump_path)
    return {"job_id": job_id}


@app.get("/jobs")
def list_jobs():
    """List all analysis jobs (newest first)."""
    jobs = job_manager.list_jobs()
    return [j.model_dump() for j in jobs]


@app.get("/jobs/{job_id}")
def get_job_status(job_id: str):
    """Get the status and progress of a specific job."""
    info = job_manager.get_status(job_id)
    if info is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return info.model_dump()


@app.get("/jobs/{job_id}/result")
def get_job_result(job_id: str):
    """Get the full analysis result for a completed job."""
    info = job_manager.get_status(job_id)
    if info is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if info.status != JobStatus.COMPLETED:
        raise HTTPException(
            status_code=409,
            detail=f"Job not completed. Current status: {info.status.value}"
        )
    result = job_manager.get_result(job_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Result not available")
    return result.model_dump()


# --- Phase 2: Cache Management ---

@app.get("/cache")
def list_cached_results():
    """List all cached analysis results."""
    return cache_manager.list_cached()


@app.delete("/cache/{dump_hash}")
def invalidate_cache(dump_hash: str):
    """Invalidate a cached result by dump hash."""
    cache_manager.db.invalidate(dump_hash)
    return {"status": "invalidated", "dump_hash": dump_hash}


# --- Phase 3: Audit Log ---

@app.get("/jobs/{job_id}/audit")
def get_job_audit_trail(job_id: str):
    """Get the audit trail for a specific job."""
    if not job_manager.job_exists(job_id):
        raise HTTPException(status_code=404, detail="Job not found")
    return audit_logger.get_audit_trail(job_id)


@app.get("/audit")
def get_recent_audit(limit: int = 100):
    """Get recent audit entries across all jobs."""
    return audit_logger.get_all_actions(limit=limit)


# --- Phase 5: Plugin Registry ---

@app.get("/plugins")
def list_plugins():
    """List all registered tool plugins."""
    return plugin_registry.list_plugins()


# --- Phase 6: Multi-Dump Analysis ---

@app.post("/jobs/analyze/multi")
def create_multi_analysis_job(request: MultiAnalyzeRequest):
    """Submit a multi-dump comparison job."""
    paths_str = ",".join(request.dump_paths)
    job_id = job_manager.create_job(paths_str, job_type="multi")
    job_worker.submit_multi(job_id, request.dump_paths)
    return {"job_id": job_id}


@app.get("/jobs/{job_id}/diff")
def get_job_diff(job_id: str):
    """Get diff analysis results for a multi-dump job."""
    info = job_manager.get_status(job_id)
    if info is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if info.status != JobStatus.COMPLETED:
        raise HTTPException(
            status_code=409,
            detail=f"Job not completed. Current status: {info.status.value}"
        )
    result = job_manager.get_result(job_id)
    if result is None or result.diff is None:
        raise HTTPException(status_code=404, detail="No diff results available")
    return result.diff


# --- Phase 7: Performance Metrics ---

@app.get("/jobs/{job_id}/metrics")
def get_job_metrics(job_id: str):
    """Get performance metrics for a specific job."""
    if not job_manager.job_exists(job_id):
        raise HTTPException(status_code=404, detail="Job not found")
    metrics = metrics_collector.get_metrics(job_id)
    if metrics is None:
        return {"job_id": job_id, "message": "No metrics available yet"}
    return metrics


@app.get("/metrics/summary")
def get_metrics_summary():
    """Get aggregate performance metrics across all jobs."""
    return metrics_collector.get_summary()


# --- Action Engine Endpoints ---

@app.post("/actions/execute")
def execute_action(data: dict = Body(...), current_user: dict = Depends(get_current_user)):
    """Executes a defined investigative/response action."""
    with request_logger.track_request("/actions/execute", "POST", current_user) as log:
        action_name = data.get("action")
        target = data.get("target")
        case_id = data.get("case_id")
        simulate = data.get("simulate", True)
        log.extra = {"action": action_name, "target": str(target)[:100], "case_id": case_id}

        if not all([action_name, target, case_id]):
            log.status_code = 400
            raise HTTPException(status_code=400, detail="Missing action, target, or case_id")

        # Access control: viewer cannot execute actions
        if current_user["role"] == "viewer":
            log.status_code = 403
            raise HTTPException(status_code=403, detail="Viewers cannot execute actions")

        # Authorize case
        case = case_manager.get_case(case_id)
        if not case:
            log.status_code = 404
            raise HTTPException(status_code=404, detail="Case not found")

        context = {
            "target": target,
            "manager": case_manager,
            "simulate_mode": simulate,
            "user_id": current_user["id"],
            "case_id": case_id
        }
        
        action_engine.simulate_mode = simulate

        result = action_engine.execute_action(action_name, context, current_user["id"], case_id)
        if result.get("status") == "error":
            log.status_code = 400
            log.error = result.get("message", "Action failed")
            raise HTTPException(status_code=400, detail=result.get("message"))

        log.status_code = 200
        return result

@app.get("/actions/recommendations/{case_id}")
def get_action_recommendations(case_id: int, current_user: dict = Depends(get_current_user)):
    case_data = case_manager.get_case(case_id)
    if not case_data:
        raise HTTPException(status_code=404, detail="Case not found")
        
    corr_state = case_data.get("alerts_state", []) 
    df_corr = pd.DataFrame(corr_state) if corr_state else pd.DataFrame()
    df_tl = pd.DataFrame(case_data.get("timeline_state", []))
    
    recs = recommend_actions(df_corr, df_tl, case_data.get("graph_state", {}))
    return {"recommendations": recs}

@app.get("/cases/{case_id}/actions")
def get_case_action_logs(case_id: int, current_user: dict = Depends(get_current_user)):
    case = case_manager.get_case(case_id)
    if not case:
         raise HTTPException(status_code=404, detail="Case not found")
         
    logs = case_manager.get_action_logs(case_id)
    return {"logs": logs}


# --- Continuous Monitoring & Detection Endpoints ---

@app.post("/ingest/event")
def ingest_event(payload: dict = Body(...), current_user: dict = Depends(get_current_user)):
    """Ingests a raw stream event, processes through rule engine, and updates cases."""
    with request_logger.track_request("/ingest/event", "POST", current_user) as log:
        event_type = payload.get("type")
        data = payload.get("data")
        source = payload.get("source")
        log.extra = {"event_type": event_type, "source": str(source)[:100]}

        if not all([event_type, data, source]):
            log.status_code = 400
            raise HTTPException(status_code=400, detail="Payload requires type, data, and source fields")

        # Rate limit: 100 events/sec per source
        source_key = str(source)[:100]
        if not rate_limiter.check(source_key, scope="ingest_event", capacity=100, rate=100.0):
            log.status_code = 429
            raise HTTPException(status_code=429, detail="Rate limit exceeded for this source.")

        result = ingestion_service.process_event(event_type, data, source)
        log.result_count = 1
        log.status_code = 200
        return result

@app.post("/rules")
def create_detection_rule(payload: dict = Body(...), current_user: dict = Depends(get_current_user)):
    name = payload.get("id") or payload.get("name")
    severity = payload.get("severity", "MEDIUM")
    action = payload.get("action", "recommend")
    conditions = payload.get("conditions")

    if not name or not conditions:
        raise HTTPException(status_code=400, detail="Missing name or conditions")

    rule_id = case_manager.create_rule(name, severity, action, conditions)
    return {"status": "success", "rule_id": rule_id}

@app.get("/rules")
def list_detection_rules(current_user: dict = Depends(get_current_user)):
    rules = case_manager.get_rules(active_only=True)
    return {"rules": rules}

@app.delete("/rules/{rule_id}")
def delete_detection_rule(rule_id: int, current_user: dict = Depends(get_current_user)):
    case_manager.delete_rule(rule_id)
    return {"status": "deleted"}

@app.get("/alerts/stream")
def get_alert_stream(limit: int = 50, current_user: dict = Depends(get_current_user)):
    stream = case_manager.get_alert_stream(limit)
    return {"stream": stream}


# --- Threat Hunting Endpoints ---

@app.post("/hunt/query")
def hunt_execute_query(payload: dict = Body(...), current_user: dict = Depends(get_current_user)):
    with request_logger.track_request("/hunt/query", "POST", current_user) as log:
        query = payload.get("query", "")
        log.query_length = len(query) if query else 0

        # --- Query Validation ---
        if not query or not query.strip():
            log.status_code = 400
            raise HTTPException(status_code=400, detail="Missing query string.")

        if len(query) > 500:
            log.status_code = 400
            raise HTTPException(status_code=400, detail="Query exceeds maximum length of 500 characters.")

        # Basic syntax check: must contain at least one operator and one field
        import re
        has_op = bool(re.search(r'(==|!=|>=|<=|>|<)', query))
        has_field = bool(re.search(r'(process_name|severity|source|case_id|timestamp|event_type|pid|ip)', query, re.IGNORECASE))
        if not has_op or not has_field:
            log.status_code = 400
            raise HTTPException(
                status_code=400,
                detail="Invalid query syntax. Must contain a field name and comparison operator. Example: process_name == 'powershell.exe'"
            )

        # --- Rate Limiting: 10 requests / 10 seconds / user ---
        user_key = str(current_user.get("id", "anon"))
        if not rate_limiter.check(user_key, scope="hunt_query", capacity=10, rate=1.0):
            log.status_code = 429
            raise HTTPException(status_code=429, detail="Rate limit exceeded. Max 10 queries per 10 seconds.")

        # --- Circuit Breaker ---
        if not query_circuit_breaker.allow_request():
            log.status_code = 503
            log.error = "Circuit breaker open"
            raise HTTPException(
                status_code=503,
                detail="Query engine temporarily unavailable. Please try again in a few seconds."
            )

        # --- Enforce result limit (default 100, max 500) ---
        limit = min(int(payload.get("limit", 100)), 500)

        try:
            results = hunting_engine.execute(query)
            query_circuit_breaker.record_success()

            total = len(results)
            limited = results[:limit]
            truncated = total > limit

            log.result_count = len(limited)
            log.truncated = truncated
            log.status_code = 200

            # Record hunting metrics
            hunting_metrics.record(
                duration_ms=log.execution_time_ms,
                success=True,
                result_count=len(limited),
            )

            return {
                "count": len(limited),
                "results": limited,
                "total": total,
                "truncated": truncated,
                "request_id": log.request_id,
            }
        except HTTPException:
            raise  # Re-raise validation/rate limit errors
        except Exception as e:
            query_circuit_breaker.record_failure()
            hunting_metrics.record(duration_ms=0, success=False, result_count=0)
            log.status_code = 400
            # Sanitize error — never expose raw stack traces
            safe_msg = str(e)[:200] if str(e) else "Query execution failed."
            log.error = safe_msg
            raise HTTPException(status_code=400, detail=safe_msg)

@app.post("/hunt/save")
def hunt_save_query(payload: dict = Body(...), current_user: dict = Depends(get_current_user)):
    name = payload.get("name")
    query = payload.get("query")
    if not name or not query:
        raise HTTPException(status_code=400, detail="Name and query are required")
        
    uid = current_user.get("id", 1)
    q_id = case_manager.save_query(uid, name, query)
    return {"status": "success", "id": q_id}

@app.get("/hunt/saved")
def hunt_get_saved(current_user: dict = Depends(get_current_user)):
    uid = current_user.get("id", 1)
    queries = case_manager.get_saved_queries(uid)
    return {"queries": queries}

@app.delete("/hunt/saved/{q_id}")
def hunt_delete_query(q_id: int, current_user: dict = Depends(get_current_user)):
    uid = current_user.get("id", 1)
    case_manager.delete_query(q_id, uid)
    return {"status": "deleted"}

@app.get("/hunt/stats")
def hunt_get_stats(current_user: dict = Depends(get_current_user)):
    try:
        stats = pattern_detector.get_hunting_stats()
        repeated = pattern_detector.find_repeated_processes()
        rare = pattern_detector.detect_rare_processes()
        
        return {
            "stats": stats,
            "patterns": {
                "repeated_processes_across_hosts": repeated,
                "rare_single_occurrences": rare
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# =========================================================================
#  OBSERVABILITY ENDPOINTS
# =========================================================================

@app.get("/metrics/hunting")
def get_hunting_metrics():
    """Returns hunting query performance metrics (sliding 5-min window)."""
    return hunting_metrics.get_stats()


@app.get("/logs/recent")
def get_recent_logs(limit: int = 100, current_user: dict = Depends(get_current_user)):
    """Returns recent structured request logs (admin only)."""
    if current_user.get("role") not in ("admin", "system"):
        raise HTTPException(status_code=403, detail="Admin access required.")
    return {"logs": request_logger.get_recent(min(limit, 500))}


@app.get("/logs/errors")
def get_error_logs(limit: int = 50, current_user: dict = Depends(get_current_user)):
    """Returns recent error logs (admin only)."""
    if current_user.get("role") not in ("admin", "system"):
        raise HTTPException(status_code=403, detail="Admin access required.")
    return {"errors": request_logger.get_error_logs(min(limit, 200))}


@app.post("/logs/frontend")
def receive_frontend_log(payload: dict = Body(...)):
    """Receives error telemetry from the frontend UI."""
    from core.observability.logger import RequestLog
    entry = RequestLog(
        request_id=payload.get("request_id", "frontend"),
        endpoint=payload.get("endpoint", "/frontend"),
        method="FRONTEND",
        error=str(payload.get("error", ""))[:500],
        extra={
            "component": payload.get("component", "unknown"),
            "user_agent": payload.get("user_agent", ""),
            "stack": str(payload.get("stack", ""))[:1000],
        },
    )
    request_logger.log(entry)
    return {"status": "received"}


@app.get("/metrics/prom")
def get_prometheus_metrics():
    """Prometheus-compatible text metrics for external scrapers."""
    from fastapi.responses import PlainTextResponse
    stats = hunting_metrics.get_stats()
    cb = query_circuit_breaker.get_status()

    lines = [
        "# HELP antigravity_hunt_query_latency_ms Average hunt query latency in milliseconds.",
        "# TYPE antigravity_hunt_query_latency_ms gauge",
        f"antigravity_hunt_query_latency_ms {stats.get('avg_query_time', 0)}",
        "",
        "# HELP antigravity_hunt_p95_latency_ms P95 hunt query latency in milliseconds.",
        "# TYPE antigravity_hunt_p95_latency_ms gauge",
        f"antigravity_hunt_p95_latency_ms {stats.get('p95_query_time', 0)}",
        "",
        "# HELP antigravity_hunt_queries_per_minute Queries per minute (sliding window).",
        "# TYPE antigravity_hunt_queries_per_minute gauge",
        f"antigravity_hunt_queries_per_minute {stats.get('queries_per_minute', 0)}",
        "",
        "# HELP antigravity_hunt_error_rate Query error rate (0-1).",
        "# TYPE antigravity_hunt_error_rate gauge",
        f"antigravity_hunt_error_rate {stats.get('error_rate', 0)}",
        "",
        "# HELP antigravity_hunt_total_queries Total queries in sliding window.",
        "# TYPE antigravity_hunt_total_queries gauge",
        f"antigravity_hunt_total_queries {stats.get('total_queries', 0)}",
        "",
        "# HELP antigravity_circuit_breaker_trips Total circuit breaker trips.",
        "# TYPE antigravity_circuit_breaker_trips counter",
        f"antigravity_circuit_breaker_trips {cb.get('total_trips', 0)}",
        "",
        "# HELP antigravity_rate_limiter_buckets Active rate limiter buckets.",
        "# TYPE antigravity_rate_limiter_buckets gauge",
        f"antigravity_rate_limiter_buckets {rate_limiter.get_bucket_count()}",
        "",
    ]
    return PlainTextResponse("\n".join(lines), media_type="text/plain; version=0.0.4")


# --- Shutdown Hook ---

@app.on_event("shutdown")
async def shutdown_event():
    """Gracefully shut down the job worker thread pool."""
    logger.info("Shutting down job worker...")
    job_worker.shutdown(wait=False)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
