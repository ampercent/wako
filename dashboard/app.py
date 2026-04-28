import streamlit as st
import pandas as pd
import sys
import os
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
from datetime import datetime

# Add project root to path
current_dir = Path(__file__).resolve().parent
project_root = current_dir.parent
sys.path.append(str(project_root))

from pipeline.engine import ForensicsEngine
from pipeline.correlation import correlate_artifacts

# Import PDF generator if available
try:
    from dashboard.pdf_gen import generate_pdf_report
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

# --- Config ---
st.set_page_config(
    page_title="Wako", 
    layout="wide", 
    page_icon="🕵️‍♂️",
    initial_sidebar_state="expanded"
)

# --- Constants ---
MEMORY_DUMP = "C:/Major_Project/Evidence/WAKO-20260115-125522.dmp"
TOOLS_DIR = "C:/Major_Project/Tools"
OUTPUT_DIR = "C:/Major_Project/Layer1_Output"
CASE_ID = "WAKO-20260115"
INVESTIGATOR_NAME = "Admin" # Placeholder

# --- Engine Initialization ---
@st.cache_resource
def get_engine():
    return ForensicsEngine(MEMORY_DUMP, TOOLS_DIR, OUTPUT_DIR)

try:
    engine = get_engine()
except Exception as e:
    st.error(f"Failed to initialize engine: {e}")
    st.stop()

# --- Helper Functions ---
def load_css(is_dark=False):
    css_path = Path(__file__).parent / "style.css"
    try:
        with open(css_path) as f:
            st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)
            
        if is_dark:
            dark_css = """
            <style>
            :root {
                --bg-color: #0E1117;
                --card-bg: #1A1C23;
                --text-primary: #E5E7EB;
                --text-secondary: #9CA3AF;
                --border-color: #374151;
            }
            .stApp { background-color: var(--bg-color) !important; color: var(--text-primary) !important; }
            .header-bar { background-color: var(--card-bg); border-bottom-color: var(--border-color); }
            .header-title, h1, h2, h3, h4, h5, h6, .card-header, div[data-testid="stMetricValue"] { color: var(--text-primary) !important; }
            .card-container, div[data-testid="stMetric"] { background-color: var(--card-bg); border-color: var(--border-color); }
            div[data-testid="stMetricLabel"] { color: var(--text-secondary) !important; }
            div[data-testid="stSidebar"] { background-color: #000000 !important; border-right-color: #1F2937; }
            code { background-color: #1F2937; color: #F472B6; border-color: #374151; }
            .status-success { background-color: #064E3B; color: #34D399; }
            .status-warning { background-color: #78350F; color: #FBBF24; }
            .status-danger { background-color: #7F1D1D; color: #F87171; }
            .status-info { background-color: #1E3A8A; color: #60A5FA; }
            </style>
            """
            st.markdown(dark_css, unsafe_allow_html=True)
    except FileNotFoundError:
        pass 

def load_data():
    """Loads and correlates all data using the correlation engine."""
    # PsList
    pslist_path = Path(OUTPUT_DIR) / "pslist.txt"
    if not pslist_path.exists():
        return None, None, None
    df_ps = engine.parse_pslist(pslist_path)

    # Check for empty/failed parsing
    if df_ps.empty or 'ImageFileName' not in df_ps.columns:
        return None, None, None

    # NetScan
    netscan_path = Path(OUTPUT_DIR) / "netscan.txt"
    df_net = pd.DataFrame()
    if netscan_path.exists():
        df_net = engine.parse_netscan(netscan_path)

    # Malfind (load any existing malfind results)
    malfind_df = pd.DataFrame()
    malfind_files = list(Path(OUTPUT_DIR).glob("windows_malfind_*.txt"))
    if malfind_files:
        frames = []
        for mf in malfind_files:
            findings = engine.parse_malfind(mf)
            for f in findings:
                # Extract PID from filename pattern: windows_malfind_{PID}.txt
                try:
                    pid = int(mf.stem.split("_")[-1])
                    frames.append({"PID": pid, "Details": f.get("Details", "")})
                except ValueError:
                    pass
        if frames:
            malfind_df = pd.DataFrame(frames)

    # Run correlation engine
    df_ps = correlate_artifacts(df_ps, df_net, malfind_df)

    # Alias for backward compatibility with existing UI code
    if not df_ps.empty and 'correlation_score' in df_ps.columns:
        df_ps['Threat Score'] = df_ps['correlation_score']

    return df_ps, df_net, None

# --- UI Components ---

def render_header():
    """Renders the persistent top header."""
    dump_name = Path(MEMORY_DUMP).name
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M")
    
    html = f"""
    <div class="header-bar">
        <div class="header-title">
            <span>🕵️‍♂️</span> Wako
        </div>
        <div class="header-meta">
            <div class="meta-item"><b>Case ID:</b> {CASE_ID}</div>
            <div class="meta-item"><b>Investigator:</b> {INVESTIGATOR_NAME}</div>
            <div class="meta-item"><b>Evidence:</b> {dump_name}</div>
            <div class="meta-item"><b>Time:</b> {current_time}</div>
        </div>
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)

def render_overview(df_ps, df_net):
    """Renders the investigation overview."""
    st.markdown("## 📊 Investigation Overview")
    
    # 1. Top Cards
    c1, c2, c3, c4 = st.columns(4)
    
    total_procs = len(df_ps) if df_ps is not None else 0
    active_conns = len(df_net) if df_net is not None and not df_net.empty else 0
    
    high_risk = df_ps[df_ps['Threat Score'] >= 3] if df_ps is not None else pd.DataFrame()
    high_risk_count = len(high_risk)
    
    browsers = df_ps[df_ps['ImageFileName'].str.lower().isin(['chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe'])] if df_ps is not None else pd.DataFrame()
    browser_count = len(browsers)

    with c1: st.metric("Total Processes", total_procs, delta="Active", delta_color="normal")
    with c2: st.metric("Network Connections", active_conns, delta="TCP/UDP")
    with c3: st.metric("Threat Alerts", high_risk_count, delta="High Risk", delta_color="inverse")
    with c4: st.metric("Browser Instances", browser_count, delta="Focus")

    st.markdown("---")

    col_main, col_side = st.columns([2, 1])

    with col_main:
        st.markdown('<div class="card-container"><div class="card-header">🛡️ Priority Threats</div>', unsafe_allow_html=True)
        if not high_risk.empty:
            st.dataframe(
                high_risk[['PID', 'ImageFileName', 'Threat Score', 'CreateTime']].style.background_gradient(cmap='Reds', subset=['Threat Score']),
                use_container_width=True,
                hide_index=True
            )
        else:
            st.success("No high-risk threats detected.")
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Gantt Preview
        st.markdown('<div class="card-container"><div class="card-header">⏱️ Activity Timeline Preview</div>', unsafe_allow_html=True)
        if df_ps is not None and 'CreateTime' in df_ps.columns:
             timeline_df = df_ps.sort_values('CreateTime').tail(15) # Last 15 started
             timeline_df['EndTime'] = timeline_df['CreateTime'] + pd.Timedelta(minutes=30)
             fig = px.timeline(timeline_df, x_start="CreateTime", x_end="EndTime", y="ImageFileName", color="Threat Score", color_continuous_scale="RdYlGn_r")
             fig.update_layout(height=300, margin=dict(l=0, r=0, t=0, b=0))
             st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col_side:
        st.markdown('<div class="card-container"><div class="card-header">📈 Distribution</div>', unsafe_allow_html=True)
        if df_ps is not None:
             proc_counts = df_ps['ImageFileName'].value_counts().head(5).reset_index()
             proc_counts.columns = ['Process', 'Count']
             fig_pie = px.donut(proc_counts, values='Count', names='Process', hole=0.6)
             fig_pie.update_layout(showlegend=False, height=250, margin=dict(l=0,r=0,t=0,b=0))
             st.plotly_chart(fig_pie, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

        st.markdown('<div class="card-container"><div class="card-header">⚡ Quick Actions</div>', unsafe_allow_html=True)
        if st.button("Run Auto-Triage", use_container_width=True):
            st.toast("Running automated analysis...")
            # Logic placeholder
        st.markdown('</div>', unsafe_allow_html=True)

def render_process_explorer(df_ps, df_net):
    st.markdown("## 🔭 Process Explorer")
    
    if df_ps is None:
        st.warning("No process data available.")
        return

    # Filter Bar
    c1, c2 = st.columns([3, 1])
    with c1:
        search = st.text_input("🔍 Filter Processes", placeholder="Search by Name or PID...", label_visibility="collapsed")
    with c2:
        filter_risk = st.checkbox("Show Only Risky")

    # Apply Filters
    filtered = df_ps.copy()
    if search:
        filtered = filtered[filtered['ImageFileName'].str.contains(search, case=False) | filtered['PID'].astype(str).str.contains(search)]
    if filter_risk:
        filtered = filtered[filtered['Threat Score'] > 0]

    # Split View
    col_list, col_detail = st.columns([1, 1.5])
    
    selected_pid = None
    with col_list:
        st.markdown('<div class="card-container">', unsafe_allow_html=True)
        st.markdown("#### Process List")
        
        # Use selection from dataframe
        event = st.dataframe(
            filtered[['PID', 'ImageFileName', 'Threat Score']],
            use_container_width=True,
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row"
        )
        
        if event.selection.rows:
            selected_index = event.selection.rows[0]
            selected_pid = filtered.iloc[selected_index]['PID']
        st.markdown('</div>', unsafe_allow_html=True)

    with col_detail:
        if selected_pid:
            row = filtered[filtered['PID'] == selected_pid].iloc[0]
            st.markdown(f"### Process Details: `{row['ImageFileName']}`")
            
            # Details Card
            st.markdown('<div class="card-container">', unsafe_allow_html=True)
            cols = st.columns(3)
            cols[0].metric("PID", row['PID'])
            cols[1].metric("Parent PID", row['PPID'])
            cols[2].metric("Threads", row['Threads'])
            
            st.caption(f"Started: {row['CreateTime']}")
            
            score = row['Threat Score']
            badge_class = "status-success" if score == 0 else "status-warning" if score < 5 else "status-danger"
            badge_text = "CLEAN" if score == 0 else "SUSPICIOUS" if score < 5 else "MALICIOUS"
            st.markdown(f'<span class="status-badge {badge_class}">{badge_text} (Score: {score})</span>', unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)
            
            # Network
            st.markdown("#### Network Activity")
            context = engine.match_process_artifacts(selected_pid, df_net)
            conns = context.get('connections', [])
            if conns:
                st.dataframe(pd.DataFrame(conns)[['Proto', 'LocalAddr', 'ForeignAddr', 'State']], use_container_width=True)
            else:
                st.info("No active network connections.")

            # Actions
            st.markdown("#### Actions")
            if st.button(f"Extract Binary ({selected_pid})"):
                 with st.spinner("Dumping..."):
                     path = engine.run_dump_files(selected_pid)
                     if path: st.success(f"Saved to {path.name}")
        else:
            st.info("👈 Select a process to view details.")

def render_timeline(df_ps):
    st.markdown("## ⏱️ Interactive Timeline")
    
    if df_ps is not None and 'CreateTime' in df_ps.columns:
         df = df_ps.dropna(subset=['CreateTime']).copy().sort_values('CreateTime')
         if db_len := len(df):
             df['EndTime'] = df['CreateTime'] + pd.Timedelta(minutes=30) # Visual duration
             
             fig = px.timeline(
                 df, x_start="CreateTime", x_end="EndTime", y="ImageFileName", 
                 color="Threat Score",
                 hover_data=['PID', 'PPID'],
                 color_continuous_scale="RdYlGn_r",
                 range_color=[0, 10]
             )
             fig.update_layout(height=700, template="plotly_white")
             st.plotly_chart(fig, use_container_width=True)
         else:
             st.warning("No timeline data.")

def render_deep_scan(df_ps):
    st.markdown("## 🧪 Deep Scan Tools")
    
    if df_ps is None: return

    # Tool Selection
    tool = st.radio("Select Tool", ["Malfind (Code Injection)", "YARA Scanner", "DLL Inspector", "Browser Forensics"], horizontal=True)
    st.markdown("---")
    
    # Target Selection
    c1, c2 = st.columns([1, 2])
    with c1:
        # Searchable selectbox
        opts = df_ps.apply(lambda x: f"{x['ImageFileName']} ({x['PID']})", axis=1).tolist()
        target_str = st.selectbox("Select Target Process", opts)
        target_pid = int(target_str.split('(')[1].strip(')')) if target_str else None

    with c2:
        st.info(f"Targeting PID: {target_pid}")
        if not target_pid: st.stop()

        if tool == "Malfind (Code Injection)":
            st.subheader("💉 Malfind Analysis")
            if st.button("Analyze Memory Pages", type="primary"):
                with st.spinner("Scanning for injected code..."):
                    out = engine.run_volatility_pid("windows.malfind", target_pid)
                    findings = engine.parse_malfind(out)
                    if findings:
                        for f in findings:
                            st.warning(f"**{f['Type']}**: {f['Details']}")
                    else:
                        st.success("No injected code signatures found.")

        elif tool == "YARA Scanner":
            st.subheader("🔍 YARA Pattern Match")
            rule = st.text_input("YARA Rule / String", "https://")
            if st.button("Scan Memory Space"):
                 with st.spinner("Scanning..."):
                     matches = engine.run_yara_scan(target_pid, rule)
                     if matches:
                         st.success(f"Found {len(matches)} matches")
                         st.code("\n".join(matches[:20]) + ("\n..." if len(matches) > 20 else ""))
                     else:
                         st.info("No matches.")

        elif tool == "Browser Forensics":
            st.subheader("🌐 Chracer Browser Analysis")
            if st.button("Run Browser Artifact Recovery"):
                with st.spinner("Analyzing..."):
                    out = engine.run_chracer(target_pid)
                    df = engine.parse_chracer_output(out)
                    if not df.empty:
                        st.dataframe(df, use_container_width=True)
                    else:
                        st.warning("No artifacts found or tool failed.")
                        with st.expander("Log"): st.text(out)


def render_network(df_net):
    st.markdown("## 🌐 Global Network Activity")
    
    if df_net is None or df_net.empty:
        st.warning("No network connections found.")
        return

    # Metrics
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Connections", len(df_net))
    c2.metric("Unique Remote IPs", df_net['ForeignAddr'].nunique() if 'ForeignAddr' in df_net.columns else 0)
    c3.metric("Listening Ports", len(df_net[df_net['State'] == 'LISTENING']) if 'State' in df_net.columns else 0)

    st.markdown("---")
    
    # Filters
    st.markdown("#### Filter Connections")
    
    if 'State' in df_net.columns and 'Proto' in df_net.columns:
        c1, c2 = st.columns(2)
        with c1:
            state_filter = st.multiselect("State", df_net['State'].unique(), default=[s for s in ['ESTABLISHED', 'LISTEN'] if s in df_net['State'].unique()])
        with c2:
            proto_filter = st.multiselect("Protocol", df_net['Proto'].unique())

        filtered = df_net.copy()
        if state_filter:
            filtered = filtered[filtered['State'].isin(state_filter)]
        if proto_filter:
            filtered = filtered[filtered['Proto'].isin(proto_filter)]
    else:
        filtered = df_net

    st.dataframe(filtered, use_container_width=True)

def render_artifacts():
    st.markdown("## 🏺 Bulk Artifacts")
    st.caption("Search across all recovered strings, URLs, and IPs.")
    
    url_file = Path(OUTPUT_DIR) / "bulk_extractor_report" / "url.txt"
    
    c1, c2 = st.columns([3, 1])
    with c1:
        query = st.text_input("Global Search", placeholder="e.g. '.onion', 'password'...")
    with c2:
         if st.button("Reload Artifacts"):
             engine.run_bulk_extractor()
             st.rerun()

    if url_file.exists():
        # Lazy load logic for performance
        try:
            df = pd.read_csv(url_file, sep="\t", names=["Offset", "URL"], engine='python', on_bad_lines='skip', nrows=10000)
            if query:
                df = df[df['URL'].str.contains(query, case=False, na=False)]
            
            st.dataframe(df.head(1000), use_container_width=True)
            st.caption(f"Showing {len(df.head(1000))} results.")
        except Exception as e:
            st.error(f"Error reading artifacts: {e}")
    else:
        st.info("Artifacts not extracted yet. Run extraction in 'Overview' or 'Tools'.")

def render_reports(df_ps):
    st.markdown("## 📑 Case Reporting")
    
    with st.container():
        st.markdown('<div class="card-container">', unsafe_allow_html=True)
        st.markdown("### Generate Report")
        notes = st.text_area("Investigator Notes", height=150)
        
        c1, c2 = st.columns(2)
        with c1:
            if st.button("📄 Generate PDF Report", use_container_width=True):
                 if PDF_AVAILABLE:
                     path = Path(OUTPUT_DIR) / "Report.pdf"
                     generate_pdf_report(df_ps, f"Case {CASE_ID}\nNotes: {notes}", str(path))
                     with open(path, "rb") as f:
                         st.download_button("Download PDF", f, "Report.pdf")
                 else:
                     st.error("PDF module missing.")
        
        with c2:
            if st.button("📊 Export Case Data (CSV)", use_container_width=True):
                csv = df_ps.to_csv(index=False).encode('utf-8')
                st.download_button("Download CSV", csv, "case_data.csv", "text/csv")
        st.markdown('</div>', unsafe_allow_html=True)


# --- Main App Logic ---

def main():
    # load_css will be called after retrieving the dark mode state from sidebar
    render_header()
    
    df_ps, df_net, _ = load_data()

    # Sidebar Navigation
    with st.sidebar:
        st.title("Navigation")
        nav = st.radio("Go to:", 
            ["Overview", "Process Explorer", "Network Activity", "Timeline", "Deep Scan", "Artifacts", "Reports"],
            label_visibility="collapsed"
        )
        st.markdown("---")
        is_dark = st.toggle("🌙 Dark Mode", value=st.session_state.get('dark_mode', False), key='dark_mode')
        st.markdown("---")
        st.info(f"System Status: {'🟢 Online' if df_ps is not None else '🔴 Error'}")

    load_css(is_dark)

    # Routing
    if nav == "Overview":
        render_overview(df_ps, df_net)
    elif nav == "Process Explorer":
        render_process_explorer(df_ps, df_net)
    elif nav == "Network Activity":
        render_network(df_net)
    elif nav == "Timeline":
        render_timeline(df_ps)
    elif nav == "Deep Scan":
        render_deep_scan(df_ps)
    elif nav == "Artifacts":
        render_artifacts()
    elif nav == "Reports":
        render_reports(df_ps)

if __name__ == "__main__":
    main()
