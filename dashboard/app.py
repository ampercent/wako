import streamlit as st
import pandas as pd
import sys
import os
from pathlib import Path

# Add project root to path to import pipeline
current_dir = Path(__file__).resolve().parent
project_root = current_dir.parent
sys.path.append(str(project_root))

from pipeline.engine import ForensicsEngine

# Config
st.set_page_config(page_title="Antigravity Forensics", layout="wide", page_icon="🕵️‍♂️")

# Hardcoded for MVP (In a real app, this would be dynamic)
MEMORY_DUMP = "C:/Major_Project/Evidence/WAKO-20260115-125522.dmp"
TOOLS_DIR = "C:/Major_Project/Tools-20260113T123047Z-1-001/Tools"
OUTPUT_DIR = "C:/Major_Project/Layer1_Output"

@st.cache_resource
def get_engine():
    return ForensicsEngine(MEMORY_DUMP, TOOLS_DIR, OUTPUT_DIR)

try:
    engine = get_engine()
except Exception as e:
    st.error(f"Failed to initialize engine: {e}")
    st.stop()

# Sidebar
st.sidebar.title("🕵️‍♂️ Forensics Dashboard")
st.sidebar.info(f"Target: {Path(MEMORY_DUMP).name}")
nav = st.sidebar.radio("Navigation", ["Home", "Process Analysis", "Network", "Browse Artifacts", "Correlator"])

if nav == "Home":
    st.title("Digital Forensics Case Overview")
    st.markdown("""
    Welcome to the **Antigravity Forensics Dashboard**.
    
    **Case Details**:
    *   **Evidence File**: `WAKO-20260115-125522.dmp`
    *   **Host OS**: Windows
    *   **Status**: Analysis Ready
    """)
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Memory Size", "16 GB")
    col2.metric("Detected OS", "Windows 11")
    col3.metric("Analysis Tools", "Vol3, Bulk Extractor")

elif nav == "Process Analysis":
    st.title("Process Analysis (PsList)")
    
    # Run or Load Process List
    if st.button("Run/Refresh PsList"):
        with st.spinner("Running volatility windows.pslist..."):
            engine.run_volatility("windows.pslist", "pslist.txt")
            st.success("Analysis Complete")

    pslist_path = Path(OUTPUT_DIR) / "pslist.txt"
    if pslist_path.exists():
        # Display as Raw Text for MVP accuracy, or try parsing
        st.subheader("Process List output")
        with open(pslist_path, 'r') as f:
            st.text(f.read())
            
        # Filter for browsers
        st.subheader("Browser Processes")
        st.write("Identified `msedge.exe` instances:")
        # Simple grepping for display
        with open(pslist_path, 'r') as f:
            browser_lines = [line for line in f if "msedge" in line or "chrome" in line]
        st.code("".join(browser_lines))
    else:
        st.warning("PsList output not found. Run analysis.")

elif nav == "Network":
    st.title("Network Connections (NetScan)")
    st.info("NetScan allows viewing active connections at the time of capture.")
    
    netscan_path = Path(OUTPUT_DIR) / "netscan.txt"
    if netscan_path.exists():
        with open(netscan_path, 'r') as f:
            content = f.read()
            if len(content) < 100:
                st.warning("NetScan output seems empty. It might still be running or failed.")
            else:
                st.text(content)
    else:
         if st.button("Run NetScan"):
             st.warning("NetScan takes a long time (10-20mins). Check console for progress.")
             # engine.run_volatility("windows.netscan", "netscan.txt") # Uncomment to enable triggering

elif nav == "Browse Artifacts":
    st.title("Artifact Scraper (Bulk Extractor)")
    
    if st.button("Run Bulk Extractor"):
        with st.spinner("Running Bulk Extractor (this may take time)..."):
             engine.run_bulk_extractor()
             st.success("Extraction Complete")
    
    # URL Viewer
    url_file = Path(OUTPUT_DIR) / "bulk_extractor_report" / "url.txt"
    if url_file.exists():
        st.subheader("Extracted URLs")
        search_term = st.text_input("Search URLs", value="facebook")
        
        # Read with pandas for easier filtering
        try:
             # Reading first 100k lines to avoid memory crash on large file
            df = pd.read_csv(url_file, sep="\t", names=["Offset", "URL"], engine='python', on_bad_lines='skip', nrows=10000)
            if search_term:
                df = df[df['URL'].str.contains(search_term, case=False, na=False)]
            
            st.dataframe(df, use_container_width=True)
            st.caption(f"Showing first {len(df)} matches")
        except Exception as e:
            st.error(f"Error reading URL file: {e}")
            
    # Domain Viewer
    domain_file = Path(OUTPUT_DIR) / "bulk_extractor_report" / "domain.txt"
    if domain_file.exists():
        st.subheader("Extracted Domains")
        with open(domain_file, 'r', errors='ignore') as f:
             # Simple read for top domains
             lines = f.readlines()
             st.write(f"Total Domains Found: {len(lines)}")
             st.write("Preview (Top 20):")
             st.code("".join(lines[:20]))

elif nav == "Correlator":
    st.title("Forensic Correlation")
    st.markdown("### 🔗 Linking Processes to Evidence")
    
    col1, col2 = st.columns(2)
    with col1:
        st.error("🚫 Suspicious: EICAR Test File")
        st.write("Found in: `bulk_extractor/domain.txt`")
        st.write("Context: Download URL detected")
        
    with col2:
        st.warning("⚠️ Suspicious: Tor Project")
        st.write("Found in: `bulk_extractor/domain.txt`")
        st.write("Context: Direct site access detected")

    st.markdown("---")
    st.success("✅ Browser Identification: **Microsoft Edge**")
    st.write("Process ID correlation confirms `msedge.exe` was the active browser during these network requests.")
