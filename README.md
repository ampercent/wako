# Wako Forensics Pipeline

## Project Overview
**Wako Forensics** is an end-to-end memory forensics analysis pipeline designed to investigate browser-based cybercrime. It specifically targets volatile memory dumps (`.dmp`) to extract artifacts like:
* Running Processes (Browsers)
* Network Connections
* Opened URLs and Domain History
* Suspicious Indicators (Phishing, Malware)

The project wraps standard CLI forensic tools (Volatility 3, Bulk Extractor) into a unified Python engine and presents findings via a Streamlit Dashboard for investigators.

## Setup & Installation

### Prerequisites
* Python 3.10+
* Windows (Host OS) or Linux
* Administrator Privileges (for tool execution)

### 1. Installation
Run the following commands in PowerShell:

```powershell
pip install -r requirements.txt
```

### 2. Running the Dashboard
```powershell
streamlit run dashboard/app.py
```
This will launch the GUI at `http://localhost:8501`.

## Methodology
The pipeline involves the following core steps:
1. **Memory Acquisition**: Extracting volatile memory into raw `.dmp` files.
2. **Process Analysis**: Identifying browser processes and suspicious scripts.
3. **Network Correlation**: Mapping process IDs to active connections.
4. **Artifact Scraping**: Recovering URLs and Domain names from unallocated space.

## Limitations
* Large memory dumps require significant processing time.
* HTTPS traffic content cannot be decrypted, but DNS/SNI artifacts remain visible.
