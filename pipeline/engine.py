import os
import subprocess
import json
import logging
from pathlib import Path
import pandas as pd
from datetime import datetime
import re

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ForensicsEngine:
    def __init__(self, memory_dump_path: str, tools_dir: str, output_dir: str):
        self.memory_dump = Path(memory_dump_path).resolve()
        self.tools_dir = Path(tools_dir).resolve()
        self.output_dir = Path(output_dir).resolve()
        
        # Determine Tool Paths
        self.vol_script = self.tools_dir / "volatility3" / "vol.py"
        self.bulk_extractor_exe = self.tools_dir / "bulk_extractor" / "win64" / "bulk_extractor64.exe"
        if not self.bulk_extractor_exe.exists():
             self.bulk_extractor_exe = self.tools_dir / "bulk_extractor" / "bulk_extractor.exe"

        # Validate Paths
        if not self.memory_dump.exists():
            raise FileNotFoundError(f"Memory dump not found: {self.memory_dump}")
        if not self.vol_script.exists():
            raise FileNotFoundError(f"Volatility script not found: {self.vol_script}")

        # Ensure Output Directory
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run_volatility(self, plugin: str, output_name: str = None) -> Path:
        """Runs a Volatility 3 plugin and returns the path to the output file."""
        if output_name is None:
            output_name = f"{plugin.replace('.', '_')}.json"
        
        output_file = self.output_dir / output_name
        logger.info(f"Running Volatility Plugin: {plugin}")

        # Construct Command (Output as JSON for easy parsing)
        # Note: Volatility 3 JSON output might need specific handling/parsing
        cmd = [
            "python", str(self.vol_script), 
            "-f", str(self.memory_dump), 
            "-r", "pretty", # Use pretty renderer for text, or 'json' if supported cleanly
            plugin
        ]

        # For this engine, we prefer JSON if possible, but Volatility 3 CLI JSON support varies.
        # We'll use the default renderer and parse text, OR try -r json if robust.
        # Let's stick to capturing stdout and saving it.
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            with open(output_file, "w", encoding='utf-8') as f:
                f.write(result.stdout)
            logger.info(f"Saved {plugin} output to {output_file}")
            return output_file
        except subprocess.CalledProcessError as e:
            logger.error(f"Volatility failed for {plugin}: {e.stderr}")
            raise

    def run_bulk_extractor(self) -> Path:
        """Runs Bulk Extractor."""
        report_dir = self.output_dir / "bulk_extractor_report"
        if report_dir.exists():
            logger.info("Bulk Extractor report directory exists. Skipping run to save time.")
            return report_dir
        
        logger.info("Starting Bulk Extractor...")
        cmd = [
            str(self.bulk_extractor_exe),
            "-o", str(report_dir),
            str(self.memory_dump)
        ]

        try:
            subprocess.run(cmd, check=True)
            logger.info("Bulk Extractor finished.")
            return report_dir
        except subprocess.CalledProcessError as e:
            logger.error(f"Bulk Extractor failed: {e}")
            raise

    def parse_pslist(self, pslist_file: Path) -> pd.DataFrame:
        """Parses pslist text output into a DataFrame."""
        try:
            lines = []
            with open(pslist_file, 'r', encoding='utf-8') as f:
                raw_lines = f.readlines()

            for line in raw_lines:
                parts = line.split()
                # Must have enough parts and start with a PID
                if len(parts) >= 8 and parts[0].isdigit():
                    try:
                        # Dynamic parsing based on '0x' Offset anchor
                        # Vol3 Format: PID PPID ImageFileName Offset Threads Handles SessionId Wow64 CreateTime ExitTime Output
                        
                        # Find the index of the Offset column (starts with 0x)
                        offset_idx = next((i for i, p in enumerate(parts) if p.startswith('0x')), -1)
                        
                        if offset_idx > 2:
                            # Extract extracted fields relative to anchors
                            pid = int(parts[0])
                            ppid = int(parts[1])
                            
                            # ImageFileName might contain spaces, so it's everything between PPID and Offset
                            image_name = " ".join(parts[2:offset_idx])
                            
                            offset = parts[offset_idx]
                            threads = int(parts[offset_idx+1]) if parts[offset_idx+1].isdigit() else 0
                            handles = int(parts[offset_idx+2]) if parts[offset_idx+2].isdigit() else 0
                            session_id = parts[offset_idx+3]
                            wow64 = parts[offset_idx+4]
                            
                            # CreateTime (Date + Time)
                            create_time_str = f"{parts[offset_idx+5]} {parts[offset_idx+6]}"
                            
                            row = {
                                "PID": pid,
                                "PPID": ppid,
                                "ImageFileName": image_name,
                                "Offset": offset,
                                "Threads": threads,
                                "Handles": handles,
                                "SessionId": session_id,
                                "Wow64": wow64,
                                "CreateTime": create_time_str,
                                "Threat Score": 0 # Default
                            }
                            lines.append(row)
                    except (ValueError, IndexError):
                        continue # Skip malformed lines gracefully
            
            df = pd.DataFrame(lines)
            
            # Convert CreateTime to datetime objects
            if not df.empty and "CreateTime" in df.columns:
                df['CreateTime'] = pd.to_datetime(df['CreateTime'], errors='coerce')

            return df
        except Exception as e:
            logger.warning(f"Failed to parse pslist strictly: {e}")
            # Return empty DF with expected columns to prevent KeyErrors
            return pd.DataFrame(columns=["PID", "PPID", "ImageFileName", "Threat Score", "CreateTime"])

    def parse_netscan(self, netscan_file: Path) -> pd.DataFrame:
        """Parses netscan text output into a DataFrame."""
        try:
            lines = []
            with open(netscan_file, 'r', encoding='utf-8') as f:
                raw_lines = f.readlines()

            for line in raw_lines:
                parts = line.split()
                # Vol3 Netscan columns: Offset, Proto, LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner, Created
                # This often varies, so we look for lines ending in valid states or PIDs
                if len(parts) >= 5 and parts[0].isalnum(): # Offset usually hex
                     # Heuristic parsing
                     # Look for Proto (TCP/UDP)
                     if parts[1] in ['TCPv4', 'TCPv6', 'UDPv4', 'UDPv6']:
                         row = {
                             "Proto": parts[1],
                             "LocalAddr": parts[2],
                             "ForeignAddr": parts[3],
                             "State": parts[4] if parts[1].startswith('TCP') else "N/A",
                             "PID": parts[-2] if parts[-2].isdigit() else None, 
                             "Owner": parts[-1],
                             "Raw": line.strip()
                         }
                         if row["PID"]:
                             try:
                                 row["PID"] = int(row["PID"])
                                 lines.append(row)
                             except ValueError:
                                 pass
            
            return pd.DataFrame(lines)
        except Exception as e:
            logger.warning(f"Failed to parse netscan: {e}")
            return pd.DataFrame()

    def calculate_threat_score(self, row, artifacts_df=None):
        """Calculates a threat score for a process based on attributes and derived artifacts."""
        score = 0
        reasons = []

        # 1. Suspicious Process Names
        suspicious_names = ["powershell.exe", "cmd.exe", "netcat.exe", "ncat.exe"]
        if row['ImageFileName'].lower() in suspicious_names:
            score += 2
            reasons.append(f"Suspicious Process: {row['ImageFileName']}")

        # 2. Browser Processes (Moderate interest, but not inherently malicious unless correlated)
        browsers = ["msedge.exe", "chrome.exe", "firefox.exe"]
        if row['ImageFileName'].lower() in browsers:
            score += 0 # Browsers are normal, but we watch them. 
        
        # 3. Network Correlation (if available in row context or external lookup)
        # Note: This simple scoring is row-local unless we pass full context.
        # We will enhance this in the dataframe apply context in app.py or here if passed merged data.
        
        return score, reasons

    def match_process_artifacts(self, pid: int, netscan_df: pd.DataFrame) -> dict:
        """Finds network connections and potential artifacts for a PID."""
        context = {
            "connections": [],
            "artifacts": []
        }
        
        # 1. Network Connections
        if not netscan_df.empty and "PID" in netscan_df.columns:
            conns = netscan_df[netscan_df['PID'] == pid]
            if not conns.empty:
                context['connections'] = conns.to_dict('records')
        
        return context

    def parse_bulk_urls(self, url_file: Path) -> pd.DataFrame:
        """Parses extracted URLs."""
        try:
            # bulk_extractor url.txt format: Offset URL
            df = pd.read_csv(url_file, sep="\t", names=["Offset", "URL"], engine='python', on_bad_lines='skip')
            return df
        except Exception as e:
             logger.warning(f"Failed to parse URL file: {e}")
             return pd.DataFrame()

    def run_volatility_pid(self, plugin: str, pid: int, output_name: str = None) -> Path:
        """Runs a Volatility 3 plugin for a specific PID."""
        if output_name is None:
            output_name = f"{plugin.replace('.', '_')}_{pid}.txt"
        
        output_file = self.output_dir / output_name
        logger.info(f"Running Layer 2 {plugin} on PID {pid}")

        cmd = [
            "python", str(self.vol_script), 
            "-f", str(self.memory_dump), 
            "-r", "pretty",
            plugin,
            "--pid", str(pid)
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            with open(output_file, "w", encoding='utf-8') as f:
                f.write(result.stdout)
            return output_file
        except subprocess.CalledProcessError as e:
            logger.error(f"Layer 2 failed for {plugin} PID {pid}: {e.stderr}")
            return None

    def parse_malfind(self, file_path: Path) -> list:
        """Parses malfind output for injected code indicators."""
        findings = []
        if not file_path or not file_path.exists():
            return findings

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Simple heuristic: Split by block headers usually containing "PID:"
            # Vol3 malfind pretty output structure:
            # PID     Process     Start VPN    End VPN      Tag ... Protection
            # ... Hex dump ...
            
            # We look for lines containing "PAGE_EXECUTE_READWRITE" (RWX) which is highly suspicious
            lines = content.split('\n')
            for line in lines:
                if "PAGE_EXECUTE_READWRITE" in line:
                    findings.append({
                        "Type": "RWX Memory Region",
                        "Details": line.strip(),
                        "Severity": "High"
                    })
        except Exception as e:
            logger.error(f"Error parsing malfind: {e}")
        
        return findings

    def parse_dlllist(self, file_path: Path) -> list:
        """Parses dlllist output."""
        dlls = []
        if not file_path or not file_path.exists():
            return dlls
            
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Skip headers etc.
            # Vol3 dlllist: PID ... Base ... Size ... Path
            for line in lines:
                parts = line.split()
                if len(parts) > 4 and "0x" in line:
                    # Heuristic to find path
                    # Usually path is the last part(s)
                    path = parts[-1]
                    if "\\" in path or "/" in path:
                         dlls.append(path)
        except Exception as e:
             logger.error(f"Error parsing dlllist: {e}")
             
        return dlls

    def run_dump_files(self, pid: int) -> Path:
        """Runs windows.dumpfiles to extract the process binary."""
        # Output directory for dumps
        dump_dir = self.output_dir / "dumps" / f"pid_{pid}"
        dump_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Dumping memory for PID {pid}...")
        
        cmd = [
            "python", str(self.vol_script), 
            "-f", str(self.memory_dump), 
            "-o", str(dump_dir),
            "windows.dumpfiles",
            "--pid", str(pid)
        ]

        try:
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            # Find the executable dump (usually ends in .img or .dat depending on Vol3 version, usually implies .exe)
            # Vol3 dumpfiles naming: file.<pid>.<address>.<ext>
            # We look for the main image.
            for f in dump_dir.iterdir():
                if f.suffix in ['.exe', '.dll', '.img', '.dat']:
                     return f
            return None
        except subprocess.CalledProcessError as e:
            logger.error(f"Dump failed for PID {pid}: {e.stderr}")
            return None

    def run_yara_scan(self, pid: int, yara_string: str) -> list:
        """Scan process memory for a specific string (YARA-like simple search)."""
        output_name = f"yara_{pid}_{abs(hash(yara_string))}.txt"
        output_file = self.output_dir / output_name
        
        # We need to construct a valid simple rule on the fly
        rule_content = f'rule search {{ strings: $a = "{yara_string}" condition: $a }}'
        rule_file = self.output_dir / f"temp_rule_{pid}.yar"
        with open(rule_file, "w") as f:
            f.write(rule_content)

        cmd = [
            "python", str(self.vol_script), 
            "-f", str(self.memory_dump), 
            "-r", "pretty",
            "windows.yarascan",
            "--pid", str(pid),
            "--yara-file", str(rule_file)
        ]

        matches = []
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            with open(output_file, "w", encoding='utf-8') as f:
                f.write(result.stdout)
            
            # scalable parsing
            content = result.stdout
            if "Rule:" in content: 
                # Very basic check if any rule matched & extract line
                matches.append(f"Found matches for string: '{yara_string}'")
                lines = content.split('\n')
                for line in lines:
                    if yara_string in line or "0x" in line: # Capture context
                        matches.append(line.strip())
            
            return matches
        except subprocess.CalledProcessError as e:
            logger.error(f"YARA failed for PID {pid}: {e.stderr}")
            return []
        finally:
            if rule_file.exists():
                rule_file.unlink() # cleanup

    def run_chracer(self, pid: int) -> str:
        """Runs the Chracer browser forensics tool on a process dump."""
        # 1. We need a dump file first. Check if one exists or create it.
        # Note: Chracer expects a Minidump. Volatility dumps are raw or PE. 
        # This is best-effort integration.
        
        dump_path = self.run_dump_files(pid)
        if not dump_path:
            return "Error: Could not dump process memory for analysis."

        finder_script = self.tools_dir / "Chracer_Repo" / "finder.py"
        if not finder_script.exists():
            return "Error: Chracer tool not found."

        logger.info(f"Running Chracer on {dump_path}...")
        
        # We need to run it in a subprocess environment where 'chracer' module is available
        # So we set PYTHONPATH
        env = os.environ.copy()
        chracer_root = finder_script.parent
        env["PYTHONPATH"] = str(chracer_root) + os.pathsep + env.get("PYTHONPATH", "")

        cmd = [
            "python", str(finder_script),
            str(dump_path)
        ]

        try:
            # high timeout as Chracer says it's slow
            result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=120)
            
            if result.returncode != 0:
                 logger.warning(f"Chracer exited with code {result.returncode}: {result.stderr}")
                 return f"Chracer Analysis Failed (Exit Code {result.returncode})\n\nOutput:\n{result.stdout}\n\nErrors:\n{result.stderr}"
            
            return result.stdout
        except subprocess.TimeoutExpired:
            return "Error: Chracer timed out (Analysis took too long)."
        except Exception as e:
            return f"Error running Chracer: {e}"

    def parse_chracer_output(self, output: str) -> pd.DataFrame:
        """Parses the ASCII table output from Chracer into a DataFrame."""
        try:
            lines = output.strip().split('\n')
            data = []
            
            # Find the header line (starts with SessionID usually based on finder.py)
            # finder.py: hdr = ['SessionID', 'Tab', 'Time', 'Title', 'URL']
            # tabulate output usually looks like:
            # SessionID    Tab  Time    Title    URL
            # -----------  ---  ------  -------  -----
            
            start_idx = -1
            for i, line in enumerate(lines):
                if "SessionID" in line and "URL" in line:
                    start_idx = i + 2 # Skip header and separator line
                    break
            
            if start_idx == -1:
                return pd.DataFrame()
                
            for line in lines[start_idx:]:
                if not line.strip(): continue
                # Tabulate uses generic spacing, but we can try splitting by multiple spaces
                # This is fragile, but effective for typical tabulate output
                parts = [p.strip() for p in re.split(r'\s{2,}', line.strip())]
                
                if len(parts) >= 5:
                    # Basic mapping
                    sid = parts[0]
                    tab_idx = parts[1]
                    ts = parts[2]
                    title = parts[-2] if len(parts) > 4 else "N/A"
                    url = parts[-1]
                    
                    data.append({
                        "SessionID": sid,
                        "Tab": tab_idx,
                        "Time": ts,
                        "Title": title,
                        "URL": url,
                        "IsIncognito": "Unknown" # Chracer basic output doesn't explicit incognito in finder.py, implied by Session context usually
                    })
                    
            return pd.DataFrame(data)
        except Exception as e:
            logger.error(f"Failed to parse Chracer output: {e}")
            return pd.DataFrame()
