import os
import subprocess
import json
import logging
from pathlib import Path
import pandas as pd

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
        # Simple parser for the standard text output of vol -r pretty
        # Real implementation might need more robust regex or CSV output
        try:
            # Skip header lines and infer structure
            # For robustness in this MVP, we might revert to just reading it as text
            # But let's try to make it structured
            lines = []
            with open(pslist_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip() and not line.startswith("Volatility") and not line.startswith("PID"):
                         parts = line.split()
                         if len(parts) >= 8: # Minimal columns
                             lines.append(parts)
            
            # Create a basic DF (column mapping is approximate for MVP)
            # PID PPID ImageFileName Offset(V) Threads Handles SessionId Wow64 ...
            cols = ["PID", "PPID", "ImageFileName", "Offset", "Threads", "Handles", "SessionId", "Wow64", "CreateTime"]
            df = pd.DataFrame(lines, columns=range(len(lines[0]))) 
            # Slice to first few critical columns
            df = df.iloc[:, :9]
            df.columns = cols
            return df
        except Exception as e:
            logger.warning(f"Failed to parse pslist strictly: {e}")
            return pd.DataFrame() # Return empty on failure for now

    def parse_bulk_urls(self, url_file: Path) -> pd.DataFrame:
        """Parses extracted URLs."""
        try:
            # bulk_extractor url.txt format: Offset URL
            df = pd.read_csv(url_file, sep="\t", names=["Offset", "URL"], engine='python', on_bad_lines='skip')
            return df
        except Exception as e:
             logger.warning(f"Failed to parse URL file: {e}")
             return pd.DataFrame()
