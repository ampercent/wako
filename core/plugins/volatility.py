"""
Volatility Plugin — Adapter for Volatility 3 framework.
==========================================================
Wraps the existing ForensicsEngine methods into the ToolPlugin interface.
Supports pslist, netscan, and malfind sub-plugins.
"""

import logging
from pathlib import Path
from typing import Any, Dict

import pandas as pd

from .base import ToolPlugin

logger = logging.getLogger(__name__)


class VolatilityPlugin(ToolPlugin):
    """
    Plugin adapter for Volatility 3.

    Parameters
    ----------
    tools_dir : str
        Path to the tools directory containing the Volatility script.
    output_dir : str
        Path where Volatility output files are stored.
    """

    def __init__(self, tools_dir: str = "", output_dir: str = "") -> None:
        self._tools_dir = tools_dir
        self._output_dir = output_dir
        self._engine = None

    @property
    def name(self) -> str:
        return "volatility"

    @property
    def version(self) -> str:
        return "3.0"

    @property
    def description(self) -> str:
        return "Volatility 3 memory forensics framework — supports pslist, netscan, malfind plugins."

    def _get_engine(self, dump_path: str):
        """Lazy-initialize the ForensicsEngine."""
        if self._engine is None:
            try:
                from pipeline.engine import ForensicsEngine
                self._engine = ForensicsEngine(
                    dump_path, self._tools_dir, self._output_dir
                )
            except Exception as e:
                logger.warning(f"Could not initialize ForensicsEngine: {e}")
                return None
        return self._engine

    def run(self, dump_path: str, **kwargs: Any) -> Any:
        """
        Execute a Volatility plugin.

        Parameters
        ----------
        dump_path : str
            Path to the memory dump file.
        plugin : str
            Volatility plugin name (e.g., ``"windows.pslist"``).
        output_name : str, optional
            Custom output filename.
        pid : int, optional
            Target PID for PID-specific plugins.

        Returns
        -------
        Path or None
            Path to the output file.
        """
        plugin_name = kwargs.get("plugin", "windows.pslist")
        output_name = kwargs.get("output_name")
        pid = kwargs.get("pid")

        engine = self._get_engine(dump_path)
        if engine is None:
            logger.error("ForensicsEngine not available")
            return None

        if pid is not None:
            return engine.run_volatility_pid(plugin_name, pid, output_name)
        return engine.run_volatility(plugin_name, output_name)

    def parse(self, output: Any) -> Dict[str, Any]:
        """
        Parse Volatility output file into structured data.

        Parameters
        ----------
        output : Path
            Output file path returned by :meth:`run`.

        Returns
        -------
        dict
            Keys: ``"type"`` (pslist/netscan/malfind), ``"data"`` (list of dicts).
        """
        if output is None or not Path(output).exists():
            return {"type": "unknown", "data": []}

        file_path = Path(output)
        file_name = file_path.stem.lower()

        if self._engine is None:
            return {"type": file_name, "data": []}

        if "pslist" in file_name:
            df = self._engine.parse_pslist(file_path)
            return {"type": "pslist", "data": df.to_dict(orient="records") if not df.empty else []}

        if "netscan" in file_name:
            df = self._engine.parse_netscan(file_path)
            return {"type": "netscan", "data": df.to_dict(orient="records") if not df.empty else []}

        if "malfind" in file_name:
            findings = self._engine.parse_malfind(file_path)
            return {"type": "malfind", "data": findings}

        return {"type": file_name, "data": []}

    def to_dataframe(self, parsed: Dict[str, Any]) -> pd.DataFrame:
        """Convert parsed Volatility output to a DataFrame."""
        data = parsed.get("data", [])
        if not data:
            return pd.DataFrame()
        return pd.DataFrame(data)
