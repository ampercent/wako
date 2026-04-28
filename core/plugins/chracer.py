"""
Chracer Plugin — Adapter for the Chracer browser forensics tool.
===================================================================
Wraps the existing ForensicsEngine Chracer methods
into the ToolPlugin interface.
"""

import logging
from pathlib import Path
from typing import Any, Dict

import pandas as pd

from .base import ToolPlugin

logger = logging.getLogger(__name__)


class ChracerPlugin(ToolPlugin):
    """
    Plugin adapter for Chracer browser forensics tool.

    Parameters
    ----------
    tools_dir : str
        Path to the tools directory containing the Chracer scripts.
    output_dir : str
        Path where output files are stored.
    """

    def __init__(self, tools_dir: str = "", output_dir: str = "") -> None:
        self._tools_dir = tools_dir
        self._output_dir = output_dir
        self._engine = None

    @property
    def name(self) -> str:
        return "chracer"

    @property
    def version(self) -> str:
        return "1.0"

    @property
    def description(self) -> str:
        return "Chracer — browser session forensics tool for Chrome-based process dumps."

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
        Execute Chracer on a specific process.

        Parameters
        ----------
        dump_path : str
            Path to the memory dump file.
        pid : int
            Target process ID for browser session extraction.

        Returns
        -------
        str
            Raw Chracer output string.
        """
        pid = kwargs.get("pid")
        if pid is None:
            return "Error: PID is required for Chracer analysis."

        engine = self._get_engine(dump_path)
        if engine is None:
            return "Error: ForensicsEngine not available."

        try:
            return engine.run_chracer(pid)
        except Exception as e:
            logger.error(f"Chracer failed for PID {pid}: {e}")
            return f"Error: {e}"

    def parse(self, output: Any) -> Dict[str, Any]:
        """
        Parse Chracer ASCII table output.

        Parameters
        ----------
        output : str
            Raw Chracer stdout string.

        Returns
        -------
        dict
            Keys: ``"sessions"`` (list of session dicts).
        """
        if not output or str(output).startswith("Error"):
            return {"sessions": [], "error": str(output)}

        try:
            from pipeline.engine import ForensicsEngine
            # Use a detached engine instance for parsing only
            engine = ForensicsEngine.__new__(ForensicsEngine)
            df = engine.parse_chracer_output(str(output))
            return {"sessions": df.to_dict(orient="records") if not df.empty else []}
        except Exception as e:
            logger.error(f"Failed to parse Chracer output: {e}")
            return {"sessions": [], "error": str(e)}

    def to_dataframe(self, parsed: Dict[str, Any]) -> pd.DataFrame:
        """Convert parsed Chracer sessions to a DataFrame."""
        data = parsed.get("sessions", [])
        if not data:
            return pd.DataFrame()
        return pd.DataFrame(data)
