"""
Bulk Extractor Plugin — Adapter for the bulk_extractor tool.
===============================================================
Wraps the existing ForensicsEngine bulk extractor methods
into the ToolPlugin interface.
"""

import logging
from pathlib import Path
from typing import Any, Dict

import pandas as pd

from .base import ToolPlugin

logger = logging.getLogger(__name__)


class BulkExtractorPlugin(ToolPlugin):
    """
    Plugin adapter for bulk_extractor.

    Parameters
    ----------
    tools_dir : str
        Path to the tools directory containing bulk_extractor binary.
    output_dir : str
        Path where output reports are stored.
    """

    def __init__(self, tools_dir: str = "", output_dir: str = "") -> None:
        self._tools_dir = tools_dir
        self._output_dir = output_dir
        self._engine = None

    @property
    def name(self) -> str:
        return "bulk_extractor"

    @property
    def version(self) -> str:
        return "2.0"

    @property
    def description(self) -> str:
        return "bulk_extractor — extracts URLs, email addresses, and other artifacts from memory images."

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
        Execute bulk_extractor against a memory dump.

        Returns
        -------
        Path or None
            Path to the report directory.
        """
        engine = self._get_engine(dump_path)
        if engine is None:
            logger.error("ForensicsEngine not available")
            return None

        try:
            return engine.run_bulk_extractor()
        except Exception as e:
            logger.error(f"bulk_extractor failed: {e}")
            return None

    def parse(self, output: Any) -> Dict[str, Any]:
        """
        Parse bulk_extractor report directory.

        Parameters
        ----------
        output : Path
            Report directory path.

        Returns
        -------
        dict
            Keys: ``"urls"`` (list of dicts), ``"report_dir"`` (str).
        """
        if output is None or not Path(output).exists():
            return {"urls": [], "report_dir": ""}

        report_dir = Path(output)
        url_file = report_dir / "url.txt"

        urls = []
        if url_file.exists():
            try:
                df = pd.read_csv(
                    url_file, sep="\t",
                    names=["Offset", "URL"],
                    engine="python",
                    on_bad_lines="skip",
                    nrows=500,
                )
                urls = df.to_dict(orient="records")
            except Exception as e:
                logger.warning(f"Failed to parse URL file: {e}")

        return {"urls": urls, "report_dir": str(report_dir)}

    def to_dataframe(self, parsed: Dict[str, Any]) -> pd.DataFrame:
        """Convert parsed bulk_extractor URLs to a DataFrame."""
        data = parsed.get("urls", [])
        if not data:
            return pd.DataFrame()
        return pd.DataFrame(data)
