"""
Plugin Base — Abstract interface and registry for forensic tools.
===================================================================
Provides the ``ToolPlugin`` ABC that all tool adapters must implement,
and a ``PluginRegistry`` for discovery and management.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import pandas as pd

logger = logging.getLogger(__name__)


class ToolPlugin(ABC):
    """
    Abstract base class for forensic tool plugins.

    Every tool adapter (Volatility, Bulk Extractor, Chracer, etc.)
    must implement this interface to participate in the pipeline.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for the plugin (e.g., ``'volatility'``)."""
        ...

    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version string."""
        ...

    @property
    def description(self) -> str:
        """Optional human-readable description."""
        return ""

    @abstractmethod
    def run(self, dump_path: str, **kwargs: Any) -> Any:
        """
        Execute the tool against a memory dump.

        Parameters
        ----------
        dump_path : str
            Path to the memory dump file.
        **kwargs
            Tool-specific options (e.g., plugin name, PID).

        Returns
        -------
        Any
            Raw tool output (file path, stdout string, etc.).
        """
        ...

    @abstractmethod
    def parse(self, output: Any) -> Dict[str, Any]:
        """
        Parse raw tool output into structured data.

        Parameters
        ----------
        output : Any
            Raw output from :meth:`run`.

        Returns
        -------
        dict
            Parsed data in a tool-specific structure.
        """
        ...

    @abstractmethod
    def to_dataframe(self, parsed: Dict[str, Any]) -> pd.DataFrame:
        """
        Convert parsed data into a standardized DataFrame.

        Parameters
        ----------
        parsed : dict
            Output of :meth:`parse`.

        Returns
        -------
        pd.DataFrame
            Tabular representation of the tool's findings.
        """
        ...


class PluginRegistry:
    """
    Registry for discovering and managing tool plugins.

    Usage::

        registry = PluginRegistry()
        registry.register(VolatilityPlugin())
        registry.register(ChracerPlugin())

        plugin = registry.get_plugin("volatility")
        result = plugin.run(dump_path)
    """

    def __init__(self) -> None:
        self._plugins: Dict[str, ToolPlugin] = {}

    def register(self, plugin: ToolPlugin) -> None:
        """
        Register a plugin instance.

        Parameters
        ----------
        plugin : ToolPlugin
            Must have a unique ``name`` property.

        Raises
        ------
        ValueError
            If a plugin with the same name is already registered.
        """
        if plugin.name in self._plugins:
            raise ValueError(f"Plugin '{plugin.name}' is already registered.")
        self._plugins[plugin.name] = plugin
        logger.info(f"Registered plugin: {plugin.name} v{plugin.version}")

    def get_plugin(self, name: str) -> Optional[ToolPlugin]:
        """Retrieve a plugin by name, or ``None`` if not found."""
        return self._plugins.get(name)

    def list_plugins(self) -> List[Dict[str, str]]:
        """Return metadata for all registered plugins."""
        return [
            {
                "name": p.name,
                "version": p.version,
                "description": p.description,
            }
            for p in self._plugins.values()
        ]

    def has_plugin(self, name: str) -> bool:
        """Check if a plugin is registered."""
        return name in self._plugins

    @property
    def count(self) -> int:
        """Number of registered plugins."""
        return len(self._plugins)
