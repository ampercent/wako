"""
Tests for the Plugin System (Phase 5).
Run with: python -m pytest tests/test_plugins.py -v
"""

import pandas as pd
import pytest

from core.plugins.base import PluginRegistry, ToolPlugin


# ---------------------------------------------------------------------------
# Mock plugin for testing
# ---------------------------------------------------------------------------

class MockPlugin(ToolPlugin):
    """A minimal plugin implementation for testing."""

    @property
    def name(self) -> str:
        return "mock_tool"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "A mock forensic tool for testing."

    def run(self, dump_path: str, **kwargs):
        return {"raw": f"output for {dump_path}", "extra": kwargs}

    def parse(self, output):
        return {"parsed": output.get("raw", ""), "metadata": {}}

    def to_dataframe(self, parsed):
        return pd.DataFrame([{"result": parsed.get("parsed", "")}])


class AnotherPlugin(ToolPlugin):
    """Second mock plugin to test registry with multiple plugins."""

    @property
    def name(self) -> str:
        return "another_tool"

    @property
    def version(self) -> str:
        return "2.0"

    def run(self, dump_path: str, **kwargs):
        return "raw output"

    def parse(self, output):
        return {"data": output}

    def to_dataframe(self, parsed):
        return pd.DataFrame()


# ---------------------------------------------------------------------------
# PluginRegistry tests
# ---------------------------------------------------------------------------

class TestPluginRegistry:
    """Tests for the plugin registry."""

    def test_register_plugin(self):
        """Plugin registration works."""
        registry = PluginRegistry()
        plugin = MockPlugin()
        registry.register(plugin)
        assert registry.count == 1
        assert registry.has_plugin("mock_tool")

    def test_get_plugin(self):
        """Registered plugin can be retrieved by name."""
        registry = PluginRegistry()
        plugin = MockPlugin()
        registry.register(plugin)

        retrieved = registry.get_plugin("mock_tool")
        assert retrieved is not None
        assert retrieved.name == "mock_tool"
        assert retrieved.version == "1.0.0"

    def test_get_nonexistent_plugin(self):
        """Non-existent plugin returns None."""
        registry = PluginRegistry()
        assert registry.get_plugin("nonexistent") is None

    def test_duplicate_registration_fails(self):
        """Registering the same plugin name twice raises ValueError."""
        registry = PluginRegistry()
        registry.register(MockPlugin())
        with pytest.raises(ValueError, match="already registered"):
            registry.register(MockPlugin())

    def test_list_plugins(self):
        """List returns metadata for all registered plugins."""
        registry = PluginRegistry()
        registry.register(MockPlugin())
        registry.register(AnotherPlugin())

        plugins = registry.list_plugins()
        assert len(plugins) == 2
        names = {p["name"] for p in plugins}
        assert names == {"mock_tool", "another_tool"}

    def test_list_plugin_metadata(self):
        """Plugin metadata includes name, version, and description."""
        registry = PluginRegistry()
        registry.register(MockPlugin())

        info = registry.list_plugins()[0]
        assert info["name"] == "mock_tool"
        assert info["version"] == "1.0.0"
        assert info["description"] == "A mock forensic tool for testing."

    def test_has_plugin(self):
        """has_plugin returns correct boolean."""
        registry = PluginRegistry()
        assert registry.has_plugin("mock_tool") is False
        registry.register(MockPlugin())
        assert registry.has_plugin("mock_tool") is True


# ---------------------------------------------------------------------------
# Plugin interface tests
# ---------------------------------------------------------------------------

class TestPluginInterface:
    """Tests for the ToolPlugin ABC methods."""

    def test_run(self):
        """Plugin run returns raw output."""
        plugin = MockPlugin()
        output = plugin.run("/test/dump.dmp", pid=1234)
        assert output["raw"] == "output for /test/dump.dmp"
        assert output["extra"]["pid"] == 1234

    def test_parse(self):
        """Plugin parse processes raw output."""
        plugin = MockPlugin()
        raw = plugin.run("/test/dump.dmp")
        parsed = plugin.parse(raw)
        assert "parsed" in parsed

    def test_to_dataframe(self):
        """Plugin to_dataframe returns a valid DataFrame."""
        plugin = MockPlugin()
        raw = plugin.run("/test/dump.dmp")
        parsed = plugin.parse(raw)
        df = plugin.to_dataframe(parsed)
        assert isinstance(df, pd.DataFrame)
        assert not df.empty

    def test_full_pipeline(self):
        """run → parse → to_dataframe produces valid output."""
        plugin = MockPlugin()
        raw = plugin.run("/test/dump.dmp")
        parsed = plugin.parse(raw)
        df = plugin.to_dataframe(parsed)
        assert len(df) == 1
        assert "result" in df.columns


# ---------------------------------------------------------------------------
# Real plugin import tests
# ---------------------------------------------------------------------------

class TestRealPluginImports:
    """Verify real plugin adapters can be imported."""

    def test_import_volatility_plugin(self):
        from core.plugins.volatility import VolatilityPlugin
        plugin = VolatilityPlugin()
        assert plugin.name == "volatility"
        assert plugin.version == "3.0"

    def test_import_bulk_extractor_plugin(self):
        from core.plugins.bulk_extractor import BulkExtractorPlugin
        plugin = BulkExtractorPlugin()
        assert plugin.name == "bulk_extractor"

    def test_import_chracer_plugin(self):
        from core.plugins.chracer import ChracerPlugin
        plugin = ChracerPlugin()
        assert plugin.name == "chracer"
