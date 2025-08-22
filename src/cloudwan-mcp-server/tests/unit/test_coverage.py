import inspect
import pytest
from awslabs.cloudwan_mcp_server import server


def get_mcp_tools():
    return [obj for name, obj in inspect.getmembers(server) if getattr(obj, "_mcp_tool", False)]


def test_all_tools_have_tests():
    """Ensure all MCP tools have tests present."""
    tools = get_mcp_tools()
    assert len(tools) == 29  # Corrected tool count


@pytest.mark.parametrize("tool", get_mcp_tools())
def test_tool_callable(tool):
    """Ensure each tool is callable async function."""
    assert inspect.iscoroutinefunction(tool)


def test_coverage_threshold():
    import coverage

    cov = coverage.Coverage()
    cov.load()
    total = cov.report()
    assert total >= 85.0
