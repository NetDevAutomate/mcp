import pytest
import json
from awslabs.cloudwan_mcp_server.server import (
    analyze_iac_firewall_policy,
    simulate_iac_firewall_traffic,
    validate_iac_firewall_syntax,
)


@pytest.mark.asyncio
class TestIaCTools:
    async def test_analyze_iac_firewall_policy(self):
        result = await analyze_iac_firewall_policy("resource {}", "terraform")
        data = json.loads(result)
        assert data["success"]
        assert "analysis" in data

    async def test_simulate_iac_firewall_traffic(self):
        result = await simulate_iac_firewall_traffic("content", "flows")
        data = json.loads(result)
        assert data["success"]
        assert data["simulation"]["flows_tested"] == 3

    async def test_validate_iac_firewall_syntax(self):
        result = await validate_iac_firewall_syntax("line1\nline2", "terraform")
        data = json.loads(result)
        assert data["success"]
        assert data["validation"]["syntax_valid"]
        assert data["validation"]["line_count"] == 2
        assert data["validation"]["format_valid"] is True
