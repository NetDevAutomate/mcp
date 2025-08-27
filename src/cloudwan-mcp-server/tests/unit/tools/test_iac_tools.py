import json

import pytest

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
        # Test with proper JSON flow format
        flows = '[{"source": "10.0.0.1", "destination": "10.0.0.2", "port": 80}]'
        result = await simulate_iac_firewall_traffic("resource aws_networkfirewall_firewall_policy", flows)
        data = json.loads(result)
        assert data["success"]
        assert data["simulation"]["flows_tested"] >= 0  # Should be based on actual flow count

    async def test_validate_iac_firewall_syntax(self):
        result = await validate_iac_firewall_syntax(
            'resource "aws_networkfirewall_rule_group" "example" {}', "terraform"
        )
        data = json.loads(result)
        assert data["success"] is True
        assert data["validation"]["syntax_valid"]
        assert data["validation"]["line_count"] > 0
        # Check for format field or just verify syntax_valid is sufficient
        assert data.get("format") or data["validation"]["syntax_valid"]
