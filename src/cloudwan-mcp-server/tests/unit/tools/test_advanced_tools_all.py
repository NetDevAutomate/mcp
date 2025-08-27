"""Comprehensive tests for ALL 7 Advanced tools - GPT-5 Specialist Stream."""

import json

import pytest

from awslabs.cloudwan_mcp_server.server import (
    analyze_iac_firewall_policy,
    analyze_network_function_group,
    get_circuit_breaker_status,
    get_system_resilience_metrics,
    list_network_function_groups,
    simulate_iac_firewall_traffic,
    validate_iac_firewall_syntax,
)


@pytest.mark.asyncio
class TestAllAdvancedTools:
    """Comprehensive tests for ALL 7 Advanced tools."""

    # TOOL 1: get_circuit_breaker_status
    async def test_get_circuit_breaker_status_success(self):
        result = await get_circuit_breaker_status()
        data = json.loads(result)
        assert data["success"] is True
        assert "circuit_breakers" in data
        assert "overall_health" in data

    # TOOL 2: get_system_resilience_metrics
    async def test_get_system_resilience_metrics_success(self):
        result = await get_system_resilience_metrics()
        data = json.loads(result)
        assert data["success"] is True
        assert "metrics" in data
        assert "health_score" in data

    # TOOL 3: analyze_iac_firewall_policy
    async def test_analyze_iac_firewall_policy_terraform(self):
        content = 'resource "aws_networkfirewall_rule_group" "test" {}'
        result = await analyze_iac_firewall_policy(content, "terraform")
        data = json.loads(result)
        assert data["success"] is True
        assert data["format"] == "terraform"
        assert "analysis" in data

    async def test_analyze_iac_firewall_policy_cloudformation(self):
        content = "Resources: NetworkFirewallRuleGroup: Type: AWS::NetworkFirewall::RuleGroup"
        result = await analyze_iac_firewall_policy(content, "cloudformation")
        data = json.loads(result)
        assert data["success"] is True
        assert data["format"] == "cloudformation"

    # TOOL 4: simulate_iac_firewall_traffic
    async def test_simulate_iac_firewall_traffic_success(self):
        content = "firewall_rules = {}"
        test_flows = "tcp:80,443;udp:53"
        result = await simulate_iac_firewall_traffic(content, test_flows)
        data = json.loads(result)
        assert data["success"] is True
        assert "simulation" in data

    async def test_simulate_iac_firewall_traffic_with_format(self):
        content = "Resources: {}"
        test_flows = "http,https"
        result = await simulate_iac_firewall_traffic(content, test_flows, "cloudformation")
        data = json.loads(result)
        assert data["success"] is True
        assert data["format"] == "cloudformation"

    # TOOL 5: validate_iac_firewall_syntax
    async def test_validate_iac_firewall_syntax_valid(self):
        content = "valid terraform content"
        result = await validate_iac_firewall_syntax(content, "terraform")
        data = json.loads(result)
        assert data["success"] is True
        assert data["validation"]["syntax_valid"] is True

    async def test_validate_iac_firewall_syntax_multiline(self):
        content = "line1\\nline2\\nline3"
        result = await validate_iac_firewall_syntax(content)
        data = json.loads(result)
        assert data["success"] is True
        assert data["validation"]["line_count"] >= 1

    # TOOL 6: list_network_function_groups
    async def test_list_network_function_groups_success(self):
        result = await list_network_function_groups()
        data = json.loads(result)
        assert data["success"] is True
        assert "network_function_groups" in data

    async def test_list_network_function_groups_with_region(self):
        result = await list_network_function_groups("us-west-2")
        data = json.loads(result)
        assert data["success"] is True
        assert data["region"] == "us-west-2"

    # TOOL 7: analyze_network_function_group
    async def test_analyze_network_function_group_success(self):
        result = await analyze_network_function_group("test-nfg")
        data = json.loads(result)
        assert data["success"] is True
        assert data["group_name"] == "test-nfg"
        assert "analysis" in data

    async def test_analyze_network_function_group_with_region(self):
        result = await analyze_network_function_group("test-nfg", "eu-west-1")
        data = json.loads(result)
        assert data["success"] is True
        assert data["region"] == "eu-west-1"
