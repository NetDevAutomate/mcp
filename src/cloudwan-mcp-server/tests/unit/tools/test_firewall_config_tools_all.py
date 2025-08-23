"""Comprehensive tests for ALL 6 Firewall + Config tools - Opus 4.1 Specialist Stream."""

import json
from unittest.mock import MagicMock, patch

import pytest

from awslabs.cloudwan_mcp_server.server import (
    analyze_anfw_policy,
    analyze_five_tuple_flow,
    aws_config_manager,
    monitor_anfw_logs,
    parse_suricata_rules,
    simulate_policy_changes,
)


@pytest.mark.asyncio
class TestAllFirewallConfigTools:
    """Comprehensive tests for ALL 6 Firewall + Config tools."""

    # TOOL 1: monitor_anfw_logs
    @patch("awslabs.cloudwan_mcp_server.server.get_aws_client")
    async def test_monitor_anfw_logs_success(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.filter_log_events.return_value = {
            "events": [{"timestamp": 123456, "message": "ALLOW TCP"}]
        }
        mock_get_client.return_value = mock_client
        
        result = await monitor_anfw_logs("test-firewall")
        data = json.loads(result)
        assert data["success"] is True
        assert data["firewall_name"] == "test-firewall"

    # TOOL 2: analyze_anfw_policy
    @patch("awslabs.cloudwan_mcp_server.server.get_aws_client")
    async def test_analyze_anfw_policy_success(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.describe_firewall_policy.return_value = {
            "FirewallPolicy": {"StatelessRuleGroups": []}
        }
        mock_get_client.return_value = mock_client
        
        result = await analyze_anfw_policy("arn:aws:network-firewall::policy/test")
        data = json.loads(result)
        assert data["success"] is True
        assert "policy" in data

    # TOOL 3: analyze_five_tuple_flow
    async def test_analyze_five_tuple_flow_tcp(self):
        result = await analyze_five_tuple_flow("10.0.0.1", "8.8.8.8", 12345, 443, "TCP")
        data = json.loads(result)
        assert data["success"] is True
        assert data["five_tuple"]["protocol"] == "TCP"

    async def test_analyze_five_tuple_flow_invalid_ip(self):
        result = await analyze_five_tuple_flow("invalid", "8.8.8.8", 12345, 443, "TCP")
        data = json.loads(result)
        assert data["success"] is False

    # TOOL 4: parse_suricata_rules
    async def test_parse_suricata_rules_valid(self):
        rules = 'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)'
        result = await parse_suricata_rules(rules)
        data = json.loads(result)
        assert data["success"] is True
        assert data["total_rules"] == 1
        assert data["valid_rules"] == 1

    async def test_parse_suricata_rules_empty(self):
        result = await parse_suricata_rules("")
        data = json.loads(result)
        assert data["success"] is True
        assert data["total_rules"] == 0

    # TOOL 5: simulate_policy_changes
    async def test_simulate_policy_changes_success(self):
        result = await simulate_policy_changes("policy_content", "test_scenarios")
        data = json.loads(result)
        assert data["success"] is True
        assert "simulation" in data

    # TOOL 6: aws_config_manager
    async def test_aws_config_manager_valid_operations(self):
        valid_ops = ["get", "list", "get_profile"]
        for op in valid_ops:
            result = await aws_config_manager(op)
            data = json.loads(result)
            assert data["success"] is True
            assert data["operation"] == op

    async def test_aws_config_manager_invalid_operation(self):
        result = await aws_config_manager("invalid_operation")
        data = json.loads(result)
        assert data["success"] is False
        assert "error" in data