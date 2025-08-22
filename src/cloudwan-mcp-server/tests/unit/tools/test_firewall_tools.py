import pytest
import json
from unittest.mock import AsyncMock, patch

from awslabs.cloudwan_mcp_server.server import (
    monitor_anfw_logs,
    analyze_anfw_policy,
    analyze_five_tuple_flow,
    parse_suricata_rules,
    simulate_policy_changes,
)


@pytest.mark.asyncio
class TestFirewallTools:
    @patch("boto3.client")
    async def test_monitor_anfw_logs(self, mock_boto_client):
        mock_client = AsyncMock()
        mock_client.filter_log_events.return_value = {"events": [{"id": 1, "message": "allow"}]}
        mock_boto_client.return_value = mock_client

        result = await monitor_anfw_logs("fw1")
        data = json.loads(result)
        assert data["success"]
        assert data["firewall_name"] == "fw1"
        assert len(data["log_events"]) > 0

    @patch("boto3.client")
    async def test_analyze_anfw_policy(self, mock_boto_client):
        mock_client = AsyncMock()
        mock_client.describe_firewall_policy.return_value = {
            "FirewallPolicy": {"FirewallPolicyArn": "arn:fw:123", "StatelessRuleGroupReferences": []}
        }
        mock_boto_client.return_value = mock_client
        result = await analyze_anfw_policy("arn:fw:123")
        data = json.loads(result)
        assert data["success"]
        assert data["policy_arn"] == "arn:fw:123"

    async def test_analyze_five_tuple_flow_valid(self):
        result = await analyze_five_tuple_flow("1.1.1.1", "2.2.2.2", 123, 80, "TCP")
        data = json.loads(result)
        assert data["success"]
        assert data["five_tuple"]["protocol"] == "TCP"

    async def test_analyze_five_tuple_flow_invalid(self):
        result = await analyze_five_tuple_flow("bad_ip", "2.2.2.2", 123, 80, "TCP")
        data = json.loads(result)
        assert data["success"] is False
        assert "error" in data

    async def test_parse_suricata_rules(self):
        rules = 'alert tcp any any -> any any (msg:"test"; sid:1;)'
        result = await parse_suricata_rules(rules)
        data = json.loads(result)
        assert data["total_rules"] == 1
        assert data["valid_rules"] == 1

    async def test_simulate_policy_changes(self):
        result = await simulate_policy_changes("{}", "{}")
        data = json.loads(result)
        assert data["success"]
        assert data["simulation"]["policy_valid"]
