"""Comprehensive tests for ALL 8 Policy + TGW tools - Llama 3.3 405b Specialist Stream."""

import json
from unittest.mock import MagicMock, patch

import pytest

from awslabs.cloudwan_mcp_server.server import (
    analyze_segment_routes,
    analyze_tgw_peers,
    analyze_tgw_routes,
    get_core_network_change_events,
    get_core_network_change_set,
    get_core_network_policy,
    manage_tgw_routes,
    validate_cloudwan_policy,
)


@pytest.mark.asyncio
class TestAllPolicyTGWTools:
    """Comprehensive tests for ALL 8 Policy + TGW tools."""

    # TOOL 1: validate_cloudwan_policy
    async def test_validate_cloudwan_policy_valid(self):
        policy = {"version": "2021.12", "core-network-configuration": {}}
        result = await validate_cloudwan_policy(policy)
        data = json.loads(result)
        assert data["success"] is True
        assert "validation_results" in data

    async def test_validate_cloudwan_policy_invalid(self):
        policy = {}  # Missing required fields
        result = await validate_cloudwan_policy(policy)
        data = json.loads(result)
        assert data["success"] is True  # Server returns success but marks invalid fields

    # TOOL 2: get_core_network_policy
    @patch("awslabs.cloudwan_mcp_server.server.get_aws_client")
    async def test_get_core_network_policy_success(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.get_core_network_policy.return_value = {
            "CoreNetworkPolicy": {"PolicyVersion": "1"}
        }
        mock_get_client.return_value = mock_client
        
        result = await get_core_network_policy("cn-123")
        data = json.loads(result)
        assert data["success"] is True
        assert "policy" in data

    # TOOL 3: get_core_network_change_set
    @patch("awslabs.cloudwan_mcp_server.server.get_aws_client")
    async def test_get_core_network_change_set_success(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.get_core_network_change_set.return_value = {
            "CoreNetworkChanges": [{"ChangeType": "CREATE"}]
        }
        mock_get_client.return_value = mock_client
        
        result = await get_core_network_change_set("cn-123", "pv-1")
        data = json.loads(result)
        assert data["success"] is True
        assert "change_sets" in data

    # TOOL 4: get_core_network_change_events
    @patch("awslabs.cloudwan_mcp_server.server.get_aws_client")
    async def test_get_core_network_change_events_success(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.get_core_network_change_events.return_value = {
            "CoreNetworkChangeEvents": [{"Status": "COMPLETE"}]
        }
        mock_get_client.return_value = mock_client
        
        result = await get_core_network_change_events("cn-123", "pv-1")
        data = json.loads(result)
        assert data["success"] is True
        assert "change_events" in data

    # TOOL 5: analyze_segment_routes
    @patch("awslabs.cloudwan_mcp_server.server.get_aws_client")
    async def test_analyze_segment_routes_success(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.get_core_network_policy.return_value = {
            "CoreNetworkPolicy": {"PolicyVersionId": "1"}
        }
        mock_get_client.return_value = mock_client
        
        result = await analyze_segment_routes("cn-123", "prod")
        data = json.loads(result)
        assert data["success"] is True
        assert "analysis" in data

    # TOOL 6: manage_tgw_routes
    async def test_manage_tgw_routes_create(self):
        result = await manage_tgw_routes("create", "rtb-123", "10.0.0.0/16")
        data = json.loads(result)
        assert data["success"] is True
        assert data["operation"] == "create"
        assert data["destination_cidr"] == "10.0.0.0/16"

    async def test_manage_tgw_routes_invalid_cidr(self):
        result = await manage_tgw_routes("create", "rtb-123", "invalid-cidr")
        data = json.loads(result)
        assert data["success"] is False

    # TOOL 7: analyze_tgw_routes
    @patch("awslabs.cloudwan_mcp_server.server.get_aws_client")
    async def test_analyze_tgw_routes_success(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.search_transit_gateway_routes.return_value = {
            "Routes": [{"DestinationCidrBlock": "10.0.0.0/16", "State": "active"}]
        }
        mock_get_client.return_value = mock_client
        
        result = await analyze_tgw_routes("rtb-123")
        data = json.loads(result)
        assert data["success"] is True
        assert "analysis" in data

    # TOOL 8: analyze_tgw_peers
    @patch("awslabs.cloudwan_mcp_server.server.get_aws_client")
    async def test_analyze_tgw_peers_success(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.describe_transit_gateway_peering_attachments.return_value = {
            "TransitGatewayPeeringAttachments": [{"State": "available"}]
        }
        mock_get_client.return_value = mock_client
        
        result = await analyze_tgw_peers("peer-123")
        data = json.loads(result)
        assert data["success"] is True
        assert "peering_attachments" in data