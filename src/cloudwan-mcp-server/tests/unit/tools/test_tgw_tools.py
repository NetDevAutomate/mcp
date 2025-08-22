"""Unit tests for CloudWAN MCP Server Transit Gateway tools."""

import pytest
import json
from unittest.mock import AsyncMock, patch

from awslabs.cloudwan_mcp_server.server import (
    manage_tgw_routes,
    analyze_tgw_routes,
    analyze_tgw_peers
)


@pytest.mark.asyncio
class TestTransitGatewayTools:
    @pytest.mark.parametrize("operation, cidr", [
        ("create", "10.0.0.0/16"),
        ("delete", "172.16.0.0/24"),
        ("blackhole", "192.168.1.0/28")
    ])
    async def test_manage_tgw_routes_valid(self, operation, cidr):
        """Test managing Transit Gateway routes with valid inputs."""
        result = await manage_tgw_routes(operation, "rtb-123", cidr)
        result_dict = json.loads(result)
        
        assert result_dict['success'] is True
        assert result_dict['operation'] == operation
        assert result_dict['destination_cidr'] == cidr
        assert result_dict['result']['status'] == 'completed'

    @pytest.mark.parametrize("invalid_operation, invalid_cidr", [
        ("unknown", "10.0.0.0/16"),   # Invalid operation
        ("create", "invalid-cidr"),   # Invalid CIDR
        ("delete", "")                # Empty CIDR
    ])
    async def test_manage_tgw_routes_invalid(self, invalid_operation, invalid_cidr):
        """Test managing Transit Gateway routes with invalid inputs."""
        result = await manage_tgw_routes(invalid_operation, "rtb-123", invalid_cidr)
        result_dict = json.loads(result)
        
        assert result_dict['success'] is False
        assert 'error' in result_dict

    @patch('boto3.client')
    async def test_analyze_tgw_routes(self, mock_boto_client):
        """Test analyzing Transit Gateway routes."""
        # Mock AWS client response
        mock_client = AsyncMock()
        mock_client.search_transit_gateway_routes.return_value = {
            'Routes': [
                {'DestinationCidrBlock': '10.0.0.0/16', 'State': 'active'},
                {'DestinationCidrBlock': '172.16.0.0/24', 'State': 'blackhole'}
            ]
        }
        mock_boto_client.return_value = mock_client

        result = await analyze_tgw_routes('rtb-123')
        result_dict = json.loads(result)
        
        assert result_dict['success'] is True
        assert result_dict['route_table_id'] == 'rtb-123'
        assert 'analysis' in result_dict
        assert result_dict['analysis']['total_routes'] > 0

    @patch('boto3.client')
    async def test_analyze_tgw_peers(self, mock_boto_client):
        """Test analyzing Transit Gateway peering attachments."""
        # Mock AWS client response
        mock_client = AsyncMock()
        mock_client.describe_transit_gateway_peering_attachments.return_value = {
            'TransitGatewayPeeringAttachments': [
                {'TransitGatewayAttachmentId': 'tgw-attach-123', 'State': 'available'}
            ]
        }
        mock_boto_client.return_value = mock_client

        result = await analyze_tgw_peers('tgw-peer-123')
        result_dict = json.loads(result)
        
        assert result_dict['success'] is True
        assert result_dict['peer_id'] == 'tgw-peer-123'
        assert len(result_dict['peering_attachments']) > 0