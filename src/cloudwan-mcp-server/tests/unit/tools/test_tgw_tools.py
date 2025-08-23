"""Unit tests for CloudWAN MCP Server Transit Gateway tools."""

import pytest
import json
from unittest.mock import AsyncMock, patch

from awslabs.cloudwan_mcp_server.server import manage_tgw_routes, analyze_tgw_routes, analyze_tgw_peers


@pytest.mark.asyncio
class TestTransitGatewayTools:
    @pytest.mark.parametrize(
        "operation, cidr", [("create", "10.0.0.0/16"), ("delete", "172.16.0.0/24"), ("blackhole", "192.168.1.0/28")]
    )
    async def test_manage_tgw_routes_valid(self, operation, cidr):
        """Test managing Transit Gateway routes with valid inputs."""
        result = await manage_tgw_routes(operation, "rtb-123", cidr)
        result_dict = json.loads(result)

        # More flexible success checking
        assert result_dict.get("success", False) is True, f"Route {operation} operation should succeed"

        # Validate key details flexibly
        assert result_dict.get("operation") == operation, "Operation should match input"
        assert result_dict.get("destination_cidr") == cidr, "CIDR should match input"

        # Check result with multiple possible keys
        result_status = result_dict.get("result", {}).get("status") or result_dict.get("status", "").lower()
        assert result_status in ["completed", "success", "ok"], "Operation should have a successful status"

    @pytest.mark.parametrize(
        "invalid_operation, invalid_cidr",
        [
            ("unknown", "10.0.0.0/16"),  # Invalid operation
            ("create", "invalid-cidr"),  # Invalid CIDR
            ("delete", ""),  # Empty CIDR
        ],
    )
    async def test_manage_tgw_routes_invalid(self, invalid_operation, invalid_cidr):
        """Test managing Transit Gateway routes with invalid inputs."""
        result = await manage_tgw_routes(invalid_operation, "rtb-123", invalid_cidr)
        result_dict = json.loads(result)

        # Flexible error checking
        assert result_dict.get("success", False) is False, "Invalid inputs should result in failure"

        # Error detail validation
        error_message = result_dict.get("error", {}).get("message") or result_dict.get("message") or ""

        if invalid_cidr in ["invalid-cidr", ""]:
            assert any(
                [
                    "Invalid CIDR" in error_message,
                    "invalid format" in error_message.lower(),
                    "cidr" in error_message.lower(),
                ]
            ), "Should indicate CIDR format error"

    @patch("boto3.client")
    async def test_analyze_tgw_routes(self, mock_boto_client):
        """Test analyzing Transit Gateway routes."""
        mock_client = AsyncMock()
        mock_client.search_transit_gateway_routes = AsyncMock(
            return_value={"Routes": [{"DestinationCidrBlock": "10.0.0.0/16"}]}
        )
        mock_boto_client.return_value = mock_client

        result = await analyze_tgw_routes("rtb-123")
        result_dict = json.loads(result)

        assert result_dict.get("success") is True
        assert result_dict.get("route_table_id") == "rtb-123"
        assert "analysis" in result_dict
        assert result_dict["analysis"].get("total_routes") == 1

    @patch("boto3.client")
    async def test_analyze_tgw_peers(self, mock_boto_client):
        """Test analyzing Transit Gateway peering attachments."""
        mock_client = AsyncMock()
        mock_client.describe_transit_gateway_peering_attachments = AsyncMock(
            return_value={
                "TransitGatewayPeeringAttachments": [
                    {"TransitGatewayAttachmentId": "tgw-attach-123", "State": "available"}
                ]
            }
        )
        mock_boto_client.return_value = mock_client

        result = await analyze_tgw_peers("tgw-peer-123")
        result_dict = json.loads(result)

        assert result_dict.get("success") is True
        assert result_dict.get("peer_id") == "tgw-peer-123"
        assert len(result_dict.get("peering_attachments", [])) > 0
