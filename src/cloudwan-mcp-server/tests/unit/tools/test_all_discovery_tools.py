"""Comprehensive tests for ALL 8 Discovery tools - DeepSeek-R1 Specialist."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from awslabs.cloudwan_mcp_server.server import (
    discover_ip_details,
    discover_vpcs,
    get_global_networks,
    list_core_networks,
    simple_discover_ip_details,
    simple_list_core_networks,
    trace_network_path,
    validate_ip_cidr,
)


@pytest.mark.asyncio
class TestAllDiscoveryTools:
    """DeepSeek-R1: Comprehensive tests for ALL 8 Discovery tools."""

    # Tool 1: SimpleDiscoverIpDetails
    async def test_simple_discover_ip_details_valid_ipv4(self):
        result = await simple_discover_ip_details("192.168.1.1")
        data = json.loads(result)
        assert data["success"] is True
        assert data["ip_address"] == "192.168.1.1"
        assert data["analysis"]["version"] == 4
        assert data["analysis"]["is_private"] is True

    async def test_simple_discover_ip_details_valid_ipv6(self):
        result = await simple_discover_ip_details("::1")
        data = json.loads(result)
        assert data["success"] is True
        assert data["analysis"]["version"] == 6

    async def test_simple_discover_ip_details_invalid(self):
        result = await simple_discover_ip_details("invalid.ip")
        data = json.loads(result)
        assert data["success"] is False
        assert "error" in data

    # Tool 2: SimpleListCoreNetworks
    @patch("boto3.client")
    async def test_simple_list_core_networks_success(self, mock_boto_client):
        mock_client = AsyncMock()
        mock_client.list_core_networks.return_value = {
            "CoreNetworks": [{"CoreNetworkId": "cn-123", "State": "AVAILABLE"}]
        }
        mock_boto_client.return_value = mock_client

        result = await simple_list_core_networks("us-east-1")
        data = json.loads(result)
        assert data["success"] is True
        assert data["total_count"] == 1

    async def test_simple_list_core_networks_invalid_region(self):
        result = await simple_list_core_networks("invalid-region")
        data = json.loads(result)
        assert data["success"] is False

    # Tool 3: trace_network_path
    async def test_trace_network_path_valid_ips(self):
        result = await trace_network_path("10.0.0.1", "10.0.0.2")
        data = json.loads(result)
        assert data["success"] is True
        assert data["source_ip"] == "10.0.0.1"
        assert data["destination_ip"] == "10.0.0.2"
        assert "path_trace" in data
        assert data["total_hops"] > 0

    async def test_trace_network_path_invalid_source(self):
        result = await trace_network_path("invalid", "10.0.0.2")
        data = json.loads(result)
        assert data["success"] is False

    async def test_trace_network_path_invalid_dest(self):
        result = await trace_network_path("10.0.0.1", "invalid")
        data = json.loads(result)
        assert data["success"] is False

    # Tool 4: list_core_networks
    @patch("boto3.client")
    async def test_list_core_networks_success(self, mock_boto_client):
        mock_client = AsyncMock()
        mock_client.list_core_networks.return_value = {"CoreNetworks": []}
        mock_boto_client.return_value = mock_client

        result = await list_core_networks()
        data = json.loads(result)
        assert data["success"] is True
        assert "core_networks" in data

    # Tool 5: get_global_networks
    @patch("boto3.client")
    async def test_get_global_networks_success(self, mock_boto_client):
        mock_client = AsyncMock()
        mock_client.describe_global_networks.return_value = {"GlobalNetworks": []}
        mock_boto_client.return_value = mock_client

        result = await get_global_networks()
        data = json.loads(result)
        assert data["success"] is True
        assert "global_networks" in data

    # Tool 6: discover_vpcs
    @patch("boto3.client")
    async def test_discover_vpcs_success(self, mock_boto_client):
        mock_client = AsyncMock()
        mock_client.describe_vpcs.return_value = {"Vpcs": []}
        mock_boto_client.return_value = mock_client

        result = await discover_vpcs()
        data = json.loads(result)
        assert data["success"] is True
        assert "vpcs" in data

    # Tool 7: discover_ip_details
    async def test_discover_ip_details_valid(self):
        result = await discover_ip_details("192.168.1.1")
        data = json.loads(result)
        assert data["success"] is True
        assert data["ip_address"] == "192.168.1.1"
        assert "details" in data

    async def test_discover_ip_details_invalid(self):
        result = await discover_ip_details("invalid.ip")
        data = json.loads(result)
        assert data["success"] is False

    # Tool 8: validate_ip_cidr
    async def test_validate_ip_cidr_validate_ip_valid(self):
        result = await validate_ip_cidr("validate_ip", ip="10.0.0.1")
        data = json.loads(result)
        assert data["success"] is True
        assert data["operation"] == "validate_ip"
        assert data["is_valid"] is True

    async def test_validate_ip_cidr_validate_cidr_valid(self):
        result = await validate_ip_cidr("validate_cidr", cidr="192.168.0.0/24")
        data = json.loads(result)
        assert data["success"] is True
        assert data["operation"] == "validate_cidr"
        assert data["is_valid"] is True

    async def test_validate_ip_cidr_invalid_operation(self):
        result = await validate_ip_cidr("invalid_operation")
        data = json.loads(result)
        assert data["success"] is False
