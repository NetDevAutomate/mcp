"""Comprehensive tests for ALL CloudWAN Discovery tools."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from awslabs.cloudwan_mcp_server.server import (
    SimpleListCoreNetworks,
    discover_ip_details,
    discover_vpcs,
    get_global_networks,
    list_core_networks,
    simple_discover_ip_details,
    trace_network_path,
    validate_ip_cidr,
)


@pytest.mark.asyncio
class TestAllDiscoveryTools:
    """Test ALL discovery tools comprehensively."""

    # Test SimpleDiscoverIpDetails
    async def test_simple_discover_ip_details_valid(self):
        result = await simple_discover_ip_details("192.168.1.1")
        data = json.loads(result)
        assert data["success"] is True
        assert data["ip_address"] == "192.168.1.1"

    async def test_simple_discover_ip_details_invalid(self):
        result = await simple_discover_ip_details("invalid-ip")
        data = json.loads(result)
        assert data["success"] is False
        assert "error" in data

    # Test SimpleListCoreNetworks
    @patch("boto3.client")
    async def test_simple_list_core_networks_valid(self, mock_boto_client):
        mock_client = AsyncMock()
        mock_client.list_core_networks.return_value = {"CoreNetworks": [{"Id": "cn-123"}]}
        mock_boto_client.return_value = mock_client

        result = await SimpleListCoreNetworks()
        data = json.loads(result)
        assert data["success"] is True

    # Test trace_network_path
    async def test_trace_network_path_valid(self):
        result = await trace_network_path("10.0.0.1", "10.0.0.2")
        data = json.loads(result)
        assert data["success"] is True
        assert data["source_ip"] == "10.0.0.1"
        assert data["destination_ip"] == "10.0.0.2"

    # Test list_core_networks
    @patch("boto3.client")
    async def test_list_core_networks(self, mock_boto_client):
        mock_client = AsyncMock()
        mock_client.list_core_networks.return_value = {"CoreNetworks": []}
        mock_boto_client.return_value = mock_client

        result = await list_core_networks()
        data = json.loads(result)
        assert data["success"] is True

    # Test get_global_networks
    @patch("boto3.client")
    async def test_get_global_networks(self, mock_boto_client):
        mock_client = AsyncMock()
        mock_client.describe_global_networks.return_value = {"GlobalNetworks": []}
        mock_boto_client.return_value = mock_client

        result = await get_global_networks()
        data = json.loads(result)
        assert data["success"] is True

    # Test discover_vpcs
    @patch("boto3.client")
    async def test_discover_vpcs(self, mock_boto_client):
        mock_client = AsyncMock()
        mock_client.describe_vpcs.return_value = {"Vpcs": []}
        mock_boto_client.return_value = mock_client

        result = await discover_vpcs()
        data = json.loads(result)
        assert data["success"] is True

    # Test discover_ip_details
    async def test_discover_ip_details(self):
        result = await discover_ip_details("10.0.0.1")
        data = json.loads(result)
        assert data["success"] is True
        assert data["ip_address"] == "10.0.0.1"

    # Test validate_ip_cidr
    async def test_validate_ip_cidr_ip(self):
        result = await validate_ip_cidr("validate_ip", ip="192.168.1.1")
        data = json.loads(result)
        assert data["success"] is True
        assert data["operation"] == "validate_ip"

    async def test_validate_ip_cidr_cidr(self):
        result = await validate_ip_cidr("validate_cidr", cidr="10.0.0.0/16")
        data = json.loads(result)
        assert data["success"] is True
        assert data["operation"] == "validate_cidr"
