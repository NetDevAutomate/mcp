"""Clean Discovery tools tests - NO Simple* duplicates."""

import json
import pytest
from unittest.mock import MagicMock, patch

from awslabs.cloudwan_mcp_server.server import (
    discover_ip_details,
    discover_vpcs,
    get_global_networks,
    list_core_networks,
    trace_network_path,
    validate_ip_cidr,
)


@pytest.mark.asyncio
class TestCleanDiscoveryTools:
    """Tests for 6 Discovery tools (no Simple* duplicates)."""

    # TOOL 1: discover_ip_details (comprehensive version)
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

    # TOOL 2: list_core_networks (comprehensive version)
    @patch("awslabs.cloudwan_mcp_server.server.get_aws_client")
    async def test_list_core_networks_success(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.list_core_networks.return_value = {"CoreNetworks": []}
        mock_get_client.return_value = mock_client
        
        result = await list_core_networks()
        data = json.loads(result)
        assert data["success"] is True
        assert "core_networks" in data

    # TOOL 3: trace_network_path
    async def test_trace_network_path_valid(self):
        result = await trace_network_path("10.0.0.1", "10.0.0.2")
        data = json.loads(result)
        assert data["success"] is True
        assert data["source_ip"] == "10.0.0.1"
        assert data["destination_ip"] == "10.0.0.2"
        assert "path_trace" in data

    # TOOL 4: get_global_networks
    @patch("awslabs.cloudwan_mcp_server.server.get_aws_client")
    async def test_get_global_networks_success(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.describe_global_networks.return_value = {"GlobalNetworks": []}
        mock_get_client.return_value = mock_client
        
        result = await get_global_networks()
        data = json.loads(result)
        assert data["success"] is True
        assert "global_networks" in data

    # TOOL 5: discover_vpcs
    @patch("awslabs.cloudwan_mcp_server.server.get_aws_client")
    async def test_discover_vpcs_success(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.describe_vpcs.return_value = {"Vpcs": []}
        mock_get_client.return_value = mock_client
        
        result = await discover_vpcs()
        data = json.loads(result)
        assert data["success"] is True
        assert "vpcs" in data

    # TOOL 6: validate_ip_cidr
    async def test_validate_ip_cidr_validate_ip(self):
        result = await validate_ip_cidr("validate_ip", ip="10.0.0.1")
        data = json.loads(result)
        assert data["success"] is True
        assert data["operation"] == "validate_ip"

    async def test_validate_ip_cidr_validate_cidr(self):
        result = await validate_ip_cidr("validate_cidr", cidr="192.168.0.0/24")
        data = json.loads(result)
        assert data["success"] is True
        assert data["operation"] == "validate_cidr"
