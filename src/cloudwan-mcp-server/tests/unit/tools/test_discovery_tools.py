"""Unit tests for CloudWAN MCP Server discovery tools."""

import pytest
import ipaddress
import json
from unittest.mock import AsyncMock, patch

from awslabs.cloudwan_mcp_server.server import simple_discover_ip_details, simple_list_core_networks, trace_network_path


@pytest.mark.asyncio
class TestDiscoveryTools:
    @pytest.mark.parametrize(
        "ip_address",
        [
            "192.168.1.1",  # Private IP
            "8.8.8.8",  # Public IP
            "127.0.0.1",  # Loopback
            "::1",  # IPv6 loopback
        ],
    )
    async def test_simple_discover_ip_details_valid_ips(self, ip_address):
        """Test simple IP details discovery with various valid IP addresses."""
        result = await simple_discover_ip_details(ip_address)
        result_dict = json.loads(result)

        assert result_dict["success"] is True
        assert result_dict["ip_address"] == ip_address

        ip_obj = ipaddress.ip_address(ip_address)
        assert result_dict["analysis"]["version"] == ip_obj.version
        assert result_dict["analysis"]["is_private"] == ip_obj.is_private

    @pytest.mark.parametrize(
        "invalid_ip",
        [
            "",  # Empty string
            "invalid_ip",  # Invalid format
            "999.999.999.999",  # Out of range
        ],
    )
    async def test_simple_discover_ip_details_invalid_ips(self, invalid_ip):
        """Test IP details discovery with invalid IP addresses."""
        result = await simple_discover_ip_details(invalid_ip)
        result_dict = json.loads(result)

        assert result_dict["success"] is False
        assert "error" in result_dict

    @patch("boto3.client")
    async def test_simple_list_core_networks(self, mock_boto_client):
        """Test listing core networks."""
        mock_client = AsyncMock()
        mock_client.list_core_networks.return_value = {"CoreNetworks": [{"Id": "cn-123", "GlobalNetworkId": "gn-456"}]}
        mock_boto_client.return_value = mock_client

        # Test default region
        result = await simple_list_core_networks(None)
        result_dict = json.loads(result)

        assert result_dict["success"] is True
        assert result_dict["total_count"] == 1
        assert len(result_dict["core_networks"]) == 1
        assert result_dict["core_networks"][0]["Id"] == "cn-123"

        # Test explicit valid region
        mock_client.list_core_networks.return_value = {"CoreNetworks": [{"Id": "cn-789", "GlobalNetworkId": "gn-abc"}]}
        result = await simple_list_core_networks("us-west-2")
        result_dict = json.loads(result)
        assert result_dict["total_count"] == 1
        assert result_dict["core_networks"][0]["Id"] == "cn-789"

    @pytest.mark.parametrize(
        "invalid_region",
        [
            "invalid-region",  # Incorrect region format
            "us_east_1",  # Incorrect separator
            "",  # Empty string
        ],
    )
    async def test_simple_list_core_networks_invalid_region(self, invalid_region):
        """Test listing core networks with invalid region formats."""
        result = await simple_list_core_networks(invalid_region)
        result_dict = json.loads(result)

        assert result_dict["success"] is False
        assert "error" in result_dict

    @pytest.mark.parametrize(
        "source_ip, dest_ip",
        [
            ("192.168.1.1", "8.8.8.8"),  # Private to Public
            ("10.0.0.1", "172.16.0.1"),  # Private network to Private network
            ("::1", "2001:db8::1"),  # IPv6 addresses
        ],
    )
    @pytest.mark.parametrize("valid_region", ["us-west-2", "eu-central-1"])
    async def test_simple_list_core_networks_valid_regions(self, valid_region):
        """Test with valid AWS regions."""
        result = await simple_list_core_networks(valid_region)
        result_dict = json.loads(result)
        assert result_dict["success"] is True
        assert result_dict["region"] == valid_region

    async def test_trace_network_path_valid_ips(self, source_ip, dest_ip):
        """Test network path tracing with valid IP addresses."""
        result = await trace_network_path(source_ip, dest_ip)
        result_dict = json.loads(result)

        assert result_dict["success"] is True
        assert result_dict["source_ip"] == source_ip
        assert result_dict["destination_ip"] == dest_ip
        assert "path_trace" in result_dict
        assert result_dict["total_hops"] > 0

    @pytest.mark.parametrize(
        "invalid_source, invalid_dest",
        [
            ("invalid_ip", "8.8.8.8"),  # Invalid source IP
            ("192.168.1.1", "invalid_ip"),  # Invalid destination IP
            ("", ""),  # Empty IPs
        ],
    )
    async def test_trace_network_path_invalid_ips(self, invalid_source, invalid_dest):
        """Test network path tracing with invalid IP addresses."""
        result = await trace_network_path(invalid_source, invalid_dest)
        result_dict = json.loads(result)

        assert result_dict["success"] is False
        assert "error" in result_dict
