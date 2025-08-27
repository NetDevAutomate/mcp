"""Tests for CloudWAN prefix learning tools."""

import json
import pytest
from unittest.mock import MagicMock, patch

from awslabs.cloudwan_mcp_server.server import (
    get_dx_attachment_learned_prefixes,
    get_vpn_attachment_learned_prefixes,
    get_cloudwan_tgw_bgp_prefixes,
    _is_private_cidr
)


@pytest.mark.asyncio
class TestPrefixLearningTools:
    
    async def test_dx_attachment_learned_prefixes_success(self):
        """Test DX attachment prefix learning with mocked AWS responses."""
        with patch("awslabs.cloudwan_mcp_server.server.get_aws_client") as mock_client:
            # Mock NetworkManager client
            nm_mock = MagicMock()
            nm_mock.get_attach_attachment.return_value = {
                "Attachment": {
                    "AttachmentType": "DIRECT_CONNECT_GATEWAY",
                    "CoreNetworkId": "core-network-123",
                    "ResourceArn": "arn:aws:directconnect:us-west-2:123456789012:direct-connect-gateway/dx-gw-123",
                    "State": "AVAILABLE",
                    "GlobalNetworkId": "global-network-123"
                }
            }
            nm_mock.get_route_analysis.return_value = {"analysis": "data"}
            
            # Mock Direct Connect client
            dx_mock = MagicMock()
            dx_mock.describe_direct_connect_gateway_route_table_entries.return_value = {
                "RouteTableEntries": [
                    {
                        "DestinationCidr": "10.1.0.0/16",
                        "NextHop": "192.168.1.1", 
                        "AsPath": [65001, 65002],
                        "Origin": "LEARNED",
                        "LocalPreference": 100,
                        "Med": 10
                    },
                    {
                        "DestinationCidr": "172.16.0.0/12",
                        "NextHop": "192.168.1.1",
                        "AsPath": [65001],
                        "Origin": "LEARNED"
                    }
                ]
            }
            
            # Configure mock to return different clients
            def get_client(service, region=None):
                if service == "networkmanager":
                    return nm_mock
                elif service == "directconnect":
                    return dx_mock
                return MagicMock()
            
            mock_client.side_effect = get_client
            
            result = await get_dx_attachment_learned_prefixes("attach-123", "us-west-2")
            data = json.loads(result)
            
            assert data["success"]
            assert data["attachment_type"] == "DIRECT_CONNECT_GATEWAY"
            assert data["learned_prefixes"]["count"] == 2
            assert len(data["learned_prefixes"]["prefixes"]) == 2
            assert data["learned_prefixes"]["analysis"]["private_prefixes"] == 2
            assert data["learned_prefixes"]["analysis"]["public_prefixes"] == 0
    
    async def test_dx_attachment_wrong_type(self):
        """Test DX tool with non-DX attachment."""
        with patch("awslabs.cloudwan_mcp_server.server.get_aws_client") as mock_client:
            nm_mock = MagicMock()
            nm_mock.get_attach_attachment.return_value = {
                "Attachment": {
                    "AttachmentType": "VPC",  # Wrong type
                    "CoreNetworkId": "core-network-123"
                }
            }
            mock_client.return_value = nm_mock
            
            result = await get_dx_attachment_learned_prefixes("attach-123")
            data = json.loads(result)
            
            assert not data["success"]
            assert "not a Direct Connect Gateway attachment" in data["error"]["message"]
    
    async def test_vpn_attachment_learned_prefixes_success(self):
        """Test VPN attachment prefix learning."""
        with patch("awslabs.cloudwan_mcp_server.server.get_aws_client") as mock_client:
            # Mock NetworkManager client
            nm_mock = MagicMock()
            nm_mock.get_attach_attachment.return_value = {
                "Attachment": {
                    "AttachmentType": "VPN",
                    "CoreNetworkId": "core-network-123",
                    "ResourceArn": "arn:aws:ec2:us-west-2:123456789012:vpn-connection/vpn-123",
                    "State": "AVAILABLE"
                }
            }
            
            # Mock EC2 client
            ec2_mock = MagicMock()
            ec2_mock.describe_vpn_connection_routes.return_value = {
                "VpnConnectionRoutes": [
                    {
                        "DestinationCidrBlock": "192.168.0.0/16",
                        "State": "available",
                        "Source": "BGP",
                        "Origin": "LEARNED"
                    },
                    {
                        "DestinationCidrBlock": "10.0.0.0/8", 
                        "State": "available",
                        "Source": "BGP",
                        "Origin": "LEARNED"
                    }
                ]
            }
            ec2_mock.describe_vpn_connections.return_value = {
                "VpnConnections": [
                    {
                        "CustomerGatewayConfiguration": "BGP routing enabled"
                    }
                ]
            }
            
            def get_client(service, region=None):
                if service == "networkmanager":
                    return nm_mock
                elif service == "ec2":
                    return ec2_mock
                return MagicMock()
            
            mock_client.side_effect = get_client
            
            result = await get_vpn_attachment_learned_prefixes("attach-vpn-123", "us-west-2")
            data = json.loads(result)
            
            assert data["success"]
            assert data["attachment_type"] == "VPN"
            assert data["learned_prefixes"]["count"] == 2
            assert data["learned_prefixes"]["security_analysis"]["private_prefixes"] == 2
    
    async def test_cloudwan_tgw_bgp_prefixes_learned(self):
        """Test CloudWAN-TGW BGP prefix learning analysis."""
        with patch("awslabs.cloudwan_mcp_server.server.get_aws_client") as mock_client:
            # Mock NetworkManager client
            nm_mock = MagicMock()
            nm_mock.get_attach_attachment.return_value = {
                "Attachment": {
                    "AttachmentType": "TRANSIT_GATEWAY",
                    "CoreNetworkId": "core-network-123",
                    "ResourceArn": "arn:aws:ec2:us-west-2:123456789012:transit-gateway/tgw-123",
                    "State": "AVAILABLE"
                }
            }
            nm_mock.get_core_network_policy.return_value = {
                "CoreNetworkPolicy": {
                    "PolicyDocument": '{"segments": [{"name": "production"}, {"name": "development"}]}'
                }
            }
            nm_mock.list_core_network_policy_versions.return_value = {"PolicyVersions": []}
            
            # Mock EC2 client
            ec2_mock = MagicMock()
            ec2_mock.describe_transit_gateway_route_tables.return_value = {
                "TransitGatewayRouteTables": [
                    {"TransitGatewayRouteTableId": "tgw-rtb-123"}
                ]
            }
            ec2_mock.search_transit_gateway_routes.return_value = {
                "Routes": [
                    {
                        "DestinationCidrBlock": "10.1.0.0/16",
                        "State": "active",
                        "Type": "propagated"
                    },
                    {
                        "DestinationCidrBlock": "172.16.0.0/12", 
                        "State": "active",
                        "Type": "propagated"
                    }
                ]
            }
            
            def get_client(service, region=None):
                if service == "networkmanager":
                    return nm_mock
                elif service == "ec2":
                    return ec2_mock
                return MagicMock()
            
            mock_client.side_effect = get_client
            
            result = await get_cloudwan_tgw_bgp_prefixes("core-network-123", "tgw-attach-123", "us-west-2", "learned")
            data = json.loads(result)
            
            assert data["success"]
            assert data["analysis_direction"] == "learned"
            assert data["bgp_prefix_analysis"]["learned_prefixes_count"] == 2
            assert data["bgp_prefix_analysis"]["private_learned"] == 2
            assert len(data["learned_prefixes"]) == 2
    
    async def test_cloudwan_tgw_bgp_security_risks(self):
        """Test BGP security risk detection."""
        with patch("awslabs.cloudwan_mcp_server.server.get_aws_client") as mock_client:
            nm_mock = MagicMock()
            nm_mock.get_attach_attachment.return_value = {
                "Attachment": {
                    "AttachmentType": "TRANSIT_GATEWAY",
                    "CoreNetworkId": "core-network-123", 
                    "ResourceArn": "arn:aws:ec2:us-west-2:123456789012:transit-gateway/tgw-123",
                    "State": "AVAILABLE"
                }
            }
            
            ec2_mock = MagicMock()
            ec2_mock.describe_transit_gateway_route_tables.return_value = {
                "TransitGatewayRouteTables": [{"TransitGatewayRouteTableId": "tgw-rtb-123"}]
            }
            # Mock dangerous default route learning
            ec2_mock.search_transit_gateway_routes.return_value = {
                "Routes": [
                    {
                        "DestinationCidrBlock": "0.0.0.0/0",  # Default route - security risk
                        "State": "active",
                        "Type": "propagated"
                    }
                ]
            }
            
            def get_client(service, region=None):
                return nm_mock if service == "networkmanager" else ec2_mock
            
            mock_client.side_effect = get_client
            
            result = await get_cloudwan_tgw_bgp_prefixes("core-network-123", "tgw-attach-123", direction="learned")
            data = json.loads(result)
            
            assert data["success"]
            assert len(data["bgp_prefix_analysis"]["security_risks"]) > 0
            assert any("CRITICAL" in risk for risk in data["bgp_prefix_analysis"]["security_risks"])
    
    def test_private_cidr_detection(self):
        """Test private CIDR block detection utility."""
        assert _is_private_cidr("10.0.0.0/8") == True
        assert _is_private_cidr("192.168.1.0/24") == True
        assert _is_private_cidr("172.16.0.0/12") == True
        assert _is_private_cidr("8.8.8.8/32") == False
        assert _is_private_cidr("0.0.0.0/0") == False
        assert _is_private_cidr("invalid-cidr") == False
        assert _is_private_cidr("") == False