"""Comprehensive tests for BGP analysis tools."""

import json
import pytest
from unittest.mock import MagicMock, patch

from awslabs.cloudwan_mcp_server.server import (
    get_cloudwan_bgp_peers,
    analyze_bgp_routing_policies,
    get_cloudwan_tgw_bgp_prefixes
)


@pytest.mark.asyncio
class TestBGPAnalysisTools:
    
    async def test_get_cloudwan_bgp_peers_with_tgw(self):
        """Test BGP peer discovery with Transit Gateway attachments."""
        with patch("awslabs.cloudwan_mcp_server.server.get_aws_client") as mock_client:
            # Mock NetworkManager client
            nm_mock = MagicMock()
            nm_mock.list_attachments.return_value = {
                "Attachments": [
                    {
                        "AttachmentId": "tgw-attach-123",
                        "AttachmentType": "TRANSIT_GATEWAY",
                        "SegmentName": "production",
                        "ResourceArn": "arn:aws:ec2:us-west-2:123456789012:transit-gateway/tgw-123",
                        "State": "AVAILABLE"
                    }
                ]
            }
            
            # Mock EC2 client
            ec2_mock = MagicMock()
            ec2_mock.describe_transit_gateways.return_value = {
                "TransitGateways": [
                    {
                        "TransitGatewayId": "tgw-123",
                        "AmazonSideAsn": 64512,
                        "State": "available"
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
            
            result = await get_cloudwan_bgp_peers("core-network-123")
            data = json.loads(result)
            
            assert data["success"]
            assert data["security_analysis"]["total_peers"] == 1
            assert "TRANSIT_GATEWAY_PEERING" in data["security_analysis"]["peer_types"]
            assert len(data["bgp_peers"]) == 1
            
            peer = data["bgp_peers"][0]
            assert peer["segment"] == "production"
            assert peer["attachment_type"] == "TRANSIT_GATEWAY_PEERING"
            assert peer["customer_bgp_asn"] == 64512
            assert peer["bgp_attributes"]["support_ipv4"] is True
    
    async def test_get_cloudwan_bgp_peers_with_vpn(self):
        """Test BGP peer discovery with VPN attachments."""
        with patch("awslabs.cloudwan_mcp_server.server.get_aws_client") as mock_client:
            nm_mock = MagicMock()
            nm_mock.list_attachments.return_value = {
                "Attachments": [
                    {
                        "AttachmentId": "vpn-attach-456",
                        "AttachmentType": "VPN",
                        "SegmentName": "development", 
                        "ResourceArn": "arn:aws:ec2:us-west-2:123456789012:vpn-connection/vpn-456",
                        "State": "AVAILABLE"
                    }
                ]
            }
            
            ec2_mock = MagicMock()
            ec2_mock.describe_vpn_connections.return_value = {
                "VpnConnections": [
                    {
                        "VpnConnectionId": "vpn-456",
                        "CustomerGatewayId": "cgw-789",
                        "Options": {
                            "LocalIpv4NetworkCidr": "169.254.10.0/30",
                            "TunnelInsideIpv4Cidr": "169.254.10.0/30"
                        },
                        "VgwTelemetry": [
                            {"Status": "UP"},
                            {"Status": "UP"}
                        ]
                    }
                ]
            }
            ec2_mock.describe_customer_gateways.return_value = {
                "CustomerGateways": [
                    {
                        "CustomerGatewayId": "cgw-789",
                        "BgpAsn": 65001,
                        "IpAddress": "203.0.113.12"
                    }
                ]
            }
            
            def get_client(service, region=None):
                return nm_mock if service == "networkmanager" else ec2_mock
            
            mock_client.side_effect = get_client
            
            result = await get_cloudwan_bgp_peers("core-network-123")
            data = json.loads(result)
            
            assert data["success"]
            assert data["security_analysis"]["total_peers"] == 1
            assert "IPSEC_VPN" in data["security_analysis"]["peer_types"]
            
            peer = data["bgp_peers"][0]
            assert peer["segment"] == "development"
            assert peer["attachment_type"] == "IPSEC_VPN"
            assert peer["customer_bgp_asn"] == 65001
            assert peer["customer_peer_ip"] == "203.0.113.12"
            assert peer["bgp_attributes"]["tunnel_count"] == 2
    
    async def test_get_cloudwan_bgp_peers_asn_conflicts(self):
        """Test ASN conflict detection in BGP peer analysis."""
        with patch("awslabs.cloudwan_mcp_server.server.get_aws_client") as mock_client:
            nm_mock = MagicMock()
            nm_mock.list_attachments.return_value = {
                "Attachments": [
                    {
                        "AttachmentId": "tgw-attach-123",
                        "AttachmentType": "TRANSIT_GATEWAY",
                        "SegmentName": "production",
                        "ResourceArn": "arn:aws:ec2:us-west-2:123456789012:transit-gateway/tgw-123",
                        "State": "AVAILABLE"
                    },
                    {
                        "AttachmentId": "vpn-attach-456", 
                        "AttachmentType": "VPN",
                        "SegmentName": "development",
                        "ResourceArn": "arn:aws:ec2:us-west-2:123456789012:vpn-connection/vpn-456",
                        "State": "AVAILABLE"
                    }
                ]
            }
            
            ec2_mock = MagicMock()
            # Both attachments use same ASN - should trigger conflict detection
            ec2_mock.describe_transit_gateways.return_value = {
                "TransitGateways": [{"AmazonSideAsn": 65001}]
            }
            ec2_mock.describe_vpn_connections.return_value = {
                "VpnConnections": [{"CustomerGatewayId": "cgw-789"}]
            }
            ec2_mock.describe_customer_gateways.return_value = {
                "CustomerGateways": [{"BgpAsn": 65001, "IpAddress": "203.0.113.12"}]
            }
            
            def get_client(service, region=None):
                return nm_mock if service == "networkmanager" else ec2_mock
            
            mock_client.side_effect = get_client
            
            result = await get_cloudwan_bgp_peers("core-network-123")
            data = json.loads(result)
            
            assert data["success"]
            assert len(data["security_analysis"]["asn_conflicts"]) == 1
            assert data["security_analysis"]["asn_conflicts"][0]["asn"] == "65001"
            assert data["security_analysis"]["asn_conflicts"][0]["usage_count"] == 2
    
    async def test_analyze_bgp_routing_policies_full_analysis(self):
        """Test comprehensive BGP routing policy analysis."""
        with patch("awslabs.cloudwan_mcp_server.server.get_aws_client") as mock_client:
            nm_mock = MagicMock()
            nm_mock.list_attachments.return_value = {
                "Attachments": [
                    {
                        "AttachmentId": "dx-attach-789",
                        "AttachmentType": "DIRECT_CONNECT_GATEWAY", 
                        "SegmentName": "production",
                        "ResourceArn": "arn:aws:directconnect:us-west-2:123456789012:direct-connect-gateway/dx-gw-789"
                    }
                ]
            }
            
            dx_mock = MagicMock()
            dx_mock.describe_direct_connect_gateway_route_table_entries.return_value = {
                "RouteTableEntries": [
                    {
                        "DestinationCidr": "10.1.0.0/16",
                        "NextHop": "192.168.1.1",
                        "AsPath": [65001, 65001, 65002],  # AS path with prepending
                        "Origin": "LEARNED",
                        "LocalPreference": 100,
                        "Med": 10,
                        "Community": ["65001:100", "65001:200"]
                    },
                    {
                        "DestinationCidr": "10.2.0.0/16",
                        "NextHop": "192.168.1.2", 
                        "AsPath": [65003],
                        "Origin": "LEARNED",
                        "Med": 5
                    }
                ]
            }
            
            def get_client(service, region=None):
                if service == "networkmanager":
                    return nm_mock
                elif service == "directconnect":
                    return dx_mock
                return MagicMock()
            
            mock_client.side_effect = get_client
            
            result = await analyze_bgp_routing_policies("core-network-123")
            data = json.loads(result)
            
            assert data["success"]
            assert data["analysis_type"] == "full_policy"
            assert data["bgp_analysis"]["total_routes"] == 2
            
            # Check AS path prepending analysis
            prepending = data["bgp_analysis"]["as_path_prepending"]
            assert prepending["routes_with_prepending"] >= 1
            assert "ASN_65001" in prepending["prepending_patterns"]
            
            # Check MED analysis
            med_analysis = data["bgp_analysis"]["med_analysis"]
            assert med_analysis["routes_with_med"] == 2
            
            # Check community analysis
            community_analysis = data["bgp_analysis"]["community_analysis"]
            assert community_analysis["routes_with_communities"] >= 1
    
    async def test_analyze_bgp_routing_policies_prefix_specific(self):
        """Test BGP analysis for specific prefix."""
        with patch("awslabs.cloudwan_mcp_server.server.get_aws_client") as mock_client:
            nm_mock = MagicMock()
            nm_mock.list_attachments.return_value = {"Attachments": []}
            mock_client.return_value = nm_mock
            
            result = await analyze_bgp_routing_policies("core-network-123", prefix="10.1.0.0/16")
            data = json.loads(result)
            
            assert data["success"]
            assert data["analysis_type"] == "prefix_specific"
            assert data["target_prefix"] == "10.1.0.0/16"
            assert "as_path_analysis" in data
            assert "longest_prefix_match" in data
    
    async def test_get_cloudwan_tgw_bgp_prefixes_learned_direction(self):
        """Test CloudWAN-TGW BGP prefix analysis for learned direction."""
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
                        "DestinationCidrBlock": "0.0.0.0/0",  # Should trigger security risk
                        "State": "active", 
                        "Type": "propagated"
                    }
                ]
            }
            
            def get_client(service, region=None):
                return nm_mock if service == "networkmanager" else ec2_mock
            
            mock_client.side_effect = get_client
            
            result = await get_cloudwan_tgw_bgp_prefixes(
                "core-network-123", "tgw-attach-123", direction="learned"
            )
            data = json.loads(result)
            
            assert data["success"]
            assert data["analysis_direction"] == "learned"
            assert data["bgp_prefix_analysis"]["learned_prefixes_count"] == 2
            assert len(data["bgp_prefix_analysis"]["security_risks"]) >= 1  # Default route should trigger risk
            assert any("CRITICAL" in risk for risk in data["bgp_prefix_analysis"]["security_risks"])
    
    async def test_bgp_peer_discovery_connect_attachment(self):
        """Test BGP peer discovery with Connect attachment."""
        with patch("awslabs.cloudwan_mcp_server.server.get_aws_client") as mock_client:
            nm_mock = MagicMock()
            nm_mock.list_attachments.return_value = {
                "Attachments": [
                    {
                        "AttachmentId": "connect-attach-789",
                        "AttachmentType": "CONNECT",
                        "SegmentName": "dmz",
                        "State": "AVAILABLE"
                    }
                ]
            }
            nm_mock.get_connect_attachment.return_value = {
                "ConnectAttachment": {
                    "AttachmentId": "connect-attach-789",
                    "CoreNetworkAddress": "169.254.100.1",
                    "PeerAddress": "169.254.100.2",
                    "Options": {
                        "PeerAsn": 65002,
                        "Protocol": "GRE",
                        "InsideCidrBlocks": ["169.254.100.0/29"]
                    }
                }
            }
            
            mock_client.return_value = nm_mock
            
            result = await get_cloudwan_bgp_peers("core-network-123")
            data = json.loads(result)
            
            assert data["success"]
            assert data["security_analysis"]["total_peers"] == 1
            
            peer = data["bgp_peers"][0]
            assert peer["attachment_type"] == "CONNECT_PEER"
            assert peer["customer_bgp_asn"] == 65002
            assert peer["cloudwan_peer_ip"] == "169.254.100.1"
            assert peer["customer_peer_ip"] == "169.254.100.2"
            assert peer["bgp_attributes"]["protocol"] == "GRE"
    
    async def test_bgp_routing_policies_security_risks(self):
        """Test BGP routing policy security risk detection."""
        with patch("awslabs.cloudwan_mcp_server.server.get_aws_client") as mock_client:
            nm_mock = MagicMock()
            nm_mock.list_attachments.return_value = {
                "Attachments": [
                    {
                        "AttachmentId": "dx-attach-suspicious",
                        "AttachmentType": "DIRECT_CONNECT_GATEWAY",
                        "ResourceArn": "arn:aws:directconnect:us-west-2:123456789012:direct-connect-gateway/dx-gw-suspicious"
                    }
                ]
            }
            
            # Mock suspicious BGP behavior - many prefixes from single ASN
            dx_mock = MagicMock()
            suspicious_routes = []
            for i in range(1200):  # Create 1200+ routes to trigger hijacking detection
                suspicious_routes.append({
                    "DestinationCidr": f"10.{i//254}.{i%254}.0/24",
                    "AsPath": [65999],  # Same suspicious ASN for all
                    "Origin": "LEARNED"
                })
            
            dx_mock.describe_direct_connect_gateway_route_table_entries.return_value = {
                "RouteTableEntries": suspicious_routes
            }
            
            def get_client(service, region=None):
                if service == "networkmanager":
                    return nm_mock
                elif service == "directconnect":
                    return dx_mock
                return MagicMock()
            
            mock_client.side_effect = get_client
            
            result = await analyze_bgp_routing_policies("core-network-123")
            data = json.loads(result)
            
            assert data["success"]
            assert len(data["bgp_analysis"]["security_risks"]) >= 1
            
            # Should detect AS hijacking potential
            hijacking_risk = next(
                (risk for risk in data["bgp_analysis"]["security_risks"] 
                 if risk.get("risk_type") == "AS_HIJACKING_POTENTIAL"), None
            )
            assert hijacking_risk is not None
            assert hijacking_risk["asn"] == 65999
            assert hijacking_risk["severity"] == "HIGH"
    
    async def test_bgp_tools_error_handling(self):
        """Test error handling in BGP analysis tools."""
        with patch("awslabs.cloudwan_mcp_server.server.get_aws_client") as mock_client:
            # Mock client error
            mock_client.side_effect = Exception("Network error")
            
            result = await get_cloudwan_bgp_peers("invalid-core-network")
            data = json.loads(result)
            
            assert not data["success"]
            assert "error" in data
            assert data["error"]["operation"] == "get_cloudwan_bgp_peers"
    
    async def test_bgp_prefix_analysis_direction_validation(self):
        """Test direction parameter validation in TGW BGP analysis."""
        with patch("awslabs.cloudwan_mcp_server.server.get_aws_client"):
            result = await get_cloudwan_tgw_bgp_prefixes(
                "core-network-123", "tgw-attach-123", direction="invalid_direction"
            )
            data = json.loads(result)
            
            assert not data["success"]
            assert "Invalid direction" in data["error"]["message"]
    
    async def test_bgp_analysis_with_no_attachments(self):
        """Test BGP analysis when no attachments exist."""
        with patch("awslabs.cloudwan_mcp_server.server.get_aws_client") as mock_client:
            nm_mock = MagicMock()
            nm_mock.list_attachments.return_value = {"Attachments": []}
            mock_client.return_value = nm_mock
            
            result = await get_cloudwan_bgp_peers("core-network-empty")
            data = json.loads(result)
            
            assert data["success"]
            assert data["security_analysis"]["total_peers"] == 0
            assert data["bgp_peers"] == []
            
            # BGP routing analysis should still work with no routes
            result2 = await analyze_bgp_routing_policies("core-network-empty")
            data2 = json.loads(result2)
            
            assert data2["success"]
            assert data2["bgp_analysis"]["total_routes"] == 0
            assert data2["bgp_analysis"]["policy_compliance"]["score"] == 100  # No violations