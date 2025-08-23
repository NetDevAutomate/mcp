from unittest.mock import AsyncMock

import pytest
from botocore.exceptions import ClientError
from cloudwan.mcp import (
    SimpleDiscoverIpDetails,
    SimpleListCoreNetworks,
    discover_ip_details,
    discover_vpcs,
    get_global_networks,
    list_core_networks,
    trace_network_path,
    validate_ip_cidr,
)


@pytest.fixture
def mock_client():
    return AsyncMock()

@pytest.mark.asyncio
@pytest.mark.parametrize("tool_func, params, success_response", [
    # SimpleDiscoverIpDetails
    (SimpleDiscoverIpDetails, {"ip_address": "10.0.0.1"}, {"ipDetails": {"status": "found"}}),
    
    # SimpleListCoreNetworks
    (SimpleListCoreNetworks, {"max_results": 10}, {"coreNetworks": [{"id": "cn-1"}]}),
    
    # trace_network_path
    (trace_network_path, {"source": "10.0.0.1", "destination": "10.0.0.2"},
     {"paths": [{"hops": 5}]}),
    
    # list_core_networks
    (list_core_networks, {"region": "us-west-2", "status_filter": "AVAILABLE"},
     {"core_networks": ["cn-1"]}),
    
    # get_global_networks
    (get_global_networks, {"region": "global", "filter": "active"},
     {"global_networks": ["gn-1"]}),
    
    # discover_vpcs
    (discover_vpcs, {"region": "us-east-1", "tag_filters": {"Env": "prod"}},
     {"vpcs": ["vpc-12345"]}),
    
    # discover_ip_details
    (discover_ip_details, {"ip_address": "192.168.1.1", "resolve_dns": True},
     {"dns_name": "example.com"}),
    
    # validate_ip_cidr
    (validate_ip_cidr, {"cidr": "10.0.0.0/24"}, {"is_valid": True}),
])
async def test_valid_inputs(mock_client, tool_func, params, success_response):
    """Test all tools with valid parameter combinations"""
    mock_client.execute.return_value = success_response
    result = await tool_func(mock_client, **params)
    assert result == success_response
    mock_client.execute.assert_awaited_once()

@pytest.mark.asyncio
@pytest.mark.parametrize("tool_func, invalid_params, error_message", [
    # SimpleDiscoverIpDetails - invalid IP
    (SimpleDiscoverIpDetails, {"ip_address": "invalid_ip"}, "Invalid IP format"),
    
    # SimpleListCoreNetworks - invalid max_results
    (SimpleListCoreNetworks, {"max_results": 0}, "max_results must be positive"),
    
    # trace_network_path - invalid IPs
    (trace_network_path, {"source": "256.0.0.1", "destination": "10.0.0.2"},
     "Invalid source IP"),
    
    # list_core_networks - invalid status
    (list_core_networks, {"status_filter": "INVALID_STATE"},
     "Invalid status filter"),
    
    # get_global_networks - invalid region
    (get_global_networks, {"region": "invalid-region"}, "Invalid region format"),
    
    # discover_vpcs - invalid tag format
    (discover_vpcs, {"tag_filters": "invalid_format"}, "Tag filters must be a dict"),
    
    # discover_ip_details - missing IP
    (discover_ip_details, {"resolve_dns": True}, "ip_address is required"),
    
    # validate_ip_cidr - invalid CIDR
    (validate_ip_cidr, {"cidr": "10.0.0.0/33"}, "Invalid CIDR range"),
])
async def test_invalid_inputs(mock_client, tool_func, invalid_params, error_message):
    """Test parameter validation for all tools"""
    with pytest.raises(ValueError) as excinfo:
        await tool_func(mock_client, **invalid_params)
    assert error_message in str(excinfo.value)

@pytest.mark.asyncio
@pytest.mark.parametrize("tool_func, params", [
    (SimpleDiscoverIpDetails, {"ip_address": "10.0.0.1"}),
    (SimpleListCoreNetworks, {"max_results": 10}),
    (trace_network_path, {"source": "10.0.0.1", "destination": "10.0.0.2"}),
    (list_core_networks, {"region": "us-west-2"}),
    (get_global_networks, {"region": "global"}),
    (discover_vpcs, {"region": "us-east-1"}),
    (discover_ip_details, {"ip_address": "192.168.1.1"}),
    (validate_ip_cidr, {"cidr": "10.0.0.0/24"}),
])
async def test_aws_error_handling(mock_client, tool_func, params):
    """Test AWS error handling for all tools"""
    mock_client.execute.side_effect = ClientError(
        {"Error": {"Code": "500", "Message": "Internal Failure"}},
        "ExecuteOperation"
    )
    
    with pytest.raises(ClientError) as excinfo:
        await tool_func(mock_client, **params)
        
    assert excinfo.value.response["Error"]["Code"] == "500"
    mock_client.execute.assert_awaited_once()