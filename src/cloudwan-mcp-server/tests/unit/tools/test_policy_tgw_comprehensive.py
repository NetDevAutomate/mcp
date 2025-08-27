import json
from unittest.mock import AsyncMock

import pytest
from botocore.exceptions import ClientError
from cloudwan.mcp import (
    analyze_segment_routes,
    analyze_tgw_peers,
    analyze_tgw_routes,
    get_core_network_change_events,
    get_core_network_change_set,
    get_core_network_policy,
    manage_tgw_routes,
    validate_cloudwan_policy,
)


@pytest.fixture
def mock_client():
    return AsyncMock()


@pytest.fixture
def sample_policy():
    """Sample CloudWAN policy for testing"""
    return {
        "version": "2021.12",
        "core-network-configuration": {
            "vpn-ecmp-support": False,
            "asn-ranges": ["64512-65534"],
            "edge-locations": [{"location": "us-east-1", "asn": 64512}],
        },
        "segments": [
            {"name": "production", "description": "Production segment", "require-attachment-acceptance": True}
        ],
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tool_func, params, success_response",
    [
        # CloudWAN Policy Tools
        (
            validate_cloudwan_policy,
            {"policy_document": json.dumps({"version": "2021.12", "segments": [{"name": "prod"}]})},
            {"is_valid": True, "validation_messages": []},
        ),
        (
            get_core_network_policy,
            {"core_network_id": "core-12345", "region": "us-east-1"},
            {"policy": {"version": "2021.12"}, "policy_version": 1},
        ),
        (
            get_core_network_change_set,
            {"core_network_id": "core-12345", "policy_version": 2},
            {"change_set": [{"type": "CORE_NETWORK_SEGMENT", "action": "CREATE"}]},
        ),
        (
            get_core_network_change_events,
            {"core_network_id": "core-12345", "change_set_id": "cs-12345"},
            {"events": [{"timestamp": "2024-01-01T00:00:00Z", "status": "COMPLETE"}]},
        ),
        (
            analyze_segment_routes,
            {"core_network_id": "core-12345", "segment_name": "production"},
            {"routes": [{"destination": "10.0.0.0/16", "next_hop": "attachment-12345"}]},
        ),
        # Transit Gateway Tools
        (
            manage_tgw_routes,
            {
                "tgw_route_table_id": "tgw-rtb-12345",
                "operation": "add",
                "cidr": "10.0.0.0/16",
                "attachment_id": "tgw-attach-12345",
            },
            {"route_status": "active", "operation_result": "success"},
        ),
        (
            analyze_tgw_routes,
            {"tgw_id": "tgw-12345", "route_table_id": "tgw-rtb-12345", "filter_criteria": {"state": "active"}},
            {"routes": [{"destination_cidr": "10.0.0.0/16", "state": "active", "type": "static"}]},
        ),
        (
            analyze_tgw_peers,
            {"tgw_id": "tgw-12345", "peering_attachment_id": "tgw-attach-peer-12345"},
            {"peer_info": {"peer_tgw_id": "tgw-67890", "peer_region": "us-west-2", "state": "available"}},
        ),
    ],
)
async def test_valid_inputs(mock_client, tool_func, params, success_response):
    """Test all policy and TGW tools with valid parameter combinations"""
    mock_client.execute.return_value = success_response
    result = await tool_func(mock_client, **params)
    assert result == success_response
    mock_client.execute.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tool_func, invalid_params, error_message",
    [
        # CloudWAN Policy validation errors
        (validate_cloudwan_policy, {"policy_document": "invalid-json"}, "Invalid JSON in policy document"),
        (
            validate_cloudwan_policy,
            {"policy_document": json.dumps({"segments": []})},  # Missing version
            "Policy must include version field",
        ),
        (get_core_network_policy, {"core_network_id": ""}, "core_network_id cannot be empty"),
        (
            get_core_network_change_set,
            {"core_network_id": "core-12345", "policy_version": -1},
            "policy_version must be positive",
        ),
        (
            get_core_network_change_events,
            {"core_network_id": "core-12345", "change_set_id": ""},
            "change_set_id cannot be empty",
        ),
        (analyze_segment_routes, {"core_network_id": "core-12345", "segment_name": ""}, "segment_name cannot be empty"),
        # Transit Gateway validation errors
        (
            manage_tgw_routes,
            {"tgw_route_table_id": "tgw-rtb-12345", "operation": "invalid", "cidr": "10.0.0.0/16"},
            "Invalid operation. Must be 'add', 'delete', or 'modify'",
        ),
        (
            manage_tgw_routes,
            {"tgw_route_table_id": "tgw-rtb-12345", "operation": "add", "cidr": "10.0.0.0/33"},
            "Invalid CIDR block",
        ),
        (analyze_tgw_routes, {"tgw_id": "", "route_table_id": "tgw-rtb-12345"}, "tgw_id cannot be empty"),
        (
            analyze_tgw_peers,
            {"tgw_id": "tgw-12345", "peering_attachment_id": "invalid-format"},
            "Invalid peering attachment ID format",
        ),
    ],
)
async def test_invalid_inputs(mock_client, tool_func, invalid_params, error_message):
    """Test parameter validation for all policy and TGW tools"""
    with pytest.raises(ValueError) as excinfo:
        await tool_func(mock_client, **invalid_params)
    assert error_message in str(excinfo.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tool_func, params",
    [
        (validate_cloudwan_policy, {"policy_document": json.dumps({"version": "2021.12"})}),
        (get_core_network_policy, {"core_network_id": "core-12345"}),
        (get_core_network_change_set, {"core_network_id": "core-12345", "policy_version": 1}),
        (get_core_network_change_events, {"core_network_id": "core-12345", "change_set_id": "cs-12345"}),
        (analyze_segment_routes, {"core_network_id": "core-12345", "segment_name": "production"}),
        (
            manage_tgw_routes,
            {
                "tgw_route_table_id": "tgw-rtb-12345",
                "operation": "add",
                "cidr": "10.0.0.0/16",
                "attachment_id": "tgw-attach-12345",
            },
        ),
        (analyze_tgw_routes, {"tgw_id": "tgw-12345"}),
        (analyze_tgw_peers, {"tgw_id": "tgw-12345"}),
    ],
)
async def test_aws_error_handling(mock_client, tool_func, params):
    """Test AWS error handling for all policy and TGW tools"""
    mock_client.execute.side_effect = ClientError(
        {"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}}, "ExecuteOperation"
    )

    with pytest.raises(ClientError) as excinfo:
        await tool_func(mock_client, **params)

    assert excinfo.value.response["Error"]["Code"] == "ThrottlingException"
    mock_client.execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_validate_complex_policy(mock_client, sample_policy):
    """Test validation of complex CloudWAN policy with all components"""
    mock_client.execute.return_value = {"is_valid": True, "validation_messages": [], "policy_version": "2021.12"}

    result = await validate_cloudwan_policy(mock_client, policy_document=json.dumps(sample_policy))

    assert result["is_valid"] is True
    assert result["policy_version"] == "2021.12"


@pytest.mark.asyncio
async def test_manage_tgw_routes_operations(mock_client):
    """Test all TGW route management operations"""
    operations = ["add", "delete", "modify"]

    for operation in operations:
        mock_client.execute.return_value = {
            "route_status": "active" if operation != "delete" else "deleted",
            "operation_result": "success",
        }

        result = await manage_tgw_routes(
            mock_client,
            tgw_route_table_id="tgw-rtb-12345",
            operation=operation,
            cidr="10.0.0.0/16",
            attachment_id="tgw-attach-12345" if operation != "delete" else None,
        )

        assert result["operation_result"] == "success"


@pytest.mark.asyncio
async def test_analyze_tgw_routes_with_filters(mock_client):
    """Test TGW route analysis with various filter combinations"""
    filter_combinations = [
        {"state": "active"},
        {"type": "static", "state": "active"},
        {"destination_prefix": "10.0"},
        {"attachment_id": "tgw-attach-12345"},
    ]

    for filters in filter_combinations:
        mock_client.execute.return_value = {
            "routes": [
                {
                    "destination_cidr": "10.0.0.0/16",
                    "state": "active",
                    "type": "static",
                    "attachment_id": "tgw-attach-12345",
                }
            ],
            "total_routes": 1,
        }

        result = await analyze_tgw_routes(mock_client, tgw_id="tgw-12345", filter_criteria=filters)

        assert len(result["routes"]) == 1
        assert result["total_routes"] == 1


@pytest.mark.asyncio
async def test_get_core_network_change_events_pagination(mock_client):
    """Test change events retrieval with pagination"""
    mock_client.execute.return_value = {
        "events": [{"timestamp": f"2024-01-01T0{i}:00:00Z", "status": "COMPLETE"} for i in range(5)],
        "next_token": "token123",
    }

    result = await get_core_network_change_events(
        mock_client, core_network_id="core-12345", change_set_id="cs-12345", max_results=5
    )

    assert len(result["events"]) == 5
    assert result["next_token"] == "token123"


@pytest.mark.asyncio
async def test_analyze_segment_routes_detailed(mock_client):
    """Test detailed segment route analysis"""
    mock_client.execute.return_value = {
        "routes": [
            {
                "destination": "10.0.0.0/16",
                "next_hop": "attachment-12345",
                "type": "propagated",
                "state": "active",
                "attachment_type": "VPC",
            },
            {
                "destination": "172.16.0.0/12",
                "next_hop": "attachment-67890",
                "type": "static",
                "state": "active",
                "attachment_type": "TRANSIT_GATEWAY",
            },
        ],
        "segment_name": "production",
        "total_routes": 2,
    }

    result = await analyze_segment_routes(
        mock_client, core_network_id="core-12345", segment_name="production", include_details=True
    )

    assert len(result["routes"]) == 2
    assert result["total_routes"] == 2
    assert all(route["state"] == "active" for route in result["routes"])


@pytest.mark.asyncio
async def test_analyze_tgw_peers_multiple_peerings(mock_client):
    """Test analyzing multiple TGW peering connections"""
    mock_client.execute.return_value = {
        "peering_connections": [
            {
                "peering_attachment_id": "tgw-attach-peer-12345",
                "peer_tgw_id": "tgw-67890",
                "peer_region": "us-west-2",
                "state": "available",
                "peer_account_id": "123456789012",
            },
            {
                "peering_attachment_id": "tgw-attach-peer-67890",
                "peer_tgw_id": "tgw-11111",
                "peer_region": "eu-west-1",
                "state": "available",
                "peer_account_id": "210987654321",
            },
        ],
        "total_peerings": 2,
    }

    result = await analyze_tgw_peers(mock_client, tgw_id="tgw-12345", include_all_peers=True)

    assert len(result["peering_connections"]) == 2
    assert all(peer["state"] == "available" for peer in result["peering_connections"])
