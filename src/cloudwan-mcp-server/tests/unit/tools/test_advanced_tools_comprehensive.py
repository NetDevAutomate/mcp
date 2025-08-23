from unittest.mock import AsyncMock

import pytest
from botocore.exceptions import ClientError
from cloudwan.mcp import (
    analyze_iac_firewall_policy,
    analyze_network_function_group,
    get_circuit_breaker_status,
    get_system_resilience_metrics,
    list_network_function_groups,
    simulate_iac_firewall_traffic,
    validate_iac_firewall_syntax,
)


@pytest.fixture
def mock_client():
    return AsyncMock()


# ------------------------- VALID INPUT TESTS -------------------------
@pytest.mark.asyncio
@pytest.mark.parametrize("tool_func, params, success_response", [
    # Circuit Breaker
    (get_circuit_breaker_status,
     {"service_name": "test-service"},
     {"status": "CLOSED", "failure_threshold": 5}),
    (get_system_resilience_metrics,
     {"time_window": "1h"},
     {"metrics": {"availability": 99.9, "error_rate": 0.1}}),

    # IaC Firewall
    (analyze_iac_firewall_policy,
     {"policy_json": '{"rules":[{"action":"allow"}]}'},
     {"analysis": {"allow_rules": 1, "deny_rules": 0}}),
    (simulate_iac_firewall_traffic,
     {"policy_json": '{"rules":[{"action":"deny"}]}', "traffic_samples": [{"src":"10.0.0.1","dst":"1.1.1.1"}]},
     {"simulation": {"denied": 1, "allowed": 0}}),
    (validate_iac_firewall_syntax,
     {"policy_json": '{"rules":[{"action":"allow"}]}'},
     {"is_valid": True, "errors": []}),

    # NFG
    (list_network_function_groups,
     {"region": "us-east-1"},
     {"groups": [{"id": "nfg-1", "name": "TestGroup"}]}),
    (analyze_network_function_group,
     {"group_id": "nfg-1"},
     {"analysis": {"functions": 3, "status": "HEALTHY"}}),
])
async def test_valid_inputs(mock_client, tool_func, params, success_response):
    mock_client.execute.return_value = success_response
    result = await tool_func(mock_client, **params)
    assert result == success_response
    mock_client.execute.assert_awaited_once()


# ------------------------- INVALID INPUT TESTS -------------------------
@pytest.mark.asyncio
@pytest.mark.parametrize("tool_func, invalid_params, error_message", [
    # Circuit Breaker
    (get_circuit_breaker_status, {"service_name": ""}, "service_name cannot be empty"),
    (get_system_resilience_metrics, {"time_window": "99x"}, "Invalid time_window format"),

    # IaC Firewall
    (analyze_iac_firewall_policy, {"policy_json": "not-a-json"}, "Invalid JSON policy"),
    (simulate_iac_firewall_traffic, {"traffic_samples": []}, "policy_json is required"),
    (validate_iac_firewall_syntax, {"policy_json": ""}, "policy_json cannot be empty"),

    # NFG
    (list_network_function_groups, {"region": ""}, "region cannot be empty"),
    (analyze_network_function_group, {"group_id": ""}, "group_id cannot be empty"),
])
async def test_invalid_inputs(mock_client, tool_func, invalid_params, error_message):
    with pytest.raises(ValueError) as excinfo:
        await tool_func(mock_client, **invalid_params)
    assert error_message in str(excinfo.value)


# ------------------------- AWS ERROR HANDLING -------------------------
@pytest.mark.asyncio
@pytest.mark.parametrize("tool_func, params", [
    (get_circuit_breaker_status, {"service_name": "svc"}),
    (get_system_resilience_metrics, {"time_window": "1h"}),
    (analyze_iac_firewall_policy, {"policy_json": '{"rules":[{}]}'}),
    (simulate_iac_firewall_traffic, {"policy_json": '{"rules":[]}', "traffic_samples": [{"src": "1", "dst": "2"}]}),
    (validate_iac_firewall_syntax, {"policy_json": '{"rules":[]'}),  # broken intentionally
    (list_network_function_groups, {"region": "us-east-1"}),
    (analyze_network_function_group, {"group_id": "nfg-1"}),
])
async def test_aws_error_handling(mock_client, tool_func, params):
    mock_client.execute.side_effect = ClientError(
        {"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}},
        "ExecuteOperation"
    )
    with pytest.raises(ClientError) as excinfo:
        await tool_func(mock_client, **params)
    assert excinfo.value.response["Error"]["Code"] == "ThrottlingException"
    mock_client.execute.assert_awaited_once()


# ------------------------- COMPLEX SCENARIOS -------------------------
@pytest.mark.asyncio
async def test_resilience_metrics_with_dimensions(mock_client):
    mock_client.execute.return_value = {
        "metrics": {
            "availability": 99.95,
            "error_rate": 0.05,
            "latency_p95": 250
        },
        "dimensions": {"region": "us-east-1", "service": "network"}
    }
    result = await get_system_resilience_metrics(
        mock_client,
        time_window="24h",
        dimensions={"region": "us-east-1", "service": "network"}
    )
    assert "latency_p95" in result["metrics"]
    assert result["dimensions"]["service"] == "network"


@pytest.mark.asyncio
async def test_analyze_iac_policy_complex(mock_client):
    complex_policy = {
        "rules": [
            {"id": "1", "action": "allow", "src": "10.0.0.0/8", "dst": "0.0.0.0/0", "protocol": "tcp"},
            {"id": "2", "action": "deny", "src": "192.168.0.0/16", "dst": "10.0.0.0/8", "protocol": "udp"}
        ]
    }
    mock_client.execute.return_value = {
        "analysis": {
            "allow_rules": 1,
            "deny_rules": 1,
            "conflicts": [],
            "complexity_score": 5.0
        }
    }
    result = await analyze_iac_firewall_policy(mock_client, policy_json=str(complex_policy))
    assert result["analysis"]["allow_rules"] == 1
    assert result["analysis"]["deny_rules"] == 1


@pytest.mark.asyncio
async def test_simulate_iac_firewall_multiple_traffic(mock_client):
    traffic_samples = [
        {"src": "10.0.0.1", "dst": "8.8.8.8", "protocol": "tcp", "port": 443},
        {"src": "192.168.1.1", "dst": "1.1.1.1", "protocol": "tcp", "port": 22}
    ]
    mock_client.execute.return_value = {
        "simulation": {
            "allowed": 1,
            "denied": 1,
            "results": [
                {"traffic": traffic_samples[0], "decision": "allow"},
                {"traffic": traffic_samples[1], "decision": "deny"}
            ]
        }
    }
    result = await simulate_iac_firewall_traffic(
        mock_client,
        policy_json='{"rules":[]}',
        traffic_samples=traffic_samples,
        detailed=True
    )
    assert result["simulation"]["allowed"] == 1
    assert any(r["decision"] == "deny" for r in result["simulation"]["results"])


@pytest.mark.asyncio
async def test_validate_iac_syntax_with_errors(mock_client):
    mock_client.execute.return_value = {
        "is_valid": False,
        "errors": [
            {"rule_id": "0", "error": "Missing action field"},
            {"rule_id": "1", "error": "Invalid CIDR block"}
        ]
    }
    result = await validate_iac_firewall_syntax(mock_client, policy_json='{"rules":[{}]}')
    assert result["is_valid"] is False
    assert len(result["errors"]) == 2


@pytest.mark.asyncio
async def test_nfg_analysis_multiple_functions(mock_client):
    mock_client.execute.return_value = {
        "analysis": {
            "functions": [
                {"name": "fw", "status": "HEALTHY"},
                {"name": "dpi", "status": "DEGRADED"}
            ],
            "summary": {"healthy": 1, "degraded": 1}
        }
    }
    result = await analyze_network_function_group(mock_client, group_id="nfg-12345", include_details=True)
    assert result["analysis"]["summary"]["degraded"] == 1
    assert any(fn["status"] == "DEGRADED" for fn in result["analysis"]["functions"])