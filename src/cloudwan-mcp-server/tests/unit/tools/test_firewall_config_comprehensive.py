from unittest.mock import AsyncMock

import pytest
from botocore.exceptions import ClientError
from cloudwan.mcp import (
    analyze_anfw_policy,
    analyze_five_tuple_flow,
    aws_config_manager,
    monitor_anfw_logs,
    parse_suricata_rules,
    simulate_policy_changes,
)


@pytest.fixture
def mock_client():
    return AsyncMock()


@pytest.fixture
def sample_firewall_policy():
    """Sample AWS Network Firewall policy for testing"""
    return {
        "FirewallPolicyName": "test-policy",
        "FirewallPolicy": {
            "StatelessDefaultActions": ["aws:forward_to_sfe"],
            "StatelessFragmentDefaultActions": ["aws:forward_to_sfe"],
            "StatefulRuleGroupReferences": [
                {
                    "ResourceArn": "arn:aws:network-firewall:us-east-1:123456789012:stateful-rulegroup/test-rules",
                    "Priority": 1,
                }
            ],
        },
    }


@pytest.fixture
def sample_suricata_rules():
    """Sample Suricata rules for testing"""
    return """
    alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious outbound connection"; flow:to_server,established; content:"malware"; sid:1000001; rev:1;)
    drop tcp any any -> any 22 (msg:"Block SSH"; sid:1000002; rev:1;)
    pass tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Allow HTTPS"; sid:1000003; rev:1;)
    """


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tool_func, params, success_response",
    [
        # Network Firewall Tools
        (
            monitor_anfw_logs,
            {"firewall_name": "test-firewall", "log_group": "/aws/networkfirewall/test", "time_range": "1h"},
            {"logs": [{"timestamp": "2024-01-01T00:00:00Z", "event_type": "ALERT"}], "total_events": 1},
        ),
        (
            analyze_anfw_policy,
            {"policy_arn": "arn:aws:network-firewall:us-east-1:123456789012:firewall-policy/test-policy"},
            {"analysis": {"rule_groups": 3, "stateless_rules": 10, "stateful_rules": 15}},
        ),
        (
            analyze_five_tuple_flow,
            {"source_ip": "10.0.0.1", "dest_ip": "8.8.8.8", "source_port": 54321, "dest_port": 443, "protocol": "TCP"},
            {"flow_analysis": {"action": "ALLOW", "matching_rules": ["allow-https"], "risk_score": 0.1}},
        ),
        (
            parse_suricata_rules,
            {"rule_content": 'alert tcp any any -> any 80 (msg:"HTTP traffic"; sid:1000001;)'},
            {"parsed_rules": [{"action": "alert", "protocol": "tcp", "message": "HTTP traffic", "sid": "1000001"}]},
        ),
        (
            simulate_policy_changes,
            {
                "current_policy": {"rules": []},
                "proposed_changes": {"add_rules": ["rule1"]},
                "test_traffic": [{"src": "10.0.0.1"}],
            },
            {"simulation_results": {"allowed": 5, "blocked": 2, "alerts": 1}},
        ),
        # Configuration Tool
        (
            aws_config_manager,
            {"operation": "get_compliance", "resource_type": "AWS::EC2::Instance", "region": "us-east-1"},
            {"compliance_status": {"compliant": 45, "non_compliant": 5, "total": 50}},
        ),
    ],
)
async def test_valid_inputs(mock_client, tool_func, params, success_response):
    """Test all firewall and config tools with valid parameter combinations"""
    mock_client.execute.return_value = success_response
    result = await tool_func(mock_client, **params)
    assert result == success_response
    mock_client.execute.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tool_func, invalid_params, error_message",
    [
        # Network Firewall validation errors
        (
            monitor_anfw_logs,
            {"firewall_name": "", "log_group": "/aws/networkfirewall/test"},
            "firewall_name cannot be empty",
        ),
        (monitor_anfw_logs, {"firewall_name": "test", "time_range": "invalid"}, "Invalid time_range format"),
        (analyze_anfw_policy, {"policy_arn": "invalid-arn"}, "Invalid policy ARN format"),
        (
            analyze_five_tuple_flow,
            {"source_ip": "invalid-ip", "dest_ip": "8.8.8.8", "protocol": "TCP"},
            "Invalid source IP address",
        ),
        (
            analyze_five_tuple_flow,
            {"source_ip": "10.0.0.1", "dest_ip": "8.8.8.8", "source_port": 70000, "protocol": "TCP"},
            "Invalid source port number",
        ),
        (
            analyze_five_tuple_flow,
            {"source_ip": "10.0.0.1", "dest_ip": "8.8.8.8", "protocol": "INVALID"},
            "Invalid protocol. Must be TCP, UDP, or ICMP",
        ),
        (parse_suricata_rules, {"rule_content": ""}, "rule_content cannot be empty"),
        (simulate_policy_changes, {"current_policy": None, "proposed_changes": {}}, "current_policy is required"),
        # Configuration validation errors
        (aws_config_manager, {"operation": "invalid_op", "resource_type": "AWS::EC2::Instance"}, "Invalid operation"),
        (
            aws_config_manager,
            {"operation": "get_compliance", "resource_type": "InvalidResourceType"},
            "Invalid resource type format",
        ),
    ],
)
async def test_invalid_inputs(mock_client, tool_func, invalid_params, error_message):
    """Test parameter validation for all firewall and config tools"""
    with pytest.raises(ValueError) as excinfo:
        await tool_func(mock_client, **invalid_params)
    assert error_message in str(excinfo.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tool_func, params",
    [
        (monitor_anfw_logs, {"firewall_name": "test-firewall", "log_group": "/aws/networkfirewall/test"}),
        (analyze_anfw_policy, {"policy_arn": "arn:aws:network-firewall:us-east-1:123456789012:firewall-policy/test"}),
        (analyze_five_tuple_flow, {"source_ip": "10.0.0.1", "dest_ip": "8.8.8.8", "protocol": "TCP"}),
        (parse_suricata_rules, {"rule_content": "alert tcp any any -> any 80"}),
        (simulate_policy_changes, {"current_policy": {"rules": []}, "proposed_changes": {}}),
        (aws_config_manager, {"operation": "get_compliance", "resource_type": "AWS::EC2::Instance"}),
    ],
)
async def test_aws_error_handling(mock_client, tool_func, params):
    """Test AWS error handling for all firewall and config tools"""
    mock_client.execute.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "Access denied"}}, "ExecuteOperation"
    )

    with pytest.raises(ClientError) as excinfo:
        await tool_func(mock_client, **params)

    assert excinfo.value.response["Error"]["Code"] == "AccessDeniedException"
    mock_client.execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_monitor_anfw_logs_with_filters(mock_client):
    """Test ANFW log monitoring with various filter combinations"""
    filter_combinations = [
        {"event_type": "ALERT", "severity": "HIGH"},
        {"source_ip": "10.0.0.1", "action": "DROP"},
        {"protocol": "TCP", "destination_port": 443},
        {"time_range": "24h", "limit": 100},
    ]

    for filters in filter_combinations:
        mock_client.execute.return_value = {
            "logs": [
                {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "event_type": "ALERT",
                    "severity": "HIGH",
                    "source_ip": "10.0.0.1",
                    "action": "DROP",
                }
            ],
            "total_events": 1,
            "filtered_by": list(filters.keys()),
        }

        result = await monitor_anfw_logs(
            mock_client, firewall_name="test-firewall", log_group="/aws/networkfirewall/test", **filters
        )

        assert len(result["logs"]) == 1
        assert "filtered_by" in result


@pytest.mark.asyncio
async def test_analyze_anfw_policy_detailed(mock_client, sample_firewall_policy):
    """Test detailed ANFW policy analysis"""
    mock_client.execute.return_value = {
        "policy_details": sample_firewall_policy,
        "analysis": {
            "rule_groups": {"stateless": 2, "stateful": 3, "total": 5},
            "default_actions": {"stateless": ["aws:forward_to_sfe"], "stateless_fragment": ["aws:forward_to_sfe"]},
            "complexity_score": 7.5,
            "recommendations": ["Consider adding explicit deny rules", "Enable logging for all rule groups"],
        },
    }

    result = await analyze_anfw_policy(
        mock_client,
        policy_arn="arn:aws:network-firewall:us-east-1:123456789012:firewall-policy/test-policy",
        include_recommendations=True,
    )

    assert result["analysis"]["rule_groups"]["total"] == 5
    assert len(result["analysis"]["recommendations"]) == 2
    assert result["analysis"]["complexity_score"] == 7.5


@pytest.mark.asyncio
async def test_analyze_five_tuple_flow_scenarios(mock_client):
    """Test five-tuple flow analysis with different scenarios"""
    test_scenarios = [
        {
            "params": {
                "source_ip": "10.0.0.1",
                "dest_ip": "8.8.8.8",
                "source_port": 54321,
                "dest_port": 53,
                "protocol": "UDP",
            },
            "expected_action": "ALLOW",
            "expected_service": "DNS",
        },
        {
            "params": {
                "source_ip": "192.168.1.100",
                "dest_ip": "10.0.0.5",
                "source_port": 12345,
                "dest_port": 22,
                "protocol": "TCP",
            },
            "expected_action": "BLOCK",
            "expected_service": "SSH",
        },
        {
            "params": {"source_ip": "172.16.0.10", "dest_ip": "1.1.1.1", "protocol": "ICMP"},
            "expected_action": "ALLOW",
            "expected_service": "PING",
        },
    ]

    for scenario in test_scenarios:
        mock_client.execute.return_value = {
            "flow_analysis": {
                "action": scenario["expected_action"],
                "service": scenario["expected_service"],
                "matching_rules": [f"rule-{scenario['expected_service'].lower()}"],
                "risk_score": 0.1 if scenario["expected_action"] == "ALLOW" else 0.8,
            }
        }

        result = await analyze_five_tuple_flow(mock_client, **scenario["params"])

        assert result["flow_analysis"]["action"] == scenario["expected_action"]
        assert result["flow_analysis"]["service"] == scenario["expected_service"]


@pytest.mark.asyncio
async def test_parse_suricata_rules_complex(mock_client, sample_suricata_rules):
    """Test parsing complex Suricata rules"""
    mock_client.execute.return_value = {
        "parsed_rules": [
            {
                "action": "alert",
                "protocol": "tcp",
                "source": "$HOME_NET any",
                "destination": "$EXTERNAL_NET any",
                "message": "Suspicious outbound connection",
                "options": {"flow": "to_server,established", "content": "malware"},
                "sid": "1000001",
                "rev": "1",
            },
            {
                "action": "drop",
                "protocol": "tcp",
                "source": "any any",
                "destination": "any 22",
                "message": "Block SSH",
                "sid": "1000002",
                "rev": "1",
            },
            {
                "action": "pass",
                "protocol": "tcp",
                "source": "$HOME_NET any",
                "destination": "$EXTERNAL_NET 443",
                "message": "Allow HTTPS",
                "sid": "1000003",
                "rev": "1",
            },
        ],
        "statistics": {"total_rules": 3, "alert_rules": 1, "drop_rules": 1, "pass_rules": 1},
    }

    result = await parse_suricata_rules(mock_client, rule_content=sample_suricata_rules, validate_syntax=True)

    assert len(result["parsed_rules"]) == 3
    assert result["statistics"]["total_rules"] == 3
    assert result["statistics"]["alert_rules"] == 1
    assert result["statistics"]["drop_rules"] == 1
    assert result["statistics"]["pass_rules"] == 1


@pytest.mark.asyncio
async def test_simulate_policy_changes_comprehensive(mock_client):
    """Test comprehensive policy change simulation"""
    current_policy = {
        "rules": [{"action": "allow", "source": "10.0.0.0/8", "destination": "any", "protocol": "tcp", "port": 443}]
    }

    proposed_changes = {
        "add_rules": [
            {"action": "deny", "source": "192.168.0.0/16", "destination": "any", "protocol": "tcp", "port": 22}
        ],
        "remove_rules": [],
        "modify_rules": [{"old": {"port": 443}, "new": {"port": 8443}}],
    }

    test_traffic = [
        {"src": "10.0.0.1", "dst": "8.8.8.8", "proto": "tcp", "port": 443},
        {"src": "192.168.1.1", "dst": "1.1.1.1", "proto": "tcp", "port": 22},
        {"src": "172.16.0.1", "dst": "8.8.4.4", "proto": "udp", "port": 53},
    ]

    mock_client.execute.return_value = {
        "simulation_results": {
            "current_policy": {"allowed": 2, "blocked": 1, "alerts": 0},
            "proposed_policy": {"allowed": 1, "blocked": 2, "alerts": 0},
            "impact_analysis": {"newly_blocked": 1, "newly_allowed": 0, "unchanged": 2},
            "detailed_results": [
                {
                    "traffic": test_traffic[0],
                    "current_action": "allow",
                    "proposed_action": "allow",
                    "matching_rule": "modified-https-rule",
                },
                {
                    "traffic": test_traffic[1],
                    "current_action": "allow",
                    "proposed_action": "deny",
                    "matching_rule": "new-ssh-deny-rule",
                },
            ],
        }
    }

    result = await simulate_policy_changes(
        mock_client,
        current_policy=current_policy,
        proposed_changes=proposed_changes,
        test_traffic=test_traffic,
        detailed_analysis=True,
    )

    assert result["simulation_results"]["impact_analysis"]["newly_blocked"] == 1
    assert len(result["simulation_results"]["detailed_results"]) == 2


@pytest.mark.asyncio
async def test_aws_config_manager_operations(mock_client):
    """Test various AWS Config Manager operations"""
    operations = [
        {
            "operation": "get_compliance",
            "params": {"resource_type": "AWS::EC2::Instance", "compliance_type": "NON_COMPLIANT"},
            "expected_keys": ["compliance_status", "non_compliant_resources"],
        },
        {
            "operation": "get_resource_history",
            "params": {"resource_id": "i-1234567890abcdef0", "resource_type": "AWS::EC2::Instance"},
            "expected_keys": ["configuration_items", "resource_timeline"],
        },
        {
            "operation": "evaluate_rules",
            "params": {"rule_names": ["required-tags", "encrypted-volumes"]},
            "expected_keys": ["evaluation_results", "compliance_summary"],
        },
        {
            "operation": "get_discovered_resources",
            "params": {"resource_type": "AWS::RDS::DBInstance", "include_deleted": False},
            "expected_keys": ["resources", "total_count"],
        },
    ]

    for op_config in operations:
        mock_response = {key: {} for key in op_config["expected_keys"]}
        mock_response.update({"operation": op_config["operation"], "timestamp": "2024-01-01T00:00:00Z"})

        mock_client.execute.return_value = mock_response

        result = await aws_config_manager(mock_client, operation=op_config["operation"], **op_config["params"])

        assert result["operation"] == op_config["operation"]
        for key in op_config["expected_keys"]:
            assert key in result


@pytest.mark.asyncio
async def test_aws_config_manager_aggregated_compliance(mock_client):
    """Test AWS Config Manager with aggregated compliance data"""
    mock_client.execute.return_value = {
        "aggregated_compliance": {
            "by_resource_type": {
                "AWS::EC2::Instance": {"compliant": 45, "non_compliant": 5, "total": 50},
                "AWS::RDS::DBInstance": {"compliant": 10, "non_compliant": 2, "total": 12},
                "AWS::S3::Bucket": {"compliant": 25, "non_compliant": 3, "total": 28},
            },
            "by_rule": {
                "required-tags": {"compliant": 70, "non_compliant": 10},
                "encrypted-storage": {"compliant": 75, "non_compliant": 5},
            },
            "overall_compliance_score": 88.9,
        }
    }

    result = await aws_config_manager(
        mock_client,
        operation="get_aggregated_compliance",
        aggregator_name="organization-aggregator",
        group_by=["RESOURCE_TYPE", "RULE"],
    )

    assert result["aggregated_compliance"]["overall_compliance_score"] == 88.9
    assert len(result["aggregated_compliance"]["by_resource_type"]) == 3
    assert len(result["aggregated_compliance"]["by_rule"]) == 2


@pytest.mark.asyncio
async def test_monitor_anfw_logs_real_time_streaming(mock_client):
    """Test real-time log streaming for ANFW"""
    mock_client.execute.return_value = {
        "streaming_enabled": True,
        "stream_config": {"buffer_size": 100, "flush_interval": 5, "filter_pattern": "ALERT HIGH"},
        "initial_logs": [
            {
                "timestamp": "2024-01-01T00:00:00Z",
                "event_type": "ALERT",
                "severity": "HIGH",
                "message": "Potential threat detected",
            }
        ],
    }

    result = await monitor_anfw_logs(
        mock_client,
        firewall_name="test-firewall",
        log_group="/aws/networkfirewall/test",
        stream_mode=True,
        filter_pattern="ALERT HIGH",
    )

    assert result["streaming_enabled"] is True
    assert result["stream_config"]["filter_pattern"] == "ALERT HIGH"
    assert len(result["initial_logs"]) == 1
