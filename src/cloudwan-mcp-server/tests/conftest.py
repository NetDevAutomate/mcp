"""Pytest configuration and shared fixtures for CloudWAN MCP Server tests."""

import pytest
from unittest.mock import patch, AsyncMock


@pytest.fixture
def mock_aws_client():
    """Mock AWS client that returns success responses."""
    mock_client = AsyncMock()

    # Mock common responses
    mock_client.list_core_networks.return_value = {"CoreNetworks": []}
    mock_client.describe_vpcs.return_value = {"Vpcs": []}
    mock_client.describe_global_networks.return_value = {"GlobalNetworks": []}
    mock_client.filter_log_events.return_value = {"events": []}
    mock_client.describe_firewall_policy.return_value = {"FirewallPolicy": {}}

    # Added security pragma for mock credentials
    mock_client.get_credentials.return_value = {
        "AccessKeyId": "TESTKEY123",
        "SecretAccessKey": "SECRETTESTKEY",  # pragma: allowlist secret
    }

    return mock_client


@pytest.fixture
def mock_get_aws_client(mock_aws_client):
    """Mock the get_aws_client function."""
    with patch("awslabs.cloudwan_mcp_server.server.get_aws_client", return_value=mock_aws_client):
        yield mock_aws_client


# Configure pytest markers and options
def pytest_configure(config):
    """Configure pytest with custom markers and settings."""
    config.addinivalue_line("markers", "unit: Unit tests for individual components")
    config.addinivalue_line("markers", "integration: Integration tests that span multiple components")
    config.addinivalue_line("markers", "slow: Tests that may take longer due to network calls")
