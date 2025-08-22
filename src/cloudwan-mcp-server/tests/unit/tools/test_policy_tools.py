"""Unit tests for CloudWAN MCP Server policy tools."""

import pytest
import json
from unittest.mock import AsyncMock, patch

from awslabs.cloudwan_mcp_server.server import (
    validate_cloudwan_policy,
    get_core_network_policy,
    get_core_network_change_set,
    get_core_network_change_events,
    analyze_segment_routes
)


@pytest.mark.asyncio
class TestCloudWANPolicyTools:
    @pytest.mark.parametrize("policy_document", [
        {
            "version": "2023-01-01",
            "core-network-configuration": {
                "segments": ["prod", "dev"],
                "routing-mode": "static"
            }
        },
        {
            "version": "2023-02-01",
            "core-network-configuration": {
                "segments": [],
                "routing-mode": "dynamic"
            }
        }
    ])
    async def test_validate_cloudwan_policy_valid(self, policy_document):
        """Test validation of valid CloudWAN policy documents."""
        result = await validate_cloudwan_policy(policy_document)
        result_dict = json.loads(result)
        
        assert result_dict['success'] is True
        assert all(r['status'] == 'valid' for r in result_dict['validation_results'])
        assert result_dict['policy_version'] == policy_document['version']

    @pytest.mark.parametrize("invalid_policy", [
        {},  # Empty policy
        {"invalid_key": "value"},  # Missing required fields
        {"version": "2023-01-01"}  # Partial policy
    ])
    async def test_validate_cloudwan_policy_invalid(self, invalid_policy):
        """Test validation of invalid CloudWAN policy documents."""
        result = await validate_cloudwan_policy(invalid_policy)
        result_dict = json.loads(result)
        
        assert result_dict['success'] is True
        assert any(r['status'] == 'invalid' for r in result_dict['validation_results'])

    @patch('boto3.client')
    async def test_get_core_network_policy(self, mock_boto_client):
        """Test retrieving core network policy."""
        # Mock AWS client response
        mock_client = AsyncMock()
        mock_client.get_core_network_policy.return_value = {
            'CoreNetworkPolicy': {
                'PolicyVersion': '1',
                'Segments': ['prod', 'dev']
            }
        }
        mock_boto_client.return_value = mock_client

        result = await get_core_network_policy('cn-123')
        result_dict = json.loads(result)
        
        assert result_dict['success'] is True
        assert result_dict['core_network_id'] == 'cn-123'
        assert 'policy' in result_dict

    @patch('boto3.client')
    async def test_get_core_network_change_set(self, mock_boto_client):
        """Test retrieving core network change sets."""
        # Mock AWS client response
        mock_client = AsyncMock()
        mock_client.get_core_network_change_set.return_value = {
            'CoreNetworkChanges': [
                {'ChangeType': 'SEGMENT_CREATE', 'Segment': 'prod'},
                {'ChangeType': 'SEGMENT_DELETE', 'Segment': 'staging'}
            ]
        }
        mock_boto_client.return_value = mock_client

        result = await get_core_network_change_set('cn-123', 'pv-456')
        result_dict = json.loads(result)
        
        assert result_dict['success'] is True
        assert result_dict['core_network_id'] == 'cn-123'
        assert result_dict['policy_version_id'] == 'pv-456'
        assert len(result_dict['change_sets']) > 0

    @patch('boto3.client')
    async def test_analyze_segment_routes(self, mock_boto_client):
        """Test segment route analysis."""
        # Mock AWS client response
        mock_client = AsyncMock()
        mock_client.get_core_network_policy.return_value = {
            'CoreNetworkPolicy': {
                'PolicyVersion': '1',
                'Segments': ['prod']
            }
        }
        mock_boto_client.return_value = mock_client

        result = await analyze_segment_routes('cn-123', 'prod')
        result_dict = json.loads(result)
        
        assert result_dict['success'] is True
        assert result_dict['core_network_id'] == 'cn-123'
        assert result_dict['segment_name'] == 'prod'
        assert 'analysis' in result_dict
        assert 'recommendations' in result_dict['analysis']