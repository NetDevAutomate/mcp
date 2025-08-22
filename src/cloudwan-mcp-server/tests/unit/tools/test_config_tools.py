import pytest
import json
from unittest.mock import patch, AsyncMock
from awslabs.cloudwan_mcp_server.server import aws_config_manager

@pytest.mark.asyncio
class TestConfigTools:
    @patch('boto3.client')
    async def test_config_manager_valid_operations(self, mock_boto_client):
        mock_client = AsyncMock()
        mock_boto_client.return_value = mock_client

        for op in ["get", "set", "list", "reset", "get_profile", "get_region", "list_profiles", "check_credentials"]:
            result = await aws_config_manager(op, "default", "us-east-1")
            data = json.loads(result)
            assert data["success"]
            assert data["operation"] == op

    async def test_config_manager_invalid_operation(self):
        result = await aws_config_manager("badop")
        data = json.loads(result)
        assert data["success"] is False
        assert data["error"]["message"].startswith("Invalid operation: badop")