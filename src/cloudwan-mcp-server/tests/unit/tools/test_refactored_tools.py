import json
from unittest.mock import MagicMock, patch
import pytest

from awslabs.cloudwan_mcp_server import server


@pytest.mark.asyncio
class TestListCoreNetworks:
    async def test_list_core_networks_success(self):
        with patch("awslabs.cloudwan_mcp_server.server.get_aws_client") as mock_client:
            mock = MagicMock()
            mock.list_core_networks.return_value = {"CoreNetworks": [{"CoreNetworkId": "cn-123"}]}
            mock_client.return_value = mock

            result = await server.list_core_networks("us-east-1")
            data = json.loads(result)
            assert data["success"]
            assert data["total_count"] == 1
            assert "CoreNetworkId" in data["core_networks"][0]

    async def test_list_core_networks_client_error(self):
        with patch("awslabs.cloudwan_mcp_server.server.get_aws_client") as mock_client:
            mock = MagicMock()
            mock.list_core_networks.side_effect = Exception("Boom")
            mock_client.return_value = mock

            result = await server.list_core_networks("us-east-1")
            data = json.loads(result)
            assert not data["success"]
            assert data["error"]["code"] == server.ErrorCode.AWS_ERROR.value


@pytest.mark.asyncio
class TestManageTgwRoutes:
    async def test_manage_tgw_routes_valid_cidr(self):
        result = await server.manage_tgw_routes("create", "rtb-123", "10.0.0.0/16", "us-east-1")
        data = json.loads(result)
        assert data["success"]
        assert data["destination_cidr"] == "10.0.0.0/16"

    async def test_manage_tgw_routes_invalid_cidr(self):
        result = await server.manage_tgw_routes("create", "rtb-123", "invalid-cidr")
        data = json.loads(result)
        assert not data["success"]
        assert data["error"]["code"] == server.ErrorCode.AWS_ERROR.value


@pytest.mark.asyncio
class TestValidateCloudwanPolicy:
    async def test_validate_cloudwan_policy_missing_fields(self):
        policy_doc = {"version": "2021.12"}  # missing core-network-configuration
        result = await server.validate_cloudwan_policy(policy_doc)
        data = json.loads(result)
        assert data["success"]
        statuses = [r["status"] for r in data["validation_results"]]
        assert "invalid" in statuses

    async def test_validate_cloudwan_policy_all_fields_present(self):
        policy_doc = {"version": "2021.12", "core-network-configuration": {}}
        result = await server.validate_cloudwan_policy(policy_doc)
        data = json.loads(result)
        assert data["success"]
        assert data["overall_status"] == "valid"
        assert data["policy_version"] == "2021.12"


@pytest.mark.asyncio
class TestAnalyzeNetworkFunctionGroup:
    async def test_analyze_network_function_group_success(self):
        result = await server.analyze_network_function_group("prod-nfg", "us-west-2")
        data = json.loads(result)
        assert data["success"]
        assert data["group_name"] == "prod-nfg"
        assert "analysis" in data
        assert "routing_policies" in data["analysis"]

    async def test_analyze_network_function_group_exception(self):
        with patch("awslabs.cloudwan_mcp_server.server.aws_config") as mock_cfg:
            mock_cfg.default_region = "us-east-1"
            # Patch to force exception
            with patch("awslabs.cloudwan_mcp_server.server.safe_json_dumps", side_effect=Exception("fail")):
                result = await server.analyze_network_function_group("prod-nfg")
                data = json.loads(result)
                assert not data["success"]
                assert data["error"]["operation"] == "analyze_network_function_group"


# Backward compatibility tests validating response schema
@pytest.mark.asyncio
class TestBackwardCompatibility:
    async def test_error_response_schema(self):
        result = await server.manage_tgw_routes("create", "rtb-123", "invalid-cidr")
        data = json.loads(result)
        assert "error" in data
        assert "code" in data["error"]
        assert "message" in data["error"]

    async def test_success_response_schema(self):
        result = await server.list_network_function_groups()
        data = json.loads(result)
        assert "success" in data
        assert data["success"] in (True, False)
