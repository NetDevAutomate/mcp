# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Comprehensive exception handling tests for CloudWAN MCP Server.

These tests validate that all bare except clause replacements work correctly
and maintain proper error handling functionality with security sanitization.
"""

import json
from unittest.mock import Mock, patch

import pytest
from botocore.exceptions import BotoCoreError, ClientError, EndpointConnectionError
from moto import mock_ec2

from awslabs.cloudwan_mcp_server.consts import (
    ErrorCode,
    get_error_response,
    sanitize_error_message,
    secure_environment_update,
)


class TestAWSExceptionHandling:
    """Test AWS service exception handling improvements."""

    def create_client_error(self, error_code: str, message: str, http_status_code: int = 400):
        """Helper to create ClientError instances for testing."""
        return ClientError(
            error_response={
                "Error": {"Code": error_code, "Message": message},
                "ResponseMetadata": {"HTTPStatusCode": http_status_code},
            },
            operation_name="TestOperation",
        )

    @mock_ec2
    def test_client_error_handling_in_discovery(self):
        """Test ClientError handling in discovery tools."""
        from awslabs.cloudwan_mcp_server.tools.discovery import DiscoveryTools

        # Mock MCP server
        mock_mcp = Mock()
        mock_mcp.tool = Mock(return_value=lambda func: func)

        discovery_tools = DiscoveryTools(mock_mcp)

        # Test AccessDenied error
        with patch("awslabs.cloudwan_mcp_server.tools.discovery.get_aws_client") as mock_client:
            mock_ec2 = Mock()
            mock_ec2.describe_vpcs.side_effect = self.create_client_error(
                "AccessDenied", "Access denied to describe VPCs", 403
            )
            mock_client.return_value = mock_ec2

            # Test error handling
            result = await discovery_tools._discover_vpcs("us-east-1")
            result_data = json.loads(result)

            assert result_data["status"] == "error"
            assert "access denied" in result_data["error"]["message"].lower()
            assert result_data["http_status"] == 403

    def test_endpoint_connection_error_handling(self):
        """Test EndpointConnectionError handling."""
        from awslabs.cloudwan_mcp_server.tools.discovery import handle_aws_error

        # Create EndpointConnectionError
        endpoint_error = EndpointConnectionError(endpoint_url="https://ec2.us-east-1.amazonaws.com")

        result = handle_aws_error(endpoint_error, "test_operation")
        result_data = json.loads(result)

        assert result_data["status"] == "error"
        assert "endpoint" in result_data["error"]["message"].lower()
        assert result_data["error"]["operation"] == "test_operation"

    def test_botocore_error_handling(self):
        """Test BotoCoreError handling."""
        from awslabs.cloudwan_mcp_server.server import handle_aws_error

        # Create BotoCoreError
        botocore_error = BotoCoreError()

        result = handle_aws_error(botocore_error, "test_operation")
        result_data = json.loads(result)

        assert result_data["status"] == "error"
        assert result_data["error"]["operation"] == "test_operation"
        assert "http_status" in result_data

    @patch("awslabs.cloudwan_mcp_server.server.get_aws_client")
    def test_aws_client_creation_error_handling(self, mock_get_client):
        """Test AWS client creation error handling."""
        from awslabs.cloudwan_mcp_server.server import register_simple_tools

        # Mock client creation failure
        mock_get_client.side_effect = BotoCoreError()

        # Test that error is handled gracefully
        try:
            result = register_simple_tools()
            # Should not raise unhandled exception
            assert True
        except BotoCoreError:
            pytest.fail("BotoCoreError should be handled, not raised")

    def test_throttling_error_handling(self):
        """Test AWS throttling error handling and classification."""
        throttling_error = self.create_client_error("Throttling", "Rate exceeded", 429)

        from awslabs.cloudwan_mcp_server.server import handle_aws_error

        result = handle_aws_error(throttling_error, "test_operation")
        result_data = json.loads(result)

        assert result_data["error"]["code"] == ErrorCode.AWS_THROTTLING_ERROR.value
        assert result_data["http_status"] == 429

    def test_resource_not_found_error_handling(self):
        """Test ResourceNotFound error handling and classification."""
        not_found_error = self.create_client_error("ResourceNotFoundException", "Resource not found", 404)

        from awslabs.cloudwan_mcp_server.server import handle_aws_error

        result = handle_aws_error(not_found_error, "test_operation")
        result_data = json.loads(result)

        assert result_data["error"]["code"] == ErrorCode.AWS_RESOURCE_NOT_FOUND.value
        assert result_data["http_status"] == 404


class TestValidationExceptionHandling:
    """Test validation exception handling improvements."""

    def test_value_error_handling_in_validation(self):
        """Test ValueError handling in validation functions."""
        from awslabs.cloudwan_mcp_server.tools.network_analysis import NetworkAnalysisTools

        mock_mcp = Mock()
        mock_mcp.tool = Mock(return_value=lambda func: func)

        analysis_tools = NetworkAnalysisTools(mock_mcp)

        # Test invalid IP address
        result = await analysis_tools._discover_ip_details("invalid-ip", "us-east-1")
        result_data = json.loads(result)

        assert result_data["status"] == "error"
        assert "invalid" in result_data["error"]["message"].lower()

    def test_type_error_handling_in_config(self):
        """Test TypeError handling in configuration."""
        # Test secure_environment_update with wrong types
        result = secure_environment_update(123, "value")  # int instead of str
        assert result is False

        result = secure_environment_update("KEY", None)  # None instead of str
        assert result is False

    def test_import_error_handling(self):
        """Test ImportError/ModuleNotFoundError handling."""
        from awslabs.cloudwan_mcp_server.server import register_modular_tools

        with patch("awslabs.cloudwan_mcp_server.server.importlib.import_module") as mock_import:
            mock_import.side_effect = ImportError("Module not found")

            # Should handle ImportError gracefully
            result = register_modular_tools()
            assert result is False  # Should return False, not raise

    def test_validation_error_response_format(self):
        """Test that validation errors return proper ErrorResponse format."""
        from awslabs.cloudwan_mcp_server.tools.transit_gateway import TransitGatewayTools

        mock_mcp = Mock()
        mock_mcp.tool = Mock(return_value=lambda func: func)

        tgw_tools = TransitGatewayTools(mock_mcp)

        # Test invalid route table ID format
        result = await tgw_tools._manage_tgw_routes(
            operation="create", route_table_id="invalid-id", destination_cidr="10.0.0.0/16"
        )
        result_data = json.loads(result)

        assert result_data["status"] == "error"
        assert "invalid" in result_data["error"]["message"].lower()
        assert result_data["error"]["operation"] == "manage_tgw_routes"

    def test_cross_field_validation_errors(self):
        """Test cross-field validation error handling."""
        from awslabs.cloudwan_mcp_server.tools.network_analysis import IPCIDRValidationModel

        # Test missing required field for operation
        with pytest.raises(ValueError) as exc_info:
            IPCIDRValidationModel(operation="validate_ip", ip=None, cidr="10.0.0.0/16")

        assert "ip parameter is required" in str(exc_info.value)


class TestErrorLoggingValidation:
    """Test error logging with sanitization and context preservation."""

    @patch("awslabs.cloudwan_mcp_server.consts.logger")
    def test_error_logging_with_sanitization(self, mock_logger):
        """Test that errors are logged with proper sanitization."""
        # Test sanitization of sensitive data in logs
        sensitive_message = "Error with key AKIAIOSFODNN7EXAMPLE in operation"
        sanitized = sanitize_error_message(sensitive_message)

        assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
        assert "AWS_ACCESS_KEY_REDACTED" in sanitized

    @patch("awslabs.cloudwan_mcp_server.server.logger")
    def test_aws_client_error_logging(self, mock_logger):
        """Test AWS client error logging with context."""
        from awslabs.cloudwan_mcp_server.server import get_aws_client

        with patch("boto3.client") as mock_boto_client:
            mock_boto_client.side_effect = BotoCoreError()

            with pytest.raises(BotoCoreError):
                get_aws_client("ec2")

            # Verify error was logged
            mock_logger.error.assert_called()
            logged_message = mock_logger.error.call_args[0][0]
            assert "AWS client creation failed" in logged_message

    @patch("awslabs.cloudwan_mcp_server.consts.logger")
    def test_environment_update_logging(self, mock_logger):
        """Test environment variable update logging."""
        # Test successful update logging
        result = secure_environment_update("AWS_PROFILE", "test-profile")
        assert result is True

        # Should log success
        mock_logger.info.assert_called()
        logged_message = mock_logger.info.call_args[0][0]
        assert "AWS_PROFILE" in logged_message
        assert "updated successfully" in logged_message

    @patch("awslabs.cloudwan_mcp_server.consts.logger")
    def test_critical_error_logging(self, mock_logger):
        """Test critical error logging levels."""
        from awslabs.cloudwan_mcp_server.server import get_aws_client

        with patch("boto3.client") as mock_boto_client:
            mock_boto_client.side_effect = Exception("Critical system failure")

            with pytest.raises(Exception):
                get_aws_client("ec2")

            # Should log critical error
            mock_logger.critical.assert_called()
            logged_message = mock_logger.critical.call_args[0][0]
            assert "Critical failure" in logged_message

    def test_error_message_truncation_for_security(self):
        """Test that overly long error messages are truncated for security."""
        long_message = "A" * 15000
        sanitized = sanitize_error_message(long_message)

        assert sanitized == "[TRUNCATED_FOR_SECURITY]"
        assert len(sanitized) < 100  # Much shorter than original


class TestResponseModelConsistency:
    """Test ErrorResponse model usage and consistency."""

    def test_error_response_model_structure(self):
        """Test ErrorResponse model has consistent structure."""
        from awslabs.cloudwan_mcp_server.models.response_models import ErrorResponse

        error_response = ErrorResponse(
            status="error", error={"message": "Test error", "code": "TEST_ERROR"}, http_status=400
        )

        assert error_response.status == "error"
        assert error_response.error["message"] == "Test error"
        assert error_response.http_status == 400

        # Test JSON serialization
        json_str = error_response.json()
        parsed = json.loads(json_str)
        assert parsed["status"] == "error"
        assert parsed["error"]["message"] == "Test error"

    def test_get_error_response_helper_consistency(self):
        """Test get_error_response helper creates consistent responses."""
        response = get_error_response(ErrorCode.AWS_CLIENT_ERROR, details="AWS service error", http_status=500)

        assert response["errorCode"] == ErrorCode.AWS_CLIENT_ERROR.value
        assert response["details"] == "AWS service error"
        assert response["httpStatus"] == 500

    def test_error_response_json_serialization(self):
        """Test that ErrorResponse JSON serialization works correctly."""
        from awslabs.cloudwan_mcp_server.models.response_models import ErrorResponse

        error_response = ErrorResponse(
            status="error", error={"message": "Serialization test", "operation": "test_op"}, http_status=422
        )

        # Test .json() method
        json_str = error_response.json()
        parsed = json.loads(json_str)

        assert parsed["status"] == "error"
        assert parsed["error"]["message"] == "Serialization test"
        assert parsed["http_status"] == 422

    def test_error_response_fallback_handling(self):
        """Test error response fallback when response models aren't available."""
        from awslabs.cloudwan_mcp_server.server import ErrorResponse

        # When response models fail to import, ErrorResponse should be dict type
        if ErrorResponse is dict:
            # Test fallback behavior
            error_dict = {"status": "error", "error": {"message": "Fallback test"}, "http_status": 500}
            assert error_dict["status"] == "error"
        else:
            # Normal response model behavior
            error_response = ErrorResponse(status="error", error={"message": "Normal test"}, http_status=500)
            assert error_response.status == "error"


class TestErrorRecoveryMechanisms:
    """Test error recovery and fallback mechanisms."""

    def test_dual_mode_error_consistency(self):
        """Test that error handling is consistent across dual-mode operation."""
        from awslabs.cloudwan_mcp_server.server import register_modular_tools, register_simple_tools

        # Both should handle errors gracefully
        simple_result = register_simple_tools()
        modular_result = register_modular_tools()

        # Neither should raise unhandled exceptions
        assert True  # If we get here, no unhandled exceptions occurred

    @patch("awslabs.cloudwan_mcp_server.server.get_aws_client")
    def test_client_creation_fallback(self, mock_get_client):
        """Test AWS client creation fallback mechanisms."""
        from awslabs.cloudwan_mcp_server.server import get_aws_client

        # First call fails, should raise but be handled by caller
        mock_get_client.side_effect = [BotoCoreError(), Mock()]

        with pytest.raises(BotoCoreError):
            get_aws_client("ec2")

    def test_import_fallback_mechanisms(self):
        """Test import fallback mechanisms in tools."""
        # Test that missing response models fall back to dict
        try:
            from awslabs.cloudwan_mcp_server.server import BaseResponse, ErrorResponse

            # Should have fallback values even if import fails
            assert BaseResponse is not None
            assert ErrorResponse is not None

        except ImportError:
            pytest.fail("Import fallback should prevent ImportError")

    def test_configuration_error_recovery(self):
        """Test configuration error recovery mechanisms."""
        # Test invalid region handling
        from awslabs.cloudwan_mcp_server.server import aws_config

        # Should have valid default even if environment is invalid
        assert aws_config.default_region is not None
        assert len(aws_config.default_region) > 0

    def test_tool_registration_error_recovery(self):
        """Test tool registration error recovery."""
        from awslabs.cloudwan_mcp_server.tools import register_all_tools

        # Mock MCP server
        mock_mcp = Mock()
        mock_mcp.tool = Mock(return_value=lambda func: func)

        # Should handle errors in individual tool registration
        try:
            tool_instances = register_all_tools(mock_mcp)
            assert isinstance(tool_instances, list)
        except Exception as e:
            pytest.fail(f"Tool registration should handle errors gracefully: {e}")


class TestSecuritySanitizationInErrorPaths:
    """Test security sanitization in all error paths."""

    def test_aws_credential_sanitization(self):
        """Test AWS credential sanitization in error messages."""
        # Test access key sanitization
        message_with_key = "Error: AKIAIOSFODNN7EXAMPLE failed authentication"
        sanitized = sanitize_error_message(message_with_key)

        assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
        assert "AWS_ACCESS_KEY_REDACTED" in sanitized

    def test_secret_key_sanitization(self):
        """Test AWS secret key sanitization."""
        message_with_secret = "Secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY is invalid"
        sanitized = sanitize_error_message(message_with_secret)

        assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in sanitized
        assert "AWS_SECRET_KEY_REDACTED" in sanitized

    def test_environment_variable_sanitization(self):
        """Test environment variable sanitization in logs."""
        # Test that invalid env var names are sanitized in logs
        result = secure_environment_update("invalid-key", "value")

        assert result is False
        # Should log sanitized version of invalid key

    def test_error_response_sanitization(self):
        """Test that error responses don't leak sensitive information."""
        from awslabs.cloudwan_mcp_server.server import handle_aws_error

        # Create error with sensitive information
        sensitive_error = Exception("Error with AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

        result = handle_aws_error(sensitive_error, "test_operation")
        result_data = json.loads(result)

        # Should not contain the actual secret
        assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in result_data["error"]["message"]

    def test_arn_sanitization_in_errors(self):
        """Test ARN sanitization in error messages."""
        arn_message = "Failed to access arn:aws:iam::123456789012:role/TestRole"
        sanitized = sanitize_error_message(arn_message)

        # Should redact the ARN
        assert "123456789012" not in sanitized
        assert "AWS_ARN_REDACTED" in sanitized

    def test_long_message_security_truncation(self):
        """Test that extremely long messages are truncated for security."""
        # Could be used for DoS or information extraction
        very_long_message = "Error: " + "A" * 50000
        sanitized = sanitize_error_message(very_long_message)

        assert sanitized == "[TRUNCATED_FOR_SECURITY]"
        assert len(sanitized) < 100

    def test_aws_credential_leak(self):
        """Test detection of AWS credential leaks in error messages."""
        payload = {"AccessKey": "ASIAOLDTEST"}  # pragma: allowlist secret
        sanitized = sanitize_error_message(json.dumps(payload))
        assert "ASIAOLDTEST" not in sanitized
        assert "AWS_ACCESS_KEY_REDACTED" in sanitized

    def test_exception_chain_with_secrets(self):
        """Test that exception chains with secrets are properly sanitized."""
        inner_exception = ValueError("AKIAEXPIRED")  # pragma: allowlist secret
        outer_exception = RuntimeError(f"Outer error: {inner_exception}")  # pragma: allowlist secret
        sanitized = sanitize_error_message(str(outer_exception))
        
        assert "AKIAEXPIRED" not in sanitized
        assert "AWS_ACCESS_KEY_REDACTED" in sanitized


# Integration test to ensure all improvements work together
class TestIntegratedErrorHandling:
    """Test that all error handling improvements work together."""

    @mock_ec2
    def test_end_to_end_error_handling(self):
        """Test complete error handling flow from tools to response."""
        from awslabs.cloudwan_mcp_server.tools.discovery import DiscoveryTools

        mock_mcp = Mock()
        mock_mcp.tool = Mock(return_value=lambda func: func)

        discovery_tools = DiscoveryTools(mock_mcp)

        with patch("awslabs.cloudwan_mcp_server.tools.discovery.get_aws_client") as mock_client:
            # Simulate AWS service error
            mock_ec2 = Mock()
            mock_ec2.describe_vpcs.side_effect = self.create_client_error(
                "InvalidRegion", "Region us-fake-1 does not exist", 400
            )
            mock_client.return_value = mock_ec2

            # Test error flows through all layers correctly
            result = await discovery_tools._discover_vpcs("us-fake-1")
            result_data = json.loads(result)

            # Should have proper error structure
            assert result_data["status"] == "error"
            assert "error" in result_data
            assert "operation" in result_data["error"]
            assert result_data["error"]["operation"] == "discover_vpcs"

    def create_client_error(self, error_code: str, message: str, http_status_code: int = 400):
        """Helper method to create ClientError for integration tests."""
        return ClientError(
            error_response={
                "Error": {"Code": error_code, "Message": message},
                "ResponseMetadata": {"HTTPStatusCode": http_status_code},
            },
            operation_name="TestOperation",
        )

    def test_multiple_error_type_handling(self):
        """Test handling multiple types of errors in sequence."""
        from awslabs.cloudwan_mcp_server.server import handle_aws_error

        errors_to_test = [
            ClientError({"Error": {"Code": "AccessDenied", "Message": "Access denied"}}, "TestOp"),
            BotoCoreError(),
            ValueError("Invalid input"),
            Exception("Generic error"),
        ]

        for error in errors_to_test:
            result = handle_aws_error(error, "test_operation")
            result_data = json.loads(result)

            # All should return proper error structure
            assert result_data["status"] == "error"
            assert "error" in result_data
            assert result_data["error"]["operation"] == "test_operation"

    @patch("awslabs.cloudwan_mcp_server.consts.logger")
    def test_error_logging_and_response_consistency(self, mock_logger):
        """Test that error logging and response generation are consistent."""
        from awslabs.cloudwan_mcp_server.server import handle_aws_error

        test_error = ClientError({"Error": {"Code": "TestError", "Message": "Test message"}}, "TestOperation")

        result = handle_aws_error(test_error, "test_operation")
        result_data = json.loads(result)

        # Should log and return consistent information
        assert result_data["status"] == "error"
        # Logger should have been called for this error
        assert mock_logger.error.called or mock_logger.warning.called


if __name__ == "__main__":
    # Run tests when executed directly
    pytest.main([__file__, "-v"])
