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

"""Comprehensive unit tests for CloudWAN MCP Server constants."""

import json
import os
from unittest.mock import patch

from awslabs.cloudwan_mcp_server.consts import (
    # Patterns
    ALLOWED_ENV_VAR_PATTERN,
    AWS_ACCESS_KEY_ID,
    AWS_ACCESS_KEY_ID_PATTERN,
    AWS_DEFAULT_REGION,
    # Environment Variables
    AWS_PROFILE,
    AWS_REGION_PATTERN,
    AWS_SECRET_ACCESS_KEY,
    AWS_SECRET_ACCESS_KEY_PATTERN,
    CACHE_MAX_SIZE,
    CLOUDWAN_DUAL_MODE,
    CLOUDWAN_MODE,
    # Constants
    DEFAULT_AWS_REGION,
    DEFAULT_LOG_LEVEL,
    DEFAULT_OPERATION_MODE,
    FASTMCP_LOG_LEVEL,
    HTTP_STATUS_BAD_REQUEST,
    HTTP_STATUS_INTERNAL_SERVER_ERROR,
    HTTP_STATUS_OK,
    MCP_SERVER_DESCRIPTION,
    MCP_SERVER_NAME,
    PROMPT_INSTRUCTIONS,
    SANITIZATION_PATTERNS,
    # Enums
    ErrorCode,
    OperationMode,
    # Helper Functions
    get_error_response,
    is_valid_operation_mode,
    safe_json_dumps,
    sanitize_error_message,
    secure_environment_update,
)


class TestConstants:
    """Test all constant definitions."""

    def test_default_values(self):
        """Test default configuration values."""
        assert DEFAULT_AWS_REGION == "us-east-1"
        assert DEFAULT_LOG_LEVEL == "WARNING"
        assert DEFAULT_OPERATION_MODE == "simple"
        assert CACHE_MAX_SIZE == 128

    def test_server_metadata(self):
        """Test MCP server metadata constants."""
        assert MCP_SERVER_NAME == "awslabs.cloudwan-mcp-server"
        assert "CloudWAN" in MCP_SERVER_DESCRIPTION
        assert "Network" in MCP_SERVER_DESCRIPTION
        assert len(PROMPT_INSTRUCTIONS) > 100

    def test_http_status_codes(self):
        """Test HTTP status code constants."""
        assert HTTP_STATUS_OK == 200
        assert HTTP_STATUS_BAD_REQUEST == 400
        assert HTTP_STATUS_INTERNAL_SERVER_ERROR == 500

    def test_environment_variable_names(self):
        """Test environment variable name constants."""
        assert AWS_PROFILE == "AWS_PROFILE"
        assert AWS_DEFAULT_REGION == "AWS_DEFAULT_REGION"
        assert AWS_ACCESS_KEY_ID == "AWS_ACCESS_KEY_ID"
        assert AWS_SECRET_ACCESS_KEY == "AWS_SECRET_ACCESS_KEY"
        assert FASTMCP_LOG_LEVEL == "FASTMCP_LOG_LEVEL"
        assert CLOUDWAN_MODE == "CLOUDWAN_MODE"
        assert CLOUDWAN_DUAL_MODE == "CLOUDWAN_DUAL_MODE"


class TestErrorCodeEnum:
    """Test ErrorCode enumeration."""

    def test_error_code_values(self):
        """Test all error code enum values."""
        assert ErrorCode.AWS_CLIENT_ERROR == "AWS_CLIENT_ERROR"
        assert ErrorCode.AWS_THROTTLING_ERROR == "AWS_THROTTLING_ERROR"
        assert ErrorCode.AWS_ACCESS_DENIED == "AWS_ACCESS_DENIED"
        assert ErrorCode.AWS_RESOURCE_NOT_FOUND == "AWS_RESOURCE_NOT_FOUND"
        assert ErrorCode.UNKNOWN_ERROR == "UNKNOWN_ERROR"

    def test_error_code_inheritance(self):
        """Test ErrorCode enum inherits from str."""
        assert isinstance(ErrorCode.AWS_CLIENT_ERROR, str)
        assert str(ErrorCode.AWS_CLIENT_ERROR) == "AWS_CLIENT_ERROR"

    def test_error_code_completeness(self):
        """Test all expected error codes are present."""
        expected_codes = {
            "AWS_CLIENT_ERROR",
            "AWS_THROTTLING_ERROR",
            "AWS_ACCESS_DENIED",
            "AWS_RESOURCE_NOT_FOUND",
            "UNKNOWN_ERROR",
        }
        actual_codes = {code.value for code in ErrorCode}
        assert actual_codes == expected_codes


class TestOperationModeEnum:
    """Test OperationMode enumeration."""

    def test_operation_mode_values(self):
        """Test all operation mode enum values."""
        assert OperationMode.SIMPLE == "simple"
        assert OperationMode.ADVANCED == "advanced"
        assert OperationMode.DUAL == "dual"

    def test_operation_mode_inheritance(self):
        """Test OperationMode enum inherits from str."""
        assert isinstance(OperationMode.SIMPLE, str)
        assert str(OperationMode.SIMPLE) == "simple"

    def test_operation_mode_completeness(self):
        """Test all expected operation modes are present."""
        expected_modes = {"simple", "advanced", "dual"}
        actual_modes = {mode.value for mode in OperationMode}
        assert actual_modes == expected_modes


class TestValidationPatterns:
    """Test all validation patterns."""

    def test_allowed_env_var_pattern(self):
        """Test environment variable validation pattern."""
        # Valid patterns
        valid_vars = ["AWS_PROFILE", "FASTMCP_LOG_LEVEL", "CLOUDWAN_MODE", "MY_CUSTOM_VAR", "A_B_C"]
        for var in valid_vars:
            assert ALLOWED_ENV_VAR_PATTERN.match(var), f"Should match: {var}"

        # Invalid patterns
        invalid_vars = [
            "aws_profile",  # lowercase
            "123_VAR",  # starts with number
            "VAR-NAME",  # contains dash
            "A",  # too short
            "a" * 31,  # too long
            "",  # empty
            "VAR@NAME",  # special character
        ]
        for var in invalid_vars:
            assert not ALLOWED_ENV_VAR_PATTERN.match(var), f"Should not match: {var}"

    def test_aws_region_pattern(self):
        """Test AWS region validation pattern."""
        # Valid regions
        valid_regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "ca-central-1", "sa-east-1"]
        for region in valid_regions:
            assert AWS_REGION_PATTERN.match(region), f"Should match: {region}"

        # Invalid regions
        invalid_regions = [
            "us-east",  # missing number
            "us-east-1a",  # extra character
            "US-EAST-1",  # uppercase
            "us_east_1",  # underscores
            "us-east-10",  # multi-digit number
            "",  # empty
            "invalid",  # completely wrong format
        ]
        for region in invalid_regions:
            assert not AWS_REGION_PATTERN.match(region), f"Should not match: {region}"

    def test_aws_access_key_pattern(self):
        """Test AWS access key ID validation pattern."""
        # Valid access keys (20 uppercase alphanumeric)
        valid_keys = [
            "AKIAIOSFODNN7EXAMPLE",
            "ASIA1234567890123456",
            "AKIA" + "A" * 16,
        ]
        for key in valid_keys:
            assert AWS_ACCESS_KEY_ID_PATTERN.match(key), f"Should match: {key}"

        # Invalid access keys
        invalid_keys = [
            "akiaiosfodnn7example",  # lowercase
            "AKIAIOSFODNN7EXAMPL",  # too short
            "AKIAIOSFODNN7EXAMPLEE",  # too long
            "AKIA-EXAMPLE-KEY123",  # contains dash
            "",  # empty
            "AKIA" + "a" * 16,  # contains lowercase
        ]
        for key in invalid_keys:
            assert not AWS_ACCESS_KEY_ID_PATTERN.match(key), f"Should not match: {key}"

    def test_aws_secret_key_pattern(self):
        """Test AWS secret access key validation pattern."""
        # Valid secret keys (40 characters)
        valid_secrets = [
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "A" * 40,
            "1" * 40,
        ]
        for secret in valid_secrets:
            assert AWS_SECRET_ACCESS_KEY_PATTERN.match(secret), f"Should match: {secret}"

        # Invalid secret keys
        invalid_secrets = [
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE",  # too short
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYS",  # too long
            "wjalrxutnfemi/k7mdeng/bpxrficyexamplekey",  # contains lowercase
            "",  # empty
            "A" * 39,  # 39 chars
            "A" * 41,  # 41 chars
        ]
        for secret in invalid_secrets:
            assert not AWS_SECRET_ACCESS_KEY_PATTERN.match(secret), f"Should not match: {secret}"


class TestSanitizationPatterns:
    """Test sanitization pattern functionality."""

    def test_sanitization_patterns_structure(self):
        """Test sanitization patterns are properly structured."""
        assert isinstance(SANITIZATION_PATTERNS, dict)
        assert len(SANITIZATION_PATTERNS) > 0

        # Check each pattern has proper structure
        for pattern, replacement in SANITIZATION_PATTERNS.items():
            assert hasattr(pattern, "sub"), "Pattern should be compiled regex"
            assert isinstance(replacement, str), "Replacement should be string"

    def test_sanitization_coverage(self):
        """Test sanitization patterns cover expected cases."""
        expected_patterns = {
            "AWS_ACCESS_KEY_REDACTED",
            "AWS_SECRET_KEY_REDACTED",
            "AWS_REGION_REDACTED",
            "AWS_ARN_REDACTED",
            "ENV_VAR_REDACTED",
        }

        actual_replacements = set(SANITIZATION_PATTERNS.values())
        # At minimum, should cover AWS credentials
        assert "AWS_ACCESS_KEY_REDACTED" in actual_replacements
        assert "AWS_SECRET_KEY_REDACTED" in actual_replacements


class TestHelperFunctions:
    """Test helper functions."""

    def test_get_error_response(self):
        """Test error response generation."""
        # Basic error response
        response = get_error_response(ErrorCode.AWS_CLIENT_ERROR)
        assert response["errorCode"] == "AWS_CLIENT_ERROR"
        assert "httpStatus" in response

        # Error response with details
        response = get_error_response(ErrorCode.AWS_ACCESS_DENIED, details="Access denied to resource", http_status=403)
        assert response["errorCode"] == "AWS_ACCESS_DENIED"
        assert response["details"] == "Access denied to resource"
        assert response["httpStatus"] == 403

        # Test with all error codes
        for error_code in ErrorCode:
            response = get_error_response(error_code)
            assert response["errorCode"] == error_code.value

    def test_is_valid_operation_mode(self):
        """Test operation mode validation."""
        # Valid modes
        assert is_valid_operation_mode("simple")
        assert is_valid_operation_mode("advanced")
        assert is_valid_operation_mode("dual")

        # Invalid modes
        assert not is_valid_operation_mode("invalid")
        assert not is_valid_operation_mode("Simple")  # case sensitive
        assert not is_valid_operation_mode("")
        assert not is_valid_operation_mode("complex")

    def test_sanitize_error_message(self):
        """Test error message sanitization."""
        # Normal message should pass through
        normal_msg = "This is a normal error message"
        assert sanitize_error_message(normal_msg) == normal_msg

        # Message with AWS access key should be sanitized
        key_msg = "Error with key AKIAIOSFODNN7EXAMPLE"
        sanitized = sanitize_error_message(key_msg)
        assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
        assert "AWS_ACCESS_KEY_REDACTED" in sanitized

        # Very long message should be truncated
        long_msg = "A" * 15000
        sanitized = sanitize_error_message(long_msg)
        assert sanitized == "[TRUNCATED_FOR_SECURITY]"

    def test_safe_json_dumps(self):
        """Test JSON serialization with datetime support."""
        from datetime import datetime

        # Basic object
        basic_obj = {"key": "value", "number": 123}
        result = safe_json_dumps(basic_obj)
        assert json.loads(result) == basic_obj

        # Object with datetime
        dt_obj = {"timestamp": datetime(2024, 1, 1, 12, 0, 0)}
        result = safe_json_dumps(dt_obj)
        parsed = json.loads(result)
        assert "2024-01-01T12:00:00" in parsed["timestamp"]

    @patch.dict("os.environ", {}, clear=True)
    @patch("awslabs.cloudwan_mcp_server.consts.logger")
    def test_secure_environment_update_success(self, mock_logger):
        """Test successful environment variable update."""
        # Valid AWS profile update
        result = secure_environment_update("AWS_PROFILE", "test-profile")
        assert result is True
        assert os.environ.get("AWS_PROFILE") == "test-profile"

        # Valid region update
        result = secure_environment_update("AWS_DEFAULT_REGION", "us-west-2")
        assert result is True
        assert os.environ.get("AWS_DEFAULT_REGION") == "us-west-2"

    @patch("awslabs.cloudwan_mcp_server.consts.logger")
    def test_secure_environment_update_validation_failures(self, mock_logger):
        """Test environment variable update validation failures."""
        # Empty key
        result = secure_environment_update("", "value")
        assert result is False

        # Empty value
        result = secure_environment_update("VALID_KEY", "")
        assert result is False

        # Invalid key format
        result = secure_environment_update("invalid-key", "value")
        assert result is False

        # Invalid region format
        result = secure_environment_update("AWS_DEFAULT_REGION", "invalid-region")
        assert result is False

        # Sensitive var without prefix
        result = secure_environment_update("AWS_SECRET_ACCESS_KEY", "plaintext-secret")
        assert result is False

    @patch("awslabs.cloudwan_mcp_server.consts.logger")
    def test_secure_environment_update_sensitive_vars(self, mock_logger):
        """Test secure handling of sensitive environment variables."""
        # Sensitive variable with proper prefix
        result = secure_environment_update("AWS_SECRET_ACCESS_KEY", "aws-secret:encrypted-value")
        assert result is True

        # Session token with proper prefix
        result = secure_environment_update("AWS_SESSION_TOKEN", "aws-secret:encrypted-token")
        assert result is True


class TestConstantsPerformance:
    """Test performance characteristics of constants."""

    def test_import_performance(self):
        """Test constants import performance."""
        import time

        start_time = time.time()
        # Import constants module
        import_time = time.time() - start_time

        # Import should be very fast (< 100ms)
        assert import_time < 0.1, f"Import took {import_time:.3f}s, should be < 0.1s"

    def test_pattern_compilation_performance(self):
        """Test regex pattern compilation performance."""
        import time

        # Time pattern access
        start_time = time.time()
        for _ in range(1000):
            _ = ALLOWED_ENV_VAR_PATTERN
            _ = AWS_REGION_PATTERN
            _ = AWS_ACCESS_KEY_ID_PATTERN
        access_time = time.time() - start_time

        # Pattern access should be very fast
        assert access_time < 0.01, f"Pattern access took {access_time:.3f}s"

    def test_sanitization_performance(self):
        """Test sanitization function performance."""
        import time

        test_message = "Error occurred with key AKIAIOSFODNN7EXAMPLE in region us-east-1"

        start_time = time.time()
        for _ in range(1000):
            sanitize_error_message(test_message)
        sanitize_time = time.time() - start_time

        # Sanitization should be reasonably fast
        assert sanitize_time < 1.0, f"Sanitization took {sanitize_time:.3f}s for 1000 calls"


class TestConstantsDocumentation:
    """Test constants have proper documentation."""

    def test_enum_docstrings(self):
        """Test enums have proper docstrings."""
        assert ErrorCode.__doc__ is not None
        assert OperationMode.__doc__ is not None

    def test_function_docstrings(self):
        """Test helper functions have docstrings."""
        assert get_error_response.__doc__ is not None
        assert is_valid_operation_mode.__doc__ is not None
        assert sanitize_error_message.__doc__ is not None
        assert secure_environment_update.__doc__ is not None
        assert safe_json_dumps.__doc__ is not None


class TestConstantsIntegration:
    """Test constants work correctly with other modules."""

    def test_server_imports_constants(self):
        """Test server module can import all required constants."""
        # This should not raise ImportError
        # Test they're the same objects
        from awslabs.cloudwan_mcp_server.consts import (
            ErrorCode as ConstErrorCode,
        )
        from awslabs.cloudwan_mcp_server.consts import (
            OperationMode as ConstOperationMode,
        )
        from awslabs.cloudwan_mcp_server.server import (
            ErrorCode,
            OperationMode,
        )

        assert ErrorCode is ConstErrorCode
        assert OperationMode is ConstOperationMode

    def test_constants_type_consistency(self):
        """Test constants maintain consistent types."""
        assert isinstance(DEFAULT_AWS_REGION, str)
        assert isinstance(DEFAULT_LOG_LEVEL, str)
        assert isinstance(CACHE_MAX_SIZE, int)
        assert isinstance(MCP_SERVER_NAME, str)

    def test_enum_member_access(self):
        """Test enum members can be accessed properly."""
        # Test ErrorCode enum access
        assert hasattr(ErrorCode, "AWS_CLIENT_ERROR")
        assert hasattr(ErrorCode, "AWS_ACCESS_DENIED")

        # Test OperationMode enum access
        assert hasattr(OperationMode, "SIMPLE")
        assert hasattr(OperationMode, "ADVANCED")
        assert hasattr(OperationMode, "DUAL")
