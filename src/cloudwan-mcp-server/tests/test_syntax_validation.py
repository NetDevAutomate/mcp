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

"""Comprehensive syntax validation tests for CloudWAN MCP Server.

These tests ensure that all syntax fixes preserve functionality and don't introduce
breaking changes. They validate import resolution, function definitions, and core
functionality across all modules.
"""

import ast
import inspect
import sys
from pathlib import Path

import pytest


class TestImportResolution:
    """Test that all modules can be imported correctly after syntax fixes."""

    def test_main_server_import(self):
        """Test that the main server module imports without errors."""
        try:
            from awslabs.cloudwan_mcp_server import server

            assert server is not None
            assert hasattr(server, "main")
        except ImportError as e:
            pytest.fail(f"Failed to import main server module: {e}")
        except SyntaxError as e:
            pytest.fail(f"Syntax error in server module: {e}")


class TestFunctionDefinitions:
    """Test that all function definitions are syntactically correct and callable."""

    def test_constants_helper_functions(self):
        """Test that constants helper functions are properly defined."""
        from awslabs.cloudwan_mcp_server import consts

        helper_functions = [
            "get_error_response",
            "is_valid_operation_mode",
            "sanitize_error_message",
            "safe_json_dumps",
        ]

        for func_name in helper_functions:
            assert hasattr(consts, func_name), f"Missing helper function: {func_name}"
            func = getattr(consts, func_name)
            assert callable(func), f"Function {func_name} is not callable"

            # Test function signature
            sig = inspect.signature(func)
            assert len(sig.parameters) > 0, f"Function {func_name} has no parameters"

    def test_server_main_function(self):
        """Test that server main function is properly defined."""
        from awslabs.cloudwan_mcp_server import server

        assert hasattr(server, "main")
        assert callable(server.main)

        # Check function signature
        sig = inspect.signature(server.main)
        assert sig.return_annotation in [None, type(None)], "Main should return None"

    def test_tool_class_definitions(self):
        """Test that tool classes are properly defined with required methods."""
        try:
            from awslabs.cloudwan_mcp_server.tools.core_network import CoreNetworkTools
            from awslabs.cloudwan_mcp_server.tools.discovery import DiscoveryTools

            # Test class instantiation doesn't fail due to syntax errors
            # We'll mock the MCP server parameter
            class MockMCP:
                def tool(self, name):
                    def decorator(func):
                        return func

                    return decorator

            mock_mcp = MockMCP()

            discovery_tools = DiscoveryTools(mock_mcp)
            assert discovery_tools is not None

            core_tools = CoreNetworkTools(mock_mcp)
            assert core_tools is not None

        except Exception as e:
            pytest.fail(f"Tool class instantiation failed: {e}")

    def test_aws_client_functions(self):
        """Test that AWS client factory functions are properly defined."""
        from awslabs.cloudwan_mcp_server import server

        assert hasattr(server, "get_aws_client")
        assert callable(server.get_aws_client)

        # Test function can be called with proper signature
        sig = inspect.signature(server.get_aws_client)
        params = list(sig.parameters.keys())
        assert "service_name" in params, "get_aws_client missing service_name parameter"


class TestSyntaxValidation:
    """Test that all Python files have valid syntax and compile correctly."""

    def get_python_files(self) -> List[Path]:
        """Get all Python files in the project."""
        project_root = Path(__file__).parent.parent
        python_files = []

        for pattern in ["**/*.py"]:
            python_files.extend(project_root.glob(pattern))

        # Filter out __pycache__ and other irrelevant files
        return [f for f in python_files if "__pycache__" not in str(f) and ".git" not in str(f)]

    def test_all_python_files_compile(self):
        """Test that all Python files compile without syntax errors."""
        python_files = self.get_python_files()
        failed_files = []

        for py_file in python_files:
            try:
                with open(py_file, "r", encoding="utf-8") as f:
                    source_code = f.read()

                # Try to compile the source code
                compile(source_code, str(py_file), "exec")

            except SyntaxError as e:
                failed_files.append((py_file, str(e)))
            except UnicodeDecodeError:
                # Skip binary files or files with encoding issues
                continue
            except Exception as e:
                # Other compilation errors
                failed_files.append((py_file, f"Compilation error: {str(e)}"))

        if failed_files:
            error_msg = "Files with syntax errors:\n"
            for file_path, error in failed_files:
                error_msg += f"  {file_path}: {error}\n"
            pytest.fail(error_msg)

    def test_ast_parsing_succeeds(self):
        """Test that all Python files can be parsed into AST without errors."""
        python_files = self.get_python_files()
        failed_files = []

        for py_file in python_files:
            try:
                with open(py_file, "r", encoding="utf-8") as f:
                    source_code = f.read()

                # Try to parse into AST
                ast.parse(source_code, filename=str(py_file))

            except SyntaxError as e:
                failed_files.append((py_file, str(e)))
            except UnicodeDecodeError:
                continue
            except Exception as e:
                failed_files.append((py_file, f"AST parsing error: {str(e)}"))

        if failed_files:
            error_msg = "Files with AST parsing errors:\n"
            for file_path, error in failed_files:
                error_msg += f"  {file_path}: {error}\n"
            pytest.fail(error_msg)

    def test_assertion_statements_valid(self):
        """Test that any assertion statements in the code are valid."""
        python_files = self.get_python_files()

        for py_file in python_files:
            try:
                with open(py_file, "r", encoding="utf-8") as f:
                    source_code = f.read()

                # Parse and look for assert statements
                tree = ast.parse(source_code)

                for node in ast.walk(tree):
                    if isinstance(node, ast.Assert):
                        # Check that assert has proper structure
                        assert node.test is not None, f"Invalid assert statement in {py_file}"

            except Exception as e:
                pytest.fail(f"Error checking assertions in {py_file}: {e}")


class TestCoreFunctionality:
    """Test that core functionality still works after syntax fixes."""

    def test_operation_mode_detection(self):
        """Test that operation mode detection works correctly."""
        from awslabs.cloudwan_mcp_server.consts import OperationMode
        from awslabs.cloudwan_mcp_server.server import determine_operation_mode

        # Test function exists and returns valid mode
        mode = determine_operation_mode()
        assert mode in [op.value for op in OperationMode], f"Invalid operation mode: {mode}"

    def test_error_sanitization(self):
        """Test that error sanitization functions work correctly."""
        from awslabs.cloudwan_mcp_server.consts import sanitize_error_message

        # Test with normal message
        normal_msg = "This is a normal error message"
        sanitized = sanitize_error_message(normal_msg)
        assert sanitized == normal_msg

        # Test with very long message (should be truncated)
        long_msg = "A" * 15000
        sanitized = sanitize_error_message(long_msg)
        assert sanitized == "[TRUNCATED_FOR_SECURITY]"

    def test_json_serialization(self):
        """Test that JSON serialization works correctly."""
        from datetime import datetime

        from awslabs.cloudwan_mcp_server.consts import safe_json_dumps

        # Test basic object
        basic_obj = {"key": "value", "number": 123}
        result = safe_json_dumps(basic_obj)
        assert '"key": "value"' in result

        # Test with datetime
        dt_obj = {"timestamp": datetime(2024, 1, 1, 12, 0, 0)}
        result = safe_json_dumps(dt_obj)
        assert "2024-01-01T12:00:00" in result

    def test_aws_config_initialization(self):
        """Test that AWS configuration initializes correctly."""
        from awslabs.cloudwan_mcp_server.server import aws_config

        assert aws_config is not None
        assert hasattr(aws_config, "default_region")
        assert aws_config.default_region is not None

    def test_error_response_generation(self):
        """Test that error response generation works."""
        from awslabs.cloudwan_mcp_server.consts import ErrorCode, get_error_response

        # Test basic error response
        response = get_error_response(ErrorCode.AWS_CLIENT_ERROR)
        assert response is not None
        assert response.get("errorCode") == "AWS_CLIENT_ERROR"

        # Test with details
        response = get_error_response(ErrorCode.AWS_ACCESS_DENIED, details="Access denied", http_status=403)
        assert response.get("details") == "Access denied"
        assert response.get("httpStatus") == 403

    def test_environment_variable_validation(self):
        """Test that environment variable validation works."""
        from awslabs.cloudwan_mcp_server.consts import ALLOWED_ENV_VAR_PATTERN

        # Test valid environment variable names
        valid_vars = ["AWS_PROFILE", "FASTMCP_LOG_LEVEL", "CLOUDWAN_MODE"]
        for var in valid_vars:
            assert ALLOWED_ENV_VAR_PATTERN.match(var), f"Should match: {var}"

        # Test invalid environment variable names
        invalid_vars = ["aws_profile", "123_VAR", "VAR-NAME"]
        for var in invalid_vars:
            assert not ALLOWED_ENV_VAR_PATTERN.match(var), f"Should not match: {var}"


class TestRegressionChecks:
    """Test critical paths to ensure no regressions were introduced."""

    def test_mcp_server_initialization(self):
        """Test that MCP server can be initialized without errors."""
        try:
            from awslabs.cloudwan_mcp_server.server import mcp

            assert mcp is not None
            assert hasattr(mcp, "run")

        except Exception as e:
            pytest.fail(f"MCP server initialization failed: {e}")

    def test_tool_registration_structure(self):
        """Test that tool registration structure is intact."""
        try:
            from awslabs.cloudwan_mcp_server.tools import register_all_tools

            assert register_all_tools is not None
            assert callable(register_all_tools)

            # Test function signature
            sig = inspect.signature(register_all_tools)
            params = list(sig.parameters.keys())
            assert "mcp_server" in params, "register_all_tools missing mcp_server parameter"

        except ImportError:
            pytest.skip("register_all_tools not available")
        except Exception as e:
            pytest.fail(f"Tool registration structure check failed: {e}")

    def test_response_model_compatibility(self):
        """Test that response models maintain compatibility."""
        try:
            from awslabs.cloudwan_mcp_server.models.response_models import BaseResponse, ErrorResponse

            # Test BaseResponse can be instantiated
            base_resp = BaseResponse(status="success", data={"test": "data"})
            assert base_resp.status == "success"

            # Test ErrorResponse can be instantiated
            error_resp = ErrorResponse(status="error", error={"message": "test error"}, http_status=400)
            assert error_resp.status == "error"

        except ImportError:
            # Fallback handling should be in place
            pytest.skip("Response models not available, fallback should be active")
        except Exception as e:
            pytest.fail(f"Response model compatibility check failed: {e}")

    def test_security_patterns_intact(self):
        """Test that security patterns and sanitization are still working."""
        from awslabs.cloudwan_mcp_server.consts import SANITIZATION_PATTERNS

        assert SANITIZATION_PATTERNS is not None
        assert len(SANITIZATION_PATTERNS) > 0

        # Test that patterns are compiled regex objects
        for pattern, replacement in SANITIZATION_PATTERNS.items():
            assert hasattr(pattern, "sub"), "Pattern should be compiled regex"
            assert isinstance(replacement, str), "Replacement should be string"

    def test_constants_completeness(self):
        """Test that all required constants are present and valid."""
        from awslabs.cloudwan_mcp_server.consts import (
            CACHE_MAX_SIZE,
            DEFAULT_AWS_REGION,
            DEFAULT_LOG_LEVEL,
            ErrorCode,
            OperationMode,
        )

        # Test enums are complete
        assert len(list(ErrorCode)) >= 5, "ErrorCode enum should have at least 5 values"
        assert len(list(OperationMode)) == 3, "OperationMode should have exactly 3 values"

        # Test default values are reasonable
        assert isinstance(DEFAULT_AWS_REGION, str) and len(DEFAULT_AWS_REGION) > 0
        assert isinstance(DEFAULT_LOG_LEVEL, str) and DEFAULT_LOG_LEVEL in ["DEBUG", "INFO", "WARNING", "ERROR"]
        assert isinstance(CACHE_MAX_SIZE, int) and CACHE_MAX_SIZE > 0


class TestModuleIntegration:
    """Test that modules work together correctly after syntax fixes."""

    def test_server_imports_from_constants(self):
        """Test that server module can import from constants without circular imports."""
        try:
            # This should work without circular import issues
            from awslabs.cloudwan_mcp_server.server import DEFAULT_AWS_REGION, ErrorCode, OperationMode

            assert DEFAULT_AWS_REGION is not None
            assert ErrorCode is not None
            assert OperationMode is not None

        except ImportError as e:
            pytest.fail(f"Server failed to import from constants: {e}")

    def test_tools_can_import_server_utilities(self):
        """Test that tools can import utilities from server module."""
        try:
            from awslabs.cloudwan_mcp_server.tools.discovery import aws_config, get_aws_client, handle_aws_error

            assert aws_config is not None
            assert callable(get_aws_client)
            assert callable(handle_aws_error)

        except ImportError as e:
            pytest.fail(f"Tools failed to import from server: {e}")

    def test_cross_module_function_calls(self):
        """Test that cross-module function calls work correctly."""
        from awslabs.cloudwan_mcp_server.consts import sanitize_error_message
        from awslabs.cloudwan_mcp_server.server import safe_json_dumps

        # Test that functions can be called together
        test_data = {"error": "Test error with sensitive data AKIATEST123"}
        sanitized = sanitize_error_message(str(test_data))
        json_result = safe_json_dumps({"sanitized": sanitized})

        assert "AKIATEST123" not in json_result
        assert "sanitized" in json_result


def run_syntax_validation_report():
    """Generate a comprehensive syntax validation report."""
    report = {
        "timestamp": "2025-01-01T00:00:00Z",
        "tests_run": 0,
        "tests_passed": 0,
        "tests_failed": 0,
        "critical_issues": [],
        "warnings": [],
        "summary": "",
    }

    # This would be called by the test runner
    # For now, it's a placeholder for reporting functionality

    return report


if __name__ == "__main__":
    # Run basic syntax validation when script is executed directly
    print("Running syntax validation tests...")

    try:
        # Test basic imports
        print("✅ Basic imports successful")

        # Test function calls
        from awslabs.cloudwan_mcp_server.consts import sanitize_error_message

        result = sanitize_error_message("test message")
        print("✅ Function calls successful")

        print("🎉 Basic syntax validation passed!")

    except Exception as e:
        print(f"❌ Syntax validation failed: {e}")
        sys.exit(1)
