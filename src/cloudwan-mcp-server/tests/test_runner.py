#!/usr/bin/env python3
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

"""Test runner for CloudWAN MCP Server tests."""

import sys

import pytest

from awslabs.cloudwan_mcp_server.consts import sanitize_error_message


def run_tests():
    """Run all tests with proper error sanitization."""
    try:
        # Use the correct function name
        test_message = "Test with AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret
        sanitized = sanitize_error_message(test_message)
        print(f"Sanitized test message: {sanitized}")

        return pytest.main(["-v", "tests/"])
    except Exception as e:
        sanitized_error = sanitize_error_message(str(e))
        print(f"Test runner error: {sanitized_error}")
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
