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

"""Constants for the CloudWAN MCP Server."""

import re
from enum import Enum
from typing import Final

# Default AWS Region
DEFAULT_AWS_REGION: Final[str] = "us-east-1"

# Default Log Level
DEFAULT_LOG_LEVEL: Final[str] = "WARNING"

# MCP Server Description
MCP_SERVER_DESCRIPTION: Final[str] = "AWS CloudWAN MCP Server - Advanced network analysis and troubleshooting tools"


class ErrorCode(Enum):
    """Error codes for CloudWAN MCP Server."""

    AWS_ERROR = "AWS_SERVICE_ERROR"
    INVALID_INPUT = "INVALID_INPUT"
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    AWS_CLIENT_ERROR = "AWS_CLIENT_ERROR"
    AWS_THROTTLING_ERROR = "AWS_THROTTLING_ERROR"
    AWS_ACCESS_DENIED = "AWS_ACCESS_DENIED"
    AWS_RESOURCE_NOT_FOUND = "AWS_RESOURCE_NOT_FOUND"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


# Sanitization patterns for error messages
SANITIZATION_PATTERNS = [
    # AWS access keys
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[ACCESS_KEY_REDACTED]"),
    # AWS secret keys (40 char base64-like strings)
    (re.compile(r"[A-Za-z0-9/+=]{40}"), "[SECRET_KEY_REDACTED]"),
    # ARNs
    (re.compile(r"arn:aws:[^:]+:[^:]*:[^:]*:[^:]+"), "[ARN_REDACTED]"),
]

# Environment variable pattern
ALLOWED_ENV_VAR_PATTERN = re.compile(r"^[A-Z_][A-Z0-9_]*$")


def sanitize_error_message(message: str) -> str:
    """Sanitize error messages to remove sensitive information."""
    if len(message) > 10000:
        return "[TRUNCATED_FOR_SECURITY]"

    sanitized = message
    for pattern, replacement in SANITIZATION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)

    return sanitized


# Default Operation Mode
DEFAULT_OPERATION_MODE: Final[str] = "simple"

# Cache Configuration
CACHE_MAX_SIZE: Final[int] = 128

# MCP Server Description
MCP_SERVER_DESCRIPTION: Final[str] = (
    "AWS CloudWAN MCP Server - Advanced network analysis and "
    "troubleshooting tools for AWS CloudWAN, Transit Gateway, "
    "Network Firewall, and VPC networking."
)
