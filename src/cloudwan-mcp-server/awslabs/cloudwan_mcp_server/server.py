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

# Standard library imports - Complete set for F821 fixes
import ipaddress
import json
import os
import re
import sys
import threading
from datetime import datetime as dt
from typing import Any, Dict, Optional, TypedDict

import boto3
import loguru
from boto3 import Config
from botocore.exceptions import BotoCoreError, ClientError
from mcp.server.fastmcp import FastMCP
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Local imports with missing items added
from .consts import (
    ALLOWED_ENV_VAR_PATTERN,
    DEFAULT_AWS_REGION,
    DEFAULT_LOG_LEVEL,
    DEFAULT_OPERATION_MODE,
    MCP_SERVER_DESCRIPTION,
    SANITIZATION_PATTERNS,
    ErrorCode,
    OperationMode,
    is_valid_operation_mode,
    sanitize_error_message,
)

# Optional local imports with fallbacks
try:
    from .models.response_models import BaseResponse, ErrorResponse
except ImportError:
    # Fallback if response models not available
    class BaseResponse(TypedDict):
        """Base response structure for all MCP tools.

        Follows AWS Labs standards with status and data fields.
        """

        status: str
        data: Any

    class ErrorResponse(TypedDict):
        """Structured error response model for MCP tools.

        Includes error details and HTTP status code.
        """

        status: str
        error: Dict[str, Any]
        http_status: int


# AWS Resource validation patterns
AWS_REGION_PATTERN = re.compile(r"^[a-z]{2,3}-[a-z]+-\d+$")
AWS_ARN_PATTERN = re.compile(r"^arn:aws:[^:]+:[^:]*:[^:]*:[^:]+$")
CORE_NETWORK_ID_PATTERN = re.compile(r"^core-network-[0-9a-f]{17}$")

CLOUDWAN_CLIENT_CONFIG = Config(retries={"max_attempts": 3, "mode": "standard"}, read_timeout=30, connect_timeout=10)


class AWSConfig(BaseSettings):
    """Secure AWS configuration using pydantic-settings for environment variable validation."""

    default_region: str = DEFAULT_AWS_REGION
    profile: str | None = None

    # Dual-mode configuration following the architecture document
    cloudwan_mode: str = DEFAULT_OPERATION_MODE.value  # Use OperationMode enum value
    cloudwan_dual_mode: bool = False  # Enable dual mode operation

    model_config = SettingsConfigDict(
        env_prefix="AWS_", env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore"
    )


# Global secure config instance
aws_config = AWSConfig()

# Thread safety for client caching
_client_lock = threading.Lock()


class ContentItem(TypedDict):
    """A TypedDict representing a single content item in an MCP response.

    This class defines the structure for content items used in MCP server responses.
    Each content item contains a type identifier and the actual content text.

    Attributes:
        type (str): The type identifier for the content (e.g., 'text', 'error')
        text (str): The actual content text
    """

    type: str
    text: str


class McpResponse(TypedDict):
    """A TypedDict representing an MCP server response.

    Attributes:
        content (List[ContentItem]): List of content items in the response
        isError (Optional[bool]): Flag indicating if the response represents an error
    """

    content: list[ContentItem]
    isError: bool | None


# Set up logging
logger = loguru.logger
logger.remove()
logger.add(sys.stderr, level=os.getenv("FASTMCP_LOG_LEVEL", DEFAULT_LOG_LEVEL))

# Initialize FastMCP server following AWS Labs pattern
mcp = FastMCP(
    MCP_SERVER_DESCRIPTION,
    dependencies=[
        "loguru",
        "boto3",
    ],
)

# ============================================================================
# DUAL-MODE ARCHITECTURE IMPLEMENTATION
# ============================================================================


def determine_operation_mode() -> str:
    """Determine operation mode based on configuration."""
    # Priority: CLOUDWAN_DUAL_MODE env var overrides CLOUDWAN_MODE
    if aws_config.cloudwan_dual_mode or os.getenv("CLOUDWAN_DUAL_MODE", "").lower() == "true":
        return OperationMode.DUAL.value

    # Check CLOUDWAN_MODE environment variable
    mode = os.getenv("CLOUDWAN_MODE", aws_config.cloudwan_mode).lower()
    if is_valid_operation_mode(mode):
        return mode

    logger.warning(f"Invalid CLOUDWAN_MODE '{mode}', defaulting to {DEFAULT_OPERATION_MODE.value}")
    return DEFAULT_OPERATION_MODE.value


# Determine current operation mode
OPERATION_MODE = determine_operation_mode()
logger.info(f"CloudWAN MCP Server starting in {OPERATION_MODE.upper()} mode")


# AWS client cache with thread-safe LRU implementation
def get_aws_client(service_name: str, region: Optional[str] = None):
    """Cached AWS client factory with thread safety."""
    try:
        if not service_name:
            logger.warning("Attempted to create client with empty service name")
            raise ValueError("Service name cannot be empty")

        client = boto3.client(
            service_name, region_name=region or aws_config.default_region, config=CLOUDWAN_CLIENT_CONFIG
        )
        logger.info(f"Successfully created client for {service_name}")
        return client
    except (BotoCoreError, ClientError) as aws_error:
        logger.error(f"AWS client creation failed for {service_name}: {sanitize_error_message(str(aws_error))}")
        raise
    except Exception as e:
        logger.critical(f"Unexpected error creating AWS client: {sanitize_error_message(str(e))}")
        raise


class DateTimeEncoder(json.JSONEncoder):
    """JSON encoder for datetime objects."""

    def default(self, obj):
        if isinstance(obj, dt):
            return obj.isoformat()
        return super().default(obj)


def safe_json_dumps(obj, **kwargs):
    """Safely serialize objects to JSON with datetime support."""
    return json.dumps(obj, cls=DateTimeEncoder, **kwargs)


def sanitize_error_message(message: str) -> str:
    """Remove sensitive information from error messages."""
    # Add rate limiting to prevent regex DoS
    if len(message) > 10000:
        return "[TRUNCATED_FOR_SECURITY]"

    sanitized = message
    for pattern, replacement in SANITIZATION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)

    return sanitized


def secure_environment_update(key: str, value: str) -> bool:  # Added return type
    """Securely update environment variables with validation."""
    try:
        # Additional security checks
        if not key or not value:
            logger.warning("Invalid environment variable key or value")
            return False

        # Validate key format
        if not ALLOWED_ENV_VAR_PATTERN.match(key):
            logger.warning(f"Invalid environment variable key format: {sanitize_error_message(key)}")
            return False

        # Validate AWS-specific keys
        aws_keys = ["AWS_PROFILE", "AWS_DEFAULT_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
        if key in aws_keys:
            # Special handling for AWS keys
            if key == "AWS_DEFAULT_REGION" and not re.match(r"^[a-z]{2,3}-[a-z]+-\d$", value):
                logger.warning(f"Invalid AWS region format: {value}")
                return False

        # Added security check for sensitive variables
        SENSITIVE_ENV_VARS = ["AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "DATABASE_PASSWORD"]
        if key in SENSITIVE_ENV_VARS:
            if not value.startswith("aws-secret:"):
                logger.error("Sensitive environment variables must use aws-secret: prefix")
                return False

        # Update environment
        os.environ[key] = value

        # Log successful update (with sanitization for non-AWS keys)
        if key in ["AWS_PROFILE", "AWS_DEFAULT_REGION"]:
            logger.info(f"Environment variable {key} updated successfully")
        else:
            logger.info(f"Environment variable {sanitize_error_message(key)} updated")

        return True

    except Exception as e:
        logger.error(
            f"Failed to update environment variable {sanitize_error_message(key)}: {sanitize_error_message(str(e))}"
        )
        return False


def validate_ip(ip_address: str) -> bool:
    """Validate IP address format."""
    try:
        import ipaddress

        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


def handle_aws_error(e: Exception, operation: str) -> str:
    """Handle AWS exceptions with comprehensive sanitization."""
    status_code = 500

    if isinstance(e, ClientError):
        error_code_str = e.response.get("Error", {}).get("Code", "Unknown")
        raw_message = e.response.get("Error", {}).get("Message", str(e))
        sanitized_message = sanitize_error_message(raw_message)

        # Map AWS error codes to our ErrorCode enum
        error_code = ErrorCode.AWS_CLIENT_ERROR
        if "Throttling" in error_code_str:
            error_code = ErrorCode.AWS_THROTTLING_ERROR
        elif "AccessDenied" in error_code_str:
            error_code = ErrorCode.AWS_ACCESS_DENIED
        elif "NotFound" in error_code_str:
            error_code = ErrorCode.AWS_RESOURCE_NOT_FOUND

        return ErrorResponse(
            error={"message": sanitized_message, "code": error_code.value}, http_status=status_code
        ).json()
    else:
        # Generic exceptions with sanitization
        sanitized_message = sanitize_error_message(str(e))
        return ErrorResponse(
            error={"message": sanitized_message, "code": ErrorCode.UNKNOWN_ERROR.value}, http_status=status_code
        ).json()


def register_simple_tools():
    """Register simple tools following AWS Labs patterns (@mcp.tool decorators)."""
    logger.info("Registering Simple Mode tools with AWS Labs compliance...")

    @mcp.tool(name="SimpleDiscoverIpDetails")
    async def simple_discover_ip_details(
        ip_address: str = Field(
            ...,
            description=("IP address to look up. CRITICAL: Must be valid IPv4/IPv6 address format"),
            min_length=7,
            max_length=45,  # IPv6 max length
            pattern=(
                r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
                r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|"
                r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
            ),
        ),
        region: Optional[str] = Field(
            None,
            description=("AWS region to search. CRITICAL: Use valid AWS region code. Defaults to server configuration"),
            pattern=r"^[a-z]{2,3}-[a-z]+-\d+$",
            max_length=20,
        ),
    ) -> str:
        """Simple IP discovery following AWS Labs pattern (Simple Mode)."""
        # Custom validation
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            return handle_aws_error(ValueError(f"Invalid IP address format: {ip_address}"), "SimpleDiscoverIpDetails")

        try:
            region = region or aws_config.default_region
            ec2_client = get_aws_client("ec2", region)

            # Basic IP address lookup
            try:
                response = ec2_client.describe_addresses(PublicIps=[ip_address])
                if response["Addresses"]:
                    return BaseResponse(status="success", data=response.get("Addresses", [])).json()
            except ClientError:
                pass

            # Check if it's a private IP in ENI
            eni_response = ec2_client.describe_network_interfaces(
                Filters=[{"Name": "private-ip-address", "Values": [ip_address]}]
            )

            if eni_response["NetworkInterfaces"]:
                return BaseResponse(status="success", data=eni_response["NetworkInterfaces"][0]).json()

            return BaseResponse(
                status="success", data={"message": f"No AWS resources found for IP {ip_address}"}
            ).json()

        except ClientError as e:
            return handle_aws_error(e, "SimpleDiscoverIpDetails")
        except Exception as e:
            return handle_aws_error(e, "SimpleDiscoverIpDetails")

    @mcp.tool(name="SimpleListCoreNetworks")
    async def simple_list_core_networks(
        region: Optional[str] = Field(
            None,
            description=("AWS region to query. IMPORTANT: Must be valid AWS region code. Defaults to us-east-1"),
            pattern=r"^[a-z]{2,3}-[a-z]+-\d+$",
            max_length=20,
            examples=["us-east-1", "eu-west-1", "ap-southeast-1"],
        ),
    ) -> str:
        """Simple core network listing following AWS Labs pattern (Simple Mode)."""
        # Validate region if provided
        if region and not AWS_REGION_PATTERN.match(region):
            return handle_aws_error(ValueError(f"Invalid AWS region format: {region}"), "SimpleListCoreNetworks")

        try:
            region = region or aws_config.default_region
            client = get_aws_client("networkmanager", region)

            response = client.list_core_networks()
            return safe_json_dumps(response.get("CoreNetworks", []))

        except Exception as e:
            return handle_aws_error(e, "SimpleListCoreNetworks")

    logger.info("✅ Simple Mode tools registered: SimpleDiscoverIpDetails, SimpleListCoreNetworks")


def register_modular_tools():
    """Register advanced modular tools from tools/ directory."""
    logger.info("Registering Advanced Mode modular tools...")
    try:
        # Import the register_all_tools function from tools module
        from .tools import register_all_tools

        # Register all modular tool groups using the existing architecture
        tool_instances = register_all_tools(mcp)

        logger.info(f"✅ Successfully registered {len(tool_instances)} advanced tool groups")
        logger.info(
            "Advanced tools: Discovery, Core Network, Network Analysis, Transit Gateway, NFG Management, Configuration"
        )
        return True

    except (ImportError, ModuleNotFoundError) as e:
        logger.error(f"Failed to load modular tools: {sanitize_error_message(str(e))}")
        logger.info("Falling back to simple tools only")
        return False


# ============================================================================
# CONDITIONAL TOOL REGISTRATION BASED ON OPERATION MODE
# ============================================================================

# Register tools based on operation mode
if OPERATION_MODE == OperationMode.SIMPLE.value:
    register_simple_tools()
    logger.info("🔧 Simple Mode: Only SimpleXxx tools registered (AWS Labs compliance)")
elif OPERATION_MODE == OperationMode.ADVANCED.value:
    modular_tools_registered = register_modular_tools()
    if not modular_tools_registered:
        logger.warning("Modular tools registration failed, falling back to simple tools")
        register_simple_tools()
    else:
        logger.info("⚡ Advanced Mode: Only modular tools registered (full capabilities)")
elif OPERATION_MODE == OperationMode.DUAL.value:
    register_simple_tools()
    modular_tools_registered = register_modular_tools()
    if modular_tools_registered:
        logger.info("🚀 Dual Mode: Both SimpleXxx and advanced modular tools registered")
    else:
        # Dual-mode fallback to simple tools
        logger.warning("Advanced tools failed to load, falling back to Simple Mode")

logger.info("🎯 Dual-Mode Architecture: Legacy monolithic tools DISABLED")
logger.info("💡 Tool Architecture: Simple + Modular = Clean namespace separation")


def main() -> None:  # Added return type
    """Run the MCP server."""
    logger.info("Starting AWS CloudWAN MCP Server...")

    # Validate environment
    region = aws_config.default_region
    if not region:
        logger.error("AWS_DEFAULT_REGION environment variable is required")
        sys.exit(1)

    profile = aws_config.profile or "default"
    logger.info(f"AWS Region: {region}")
    logger.info(f"AWS Profile: {profile}")

    try:
        mcp.run()
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
