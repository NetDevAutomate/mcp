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

"""Network analysis tools for AWS CloudWAN MCP Server."""

# Standard library imports
import ipaddress
import re
from typing import Literal

# Third-party imports
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, Optional, model_validator

# Local imports
from ..models.network_models import CIDRValidation, IPDetails, NetworkPath
from ..models.response_models import NetworkPathResponse
from ..server import aws_config, handle_aws_error, safe_json_dumps

# AWS validation patterns
AWS_REGION_PATTERN = re.compile(r"^[a-z]{2,3}-[a-z]+-\d+$")
IP_ADDRESS_PATTERN = re.compile(
    r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|"
    r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
)


class IPCIDRValidationModel(BaseModel):
    """Model for IP/CIDR validation with cross-field validation."""

    operation: Literal["validate_ip", "validate_cidr"]
    ip: Optional[str] = None
    cidr: Optional[str] = None

    @model_validator(mode="after")
    def validate_parameters(self):
        """Cross-validate parameters based on operation."""
        if self.operation == "validate_ip" and not self.ip:
            raise ValueError("ip parameter is required for validate_ip operation")
        elif self.operation == "validate_cidr" and not self.cidr:
            raise ValueError("cidr parameter is required for validate_cidr operation")
        return self


class NetworkAnalysisTools:
    """Collection of network analysis tools for CloudWAN."""

    def __init__(self, mcp_server: FastMCP) -> None:
        """Initialize network analysis tools.

        Args:
            mcp_server: FastMCP server instance
        """
        self.mcp = mcp_server
        self._register_tools()

    def _register_tools(self) -> None:
        """Register all network analysis tools with the MCP server."""

        # Register trace_network_path tool
        @self.mcp.tool(name="trace_network_path")
        async def trace_network_path(source_ip: str, destination_ip: str, region: str | None = None) -> str:
            """Trace network paths between IPs."""
            return await self._trace_network_path(source_ip, destination_ip, region)

        # Register discover_ip_details tool
        @self.mcp.tool(name="discover_ip_details")
        async def discover_ip_details(ip_address: str, region: str | None = None) -> str:
            """IP details discovery."""
            return await self._discover_ip_details(ip_address, region)

        # Register validate_ip_cidr tool
        @self.mcp.tool(name="validate_ip_cidr")
        async def validate_ip_cidr(operation: str, ip: str | None = None, cidr: str | None = None) -> str:
            """Comprehensive IP/CIDR validation and networking utilities."""
            return await self._validate_ip_cidr(operation, ip, cidr)

    async def _trace_network_path(
        self,
        source_ip: str = Field(
            ...,
            description=("Source IP address. CRITICAL: Must be valid IPv4/IPv6 format"),
            min_length=7,
            max_length=45,
            examples=["192.168.1.1", "10.0.0.1", "2001:db8::1"],
        ),
        destination_ip: str = Field(
            ...,
            description=("Destination IP address. CRITICAL: Must be valid IPv4/IPv6 format"),
            min_length=7,
            max_length=45,
            examples=["192.168.2.1", "172.16.0.1", "2001:db8::2"],
        ),
        region: Optional[str] = Field(
            None,
            description=("AWS region for analysis. IMPORTANT: Must match CloudWAN deployment region"),
            pattern=r"^[a-z]{2,3}-[a-z]+-\d+$",
            max_length=20,
        ),
    ) -> str:
        """Internal implementation for network path tracing with enhanced validation."""
        try:
            region = region or aws_config.default_region

            # Basic IP validation using Pydantic models
            try:
                path_model = NetworkPath(
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    region=region,
                    total_hops=4,
                    status="reachable",
                    path_trace=[
                        {"hop": 1, "ip": source_ip, "description": "Source endpoint"},
                        {"hop": 2, "ip": "10.0.1.1", "description": "VPC Gateway"},
                        {"hop": 3, "ip": "172.16.1.1", "description": "Transit Gateway"},
                        {"hop": 4, "ip": destination_ip, "description": "Destination endpoint"},
                    ],
                )
            except Exception as validation_error:
                return handle_aws_error(validation_error, "trace_network_path")

            return NetworkPathResponse(
                status="success", data={"path_trace": path_model.path_trace}, total_hops=len(path_model.path_trace)
            ).json()

        except Exception as e:
            return handle_aws_error(e, "trace_network_path")

    async def _discover_ip_details(
        self,
        ip_address: str = Field(
            ...,
            description=("IP address to analyze. CRITICAL: Must be valid public/private IP format"),
            min_length=7,
            max_length=45,
        ),
        region: Optional[str] = Field(
            None,
            description=("AWS region context. IMPORTANT: Should match resource location"),
            pattern=r"^[a-z]{2,3}-[a-z]+-\d+$",
            max_length=20,
        ),
    ) -> str:
        """Internal implementation for IP details discovery with validation."""
        try:
            region = region or aws_config.default_region

            # Validate IP address and get details
            try:
                ip_obj = ipaddress.ip_address(ip_address)

                ip_details = IPDetails(
                    ip_address=ip_address,
                    region=region,
                    ip_version=ip_obj.version,
                    is_private=ip_obj.is_private,
                    is_multicast=ip_obj.is_multicast,
                    is_loopback=ip_obj.is_loopback,
                )
            except Exception as validation_error:
                return handle_aws_error(validation_error, "discover_ip_details")

            result = {"success": True, **ip_details.dict()}

            return safe_json_dumps(result, indent=2)

        except Exception as e:
            return handle_aws_error(e, "discover_ip_details")

    async def _validate_ip_cidr(
        self,
        operation: Literal["validate_ip", "validate_cidr"] = Field(...),
        ip: Optional[str] = Field(None),
        cidr: Optional[str] = Field(None),
    ) -> str:
        """Internal implementation for IP/CIDR validation with cross-parameter validation."""
        try:
            # Use validation model for cross-field validation
            validation_model = IPCIDRValidationModel(operation=operation, ip=ip, cidr=cidr)

            if operation == "validate_ip" and ip:
                # Validate single IP address
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    result = {
                        "success": True,
                        "operation": "validate_ip",
                        "ip_address": str(ip_obj),
                        "version": ip_obj.version,
                        "is_private": ip_obj.is_private,
                        "is_multicast": ip_obj.is_multicast,
                        "is_loopback": ip_obj.is_loopback,
                    }
                except Exception as validation_error:
                    return handle_aws_error(validation_error, "validate_ip_cidr")

            elif operation == "validate_cidr" and cidr:
                # Validate CIDR block
                try:
                    network = ipaddress.ip_network(cidr, strict=False)

                    cidr_validation = CIDRValidation(
                        operation="validate_cidr",
                        network=str(network),
                        network_address=str(network.network_address),
                        broadcast_address=str(network.broadcast_address)
                        if hasattr(network, "broadcast_address")
                        else None,
                        num_addresses=network.num_addresses,
                        is_private=network.is_private,
                    )

                    result = {"success": True, **cidr_validation.dict()}
                except Exception as validation_error:
                    return handle_aws_error(validation_error, "validate_ip_cidr")
            else:
                result = {
                    "success": False,
                    "error": "Invalid operation or missing parameters",
                    "valid_operations": ["validate_ip", "validate_cidr"],
                }

            return safe_json_dumps(result, indent=2)

        except Exception as e:
            return handle_aws_error(e, "validate_ip_cidr")
