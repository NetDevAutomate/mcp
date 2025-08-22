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

"""Input validation utilities for AWS CloudWAN MCP Server."""

import ipaddress
import re
from typing import Any, Dict, List

from ..consts import AWS_REGION_PATTERN
from ..utils.logger import get_logger

logger = get_logger(__name__)


class InputValidator:
    """Input validation for AWS CloudWAN parameters."""

    @staticmethod
    def validate_aws_region(region: str) -> bool:
        """Validate AWS region format."""
        if not region:
            return False
        return bool(AWS_REGION_PATTERN.match(region))

    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Validate IP address format."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_cidr_block(cidr: str) -> bool:
        """Validate CIDR block format."""
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_core_network_id(core_network_id: str) -> bool:
        """Validate CloudWAN core network ID format."""
        pattern = re.compile(r"^core-network-[0-9a-f]{17}$")
        return bool(pattern.match(core_network_id))

    @staticmethod
    def sanitize_string_input(input_str: str, max_length: int = 1000) -> str:
        """Sanitize string input for security."""
        if not input_str:
            return ""

        # Truncate if too long
        if len(input_str) > max_length:
            return input_str[:max_length]

        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\';\\]', "", input_str)
        return sanitized.strip()


def validate_tool_parameters(tool_name: str, parameters: Dict[str, Any]) -> List[str]:
    """Validate tool parameters and return list of validation errors."""
    errors = []
    validator = InputValidator()

    # Common validations
    if "region" in parameters and parameters["region"]:
        if not validator.validate_aws_region(parameters["region"]):
            errors.append(f"Invalid AWS region format: {parameters['region']}")

    if "ip_address" in parameters:
        if not validator.validate_ip_address(parameters["ip_address"]):
            errors.append(f"Invalid IP address format: {parameters['ip_address']}")

    if "cidr" in parameters:
        if not validator.validate_cidr_block(parameters["cidr"]):
            errors.append(f"Invalid CIDR block format: {parameters['cidr']}")

    # Tool-specific validations
    if tool_name in ["get_core_network_policy", "get_core_network_change_set"]:
        if "core_network_id" in parameters:
            if not validator.validate_core_network_id(parameters["core_network_id"]):
                errors.append(f"Invalid core network ID format: {parameters['core_network_id']}")

    return errors
