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

# utils/validation.py
import ipaddress
import re


def validate_aws_region(region: str) -> bool:
    """Validate AWS region format."""
    pattern = re.compile(r"^[a-z]{2,3}-[a-z]+-\d+$")
    return bool(pattern.match(region))


def validate_aws_arn(arn: str) -> bool:
    """Validate AWS ARN format."""
    pattern = re.compile(r"^arn:aws:[^:]+:[^:]*:[^:]*:[^:]+$")
    return bool(pattern.match(arn))


def validate_ip_address(ip: str) -> bool:
    """Validate IP address format."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_cidr_block(cidr: str) -> bool:
    """Validate CIDR block format."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def sanitize_error_message(message: str) -> str:
    """Sanitize error messages to remove sensitive information."""
    if len(message) > 10000:
        return "[TRUNCATED_FOR_SECURITY]"

    # Remove AWS access keys
    message = re.sub(r"AKIA[0-9A-Z]{16}", "[ACCESS_KEY_REDACTED]", message)
    # Remove AWS secret keys (40 char base64-like strings)
    message = re.sub(r"[A-Za-z0-9/+=]{40}", "[SECRET_KEY_REDACTED]", message)
    # Remove ARNs
    message = re.sub(r"arn:aws:[^:]+:[^:]*:[^:]*:[^:]+", "[ARN_REDACTED]", message)

    return message


def secure_environment_update(key: str, value: str) -> bool:
    try:
        # ... existing code ...
        if key in SENSITIVE_VARIABLES:
            if not value.startswith("aws-secret:"):
                raise ValueError("Sensitive variables must use aws-secret: prefix")
        return True
    except (ValueError, TypeError) as e:
        print(f"Environment update validation failed: {sanitize_error_message(str(e))}")
        return False
        # ... existing code ...


# Missing sensitive variables definition
SENSITIVE_VARIABLES = [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "DATABASE_PASSWORD",
    "API_KEY",
]
