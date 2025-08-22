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

"""AWS configuration management utilities for CloudWAN MCP Server."""

import os

from ..consts import DEFAULT_AWS_REGION
from .logger import get_logger

logger = get_logger(__name__)


class AWSConfigManager:
    """AWS configuration manager for dynamic config updates."""

    def __init__(self):
        """Initialize AWS config manager."""
        self.default_region = os.getenv("AWS_DEFAULT_REGION", DEFAULT_AWS_REGION)
        self.profile = os.getenv("AWS_PROFILE")

    def update_region(self, region: str) -> bool:
        """Update default AWS region."""
        try:
            self.default_region = region
            os.environ["AWS_DEFAULT_REGION"] = region
            logger.info(f"Updated AWS region to: {region}")
            return True
        except Exception as e:
            logger.error(f"Failed to update AWS region: {str(e)}")
            return False

    def update_profile(self, profile: str) -> bool:
        """Update AWS profile."""
        try:
            self.profile = profile
            os.environ["AWS_PROFILE"] = profile
            logger.info(f"Updated AWS profile to: {profile}")
            return True
        except Exception as e:
            logger.error(f"Failed to update AWS profile: {str(e)}")
            return False


def get_aws_config() -> AWSConfigManager:
    """Get global AWS config manager instance."""
    if not hasattr(get_aws_config, "_instance"):
        get_aws_config._instance = AWSConfigManager()
    return get_aws_config._instance
