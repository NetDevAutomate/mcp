# aws_client_factory.py
import threading
from functools import lru_cache
from typing import Optional

import boto3
from botocore.config import Config

_client_lock = threading.Lock()


@lru_cache(maxsize=128)
def get_aws_client(service_name: str, region: Optional[str] = None):
    """Get cached AWS client with proper configuration."""
    with _client_lock:
        config = Config(retries={"max_attempts": 3, "mode": "standard"}, read_timeout=30, connect_timeout=10)

        region = region or "us-east-1"

        return boto3.client(service_name, region_name=region, config=config)


def clear_client_cache():
    """Clear the client cache for testing purposes."""
    get_aws_client.cache_clear()


def create_network_firewall_client(region: str) -> Any:
    """Create Network Firewall client with proper config."""
    # REPOMARK:SCOPE: 5 - Implement proper client creation
    from botocore.config import Config

    return get_aws_client("network-firewall", region, config=Config(retries={"max_attempts": 3}))
