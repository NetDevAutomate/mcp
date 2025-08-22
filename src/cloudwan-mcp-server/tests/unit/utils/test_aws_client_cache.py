import pytest
from unittest.mock import patch
from awslabs.cloudwan_mcp_server.utils.aws_client_cache import ThreadSafeAWSClientCache

@pytest.fixture
def cache():
    return ThreadSafeAWSClientCache(max_size=2)

@patch('boto3.client')
def test_cache_hit(mock_boto, cache):
    client1 = cache.get_client("ec2", "us-east-1")
    client2 = cache.get_client("ec2", "us-east-1")
    assert client1 is client2

def test_cache_eviction(cache):
    cache.get_client("ec2", "us-east-1")
    cache.get_client("s3", "us-west-2")
    cache.get_client("rds", "eu-central-1")
    assert len(cache._cache) == 2