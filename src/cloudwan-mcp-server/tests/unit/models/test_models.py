import pytest
from pydantic import ValidationError
from awslabs.cloudwan_mcp_server.models.aws_models import CoreNetwork
from awslabs.cloudwan_mcp_server.models.network_models import IPDetails


def test_core_network_model_valid():
    data = {
        "core_network_id": "cn-123",
        "core_network_arn": "arn:aws:networkmanager::123:core-network/cn-123",  # pragma: allowlist secret
        "global_network_id": "gn-456",
        "state": "AVAILABLE",
        "created_at": "2024-01-01T12:00:00Z",
    }
    model = CoreNetwork(**data)
    assert model.core_network_id == "cn-123"


def test_core_network_model_invalid():
    with pytest.raises(ValidationError):
        CoreNetwork(core_network_id="")


def test_ip_details_model():
    details = IPDetails(
        ip_address="192.168.1.1",
        region="us-east-1",
        ip_version=4,
        is_private=True,
        is_multicast=False,
        is_loopback=False,
    )
    assert details.is_private is True
