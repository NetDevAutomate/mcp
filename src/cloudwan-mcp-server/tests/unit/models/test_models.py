import pytest
from pydantic import ValidationError
from awslabs.cloudwan_mcp_server.models.aws_models import CoreNetwork
from awslabs.cloudwan_mcp_server.models.network_models import IPDetails

def test_core_network_model_valid():
    data = {"id": "cn-123", "arn": "arn:aws:networkmanager::123:cn/cn-123"}
    model = CoreNetwork(**data)
    assert model.id == "cn-123"

def test_core_network_model_invalid():
    with pytest.raises(ValidationError):
        CoreNetwork(id="")

def test_ip_details_model():
    details = IPDetails(version=4, is_private=True)
    assert details.is_global is False