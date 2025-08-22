import pytest
from awslabs.cloudwan_mcp_server.server import list_network_function_groups


@pytest.mark.asyncio
async def test_list_network_function_groups():
    result = await list_network_function_groups()
    data = json.loads(result)
    assert len(data["network_function_groups"]) == 2
    assert data["success"] is True
