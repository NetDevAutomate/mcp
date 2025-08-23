import json
import pytest
from awslabs.cloudwan_mcp_server.server import list_network_function_groups


@pytest.mark.asyncio
async def test_list_network_function_groups():
    result = await list_network_function_groups()
    data = json.loads(result)
    assert data["success"] is True
    
    # Check for either 'groups' or 'network_function_groups'
    groups = data.get("groups") or data.get("network_function_groups", [])
    assert len(groups) >= 2, "Expected at least 2 network function groups"

    # Verify each group has required attributes
    for group in groups:
        assert isinstance(group, dict), "Each group should be a dictionary"
        assert "name" in group or "id" in group, "Group should have a name or id"
