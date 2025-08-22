import pytest
import json
from awslabs.cloudwan_mcp_server.server import get_circuit_breaker_status, get_system_resilience_metrics


@pytest.mark.asyncio
class TestCircuitBreakerTools:
    async def test_get_circuit_breaker_status(self):
        result = await get_circuit_breaker_status()
        data = json.loads(result)
        assert data["success"]
        assert "circuit_breakers" in data

    async def test_get_system_resilience_metrics(self):
        result = await get_system_resilience_metrics()
        data = json.loads(result)
        assert data["success"]
        assert "metrics" in data
        assert "health_score" in data
