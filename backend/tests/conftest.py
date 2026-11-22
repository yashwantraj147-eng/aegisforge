import pytest
from httpx import AsyncClient, ASGITransport
from backend.app.main import app

@pytest.fixture
def anyio_backend():
    return "asyncio"

@pytest.fixture
async def async_client():
    """Shared HTTPX async client bound directly to the FastAPI ASGI application."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client

@pytest.fixture
def sample_eicar_hex():
    """Standard EICAR Anti-Virus test file raw hex bytes."""
    return "58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e444152442d414e544956495255532d544553542d46494c452124482b482a"

@pytest.fixture
def sample_nop_sled_hex():
    """Standard x86 NOP sled + execve /bin/sh shellcode hex."""
    return "9090909031c050682f2f7368682f62696e89e3505389e1b00bcd80"
