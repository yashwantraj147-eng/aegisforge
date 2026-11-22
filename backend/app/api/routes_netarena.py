from fastapi import APIRouter
from backend.app.engines.net_arena import net_arena_engine
from backend.app.models.schemas import (
    NetArenaStatusResponse, ToggleMITMRequest, ToggleActiveDefenseRequest, PacketEvent
)

router = APIRouter(prefix="/netarena", tags=["Module 2: Net Arena & Active Defense"])

@router.get("/status", response_model=NetArenaStatusResponse)
def get_net_arena_status():
    """Returns current micro-network state, node topology, and victim ARP cache."""
    return net_arena_engine.get_status()

@router.post("/mitm", response_model=NetArenaStatusResponse)
async def toggle_mitm(req: ToggleMITMRequest):
    """Engages or disengages simulated ARP cache poisoning attack."""
    return await net_arena_engine.toggle_mitm(req)

@router.post("/defense", response_model=NetArenaStatusResponse)
async def toggle_defense(req: ToggleActiveDefenseRequest):
    """Toggles Active Defense Daemon (Dynamic ARP Inspection + Static Pinning)."""
    return await net_arena_engine.toggle_defense(req)

@router.get("/packets", response_model=list[PacketEvent])
def get_packets(count: int = 5):
    """Returns stream of synthetic network packet frames for live telemetry inspection."""
    return net_arena_engine.generate_synthetic_packets(count)
