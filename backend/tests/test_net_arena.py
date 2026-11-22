import pytest
from backend.app.engines.net_arena import NetArenaEngine
from backend.app.models.schemas import ToggleMITMRequest, ToggleActiveDefenseRequest

@pytest.fixture
def arena():
    return NetArenaEngine()

def test_net_arena_baseline(arena):
    status = arena.get_status()
    assert len(status.nodes) == 3
    assert status.mitm_active is False
    assert status.active_defense_enabled is True

    # Check ARP Table has valid Gateway
    gw_entry = arena.victim_arp_table[arena.gateway.ip]
    assert gw_entry.mac == arena.gateway.mac
    assert gw_entry.state == "VALID"

@pytest.mark.asyncio
async def test_mitm_thwarted_by_active_defense(arena):
    # Defense is ENABLED by default
    res = await arena.toggle_mitm(ToggleMITMRequest(enable=True))
    assert res.mitm_active is True
    assert res.spoofed_packets_detected > 0
    # Victim ARP table remains PINNED or VALID to legitimate gateway MAC
    gw_entry = arena.victim_arp_table[arena.gateway.ip]
    assert gw_entry.mac == arena.gateway.mac
    assert gw_entry.state == "PINNED"

@pytest.mark.asyncio
async def test_mitm_poisons_arp_when_defense_disabled(arena):
    # Disable defense
    await arena.toggle_defense(ToggleActiveDefenseRequest(enable=False))
    res = await arena.toggle_mitm(ToggleMITMRequest(enable=True))

    # Now victim ARP table should be poisoned with attacker MAC
    gw_entry = arena.victim_arp_table[arena.gateway.ip]
    assert gw_entry.mac == arena.attacker.mac
    assert gw_entry.state == "POISONED"

    # Re-enabling defense should clean and restore
    res2 = await arena.toggle_defense(ToggleActiveDefenseRequest(enable=True, enable_static_pinning=True))
    gw_entry_restored = arena.victim_arp_table[arena.gateway.ip]
    assert gw_entry_restored.mac == arena.gateway.mac
    assert gw_entry_restored.state == "PINNED"

def test_synthetic_packet_stream(arena):
    packets = arena.generate_synthetic_packets(count=10)
    assert len(packets) == 10
    for p in packets:
        assert p.protocol in ["ARP", "DNS", "HTTP", "TCP", "ICMP"]
        assert len(p.source_ip) > 0
