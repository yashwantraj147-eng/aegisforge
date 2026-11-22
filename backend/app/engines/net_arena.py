import asyncio
import random
import time
from datetime import datetime, timezone
from typing import List, Dict, Optional

from backend.app.core.config import settings
from backend.app.core.ws_manager import ws_manager
from backend.app.models.schemas import (
    NetNode, ARPEntry, PacketEvent, NetArenaStatusResponse,
    ToggleMITMRequest, ToggleActiveDefenseRequest
)

class NetArenaEngine:
    """
    Module 2: Network Arena & Active Defense Daemon.
    Simulates a 3-node micro-network:
      - Node 1: Gateway (192.168.100.1, MAC: 00:11:22:33:44:01)
      - Node 2: Victim Host (192.168.100.105, MAC: 00:11:22:33:44:02)
      - Node 3: Attacker/Monitor (192.168.100.200, MAC: 00:11:22:33:44:03)
    Features:
      - Live ARP table simulation
      - Simulated ARP Cache Poisoning / MITM attack
      - Active Defense Daemon: Real-time Dynamic ARP Inspection (DAI) & Static Table Pinning
      - Realistic synthetic packet stream generator
    """
    def __init__(self):
        self.gateway = NetNode(
            id="node-gw",
            label="Internal Gateway",
            ip="192.168.100.1",
            mac="00:11:22:33:44:01",
            role="GATEWAY"
        )
        self.victim = NetNode(
            id="node-victim",
            label="Victim Workstation",
            ip="192.168.100.105",
            mac="00:11:22:33:44:02",
            role="VICTIM"
        )
        self.attacker = NetNode(
            id="node-attacker",
            label="Monitor / Sandbox Attacker",
            ip="192.168.100.200",
            mac="00:11:22:33:44:03",
            role="MONITOR_ATTACKER"
        )

        self.mitm_active: bool = False
        self.active_defense_enabled: bool = True
        self.static_pinning_enabled: bool = True
        self.gratuitous_counter_enabled: bool = True

        self.total_packets_inspected: int = 142
        self.spoofed_packets_detected: int = 0
        self.defensive_actions: List[str] = [
            "DAI Daemon initialized and monitoring virtual bridge interface.",
            "Baseline ARP mappings cached for 192.168.100.0/24 subnet."
        ]

        self._lock = asyncio.Lock()
        # In-memory ARP Table for Victim
        self.victim_arp_table: Dict[str, ARPEntry] = {}
        self._reset_arp_table()

    def _reset_arp_table(self):
        now = datetime.now(timezone.utc).isoformat()
        self.victim_arp_table = {
            self.gateway.ip: ARPEntry(
                ip=self.gateway.ip,
                mac=self.gateway.mac,
                hostname="gateway.aegis.internal",
                state="VALID",
                last_seen=now
            ),
            self.attacker.ip: ARPEntry(
                ip=self.attacker.ip,
                mac=self.attacker.mac,
                hostname="monitor.aegis.internal",
                state="VALID",
                last_seen=now
            )
        }

    def get_status(self) -> NetArenaStatusResponse:
        return NetArenaStatusResponse(
            nodes=[self.gateway, self.victim, self.attacker],
            arp_table=list(self.victim_arp_table.values()),
            mitm_active=self.mitm_active,
            active_defense_enabled=self.active_defense_enabled,
            total_packets_inspected=self.total_packets_inspected,
            spoofed_packets_detected=self.spoofed_packets_detected,
            defensive_actions_taken=self.defensive_actions[-10:]
        )

    async def toggle_mitm(self, req: ToggleMITMRequest) -> NetArenaStatusResponse:
        async with self._lock:
            self.mitm_active = req.enable
            now = datetime.now(timezone.utc).isoformat()

            if self.mitm_active:
            # Check if Active Defense intercepts it
            if self.active_defense_enabled:
                # Active Defense is engaged: Victim is NOT compromised!
                self.victim.is_compromised = False
                self.spoofed_packets_detected += 1
                action_msg = (
                    f"[DEFENSE ACTIVE] Gratuitous ARP packet detected: {self.gateway.ip} claimed by "
                    f"rogue MAC {self.attacker.mac}. Blocked by Dynamic ARP Inspection (DAI)."
                )
                self.defensive_actions.append(action_msg)
                
                if self.static_pinning_enabled:
                    pin_msg = f"[PINNING] Enforced permanent static binding: {self.gateway.ip} -> {self.gateway.mac}"
                    self.defensive_actions.append(pin_msg)
                    self.victim_arp_table[self.gateway.ip] = ARPEntry(
                        ip=self.gateway.ip,
                        mac=self.gateway.mac,
                        hostname="gateway.aegis.internal",
                        state="PINNED",
                        last_seen=now
                    )
                
                if self.gratuitous_counter_enabled:
                    counter_msg = f"[COUNTER] Broadcasted gratuitous ARP correction for {self.gateway.ip} to flush poisoned caches."
                    self.defensive_actions.append(counter_msg)

                await ws_manager.broadcast_event(
                    module="NET_ARENA",
                    event_type="ARP_SPOOF_BLOCKED",
                    severity="CRITICAL",
                    message="Active Defense Daemon thwarted unauthorized ARP spoofing attack on gateway address.",
                    data={
                        "spoofed_ip": self.gateway.ip,
                        "rogue_mac": self.attacker.mac,
                        "legitimate_mac": self.gateway.mac,
                        "countermeasure": "Static ARP Pinning & Gratuitous ARP Correction"
                    }
                )
            else:
                # Defense disabled -> Victim ARP cache is poisoned and compromised!
                self.victim.is_compromised = True
                self.victim_arp_table[self.gateway.ip] = ARPEntry(
                    ip=self.gateway.ip,
                    mac=self.attacker.mac,  # Poisoned with attacker MAC!
                    hostname="gateway.aegis.internal [POISONED]",
                    state="POISONED",
                    last_seen=now
                )
                self.defensive_actions.append(
                    f"[COMPROMISE] ARP Poisoning successful: {self.gateway.ip} resolved to {self.attacker.mac}. Traffic intercepted."
                )
                await ws_manager.broadcast_event(
                    module="NET_ARENA",
                    event_type="ARP_CACHE_POISONED",
                    severity="HIGH",
                    message="Victim ARP cache poisoned. Attacker node in position for Man-in-the-Middle inspection.",
                    data={
                        "target_ip": self.victim.ip,
                        "poisoned_mapping": f"{self.gateway.ip} -> {self.attacker.mac}"
                    }
                )
        else:
            # Disengage MITM
            self.victim.is_compromised = False
            self._reset_arp_table()
            self.defensive_actions.append("[INFO] MITM simulation stopped. ARP cache restored to legitimate gateway binding.")
            await ws_manager.broadcast_event(
                module="NET_ARENA",
                event_type="MITM_DISENGAGED",
                severity="INFO",
                message="Simulated MITM attack terminated. Baseline network state restored."
            )

        return self.get_status()

    async def toggle_defense(self, req: ToggleActiveDefenseRequest) -> NetArenaStatusResponse:
        async with self._lock:
            self.active_defense_enabled = req.enable
            self.static_pinning_enabled = req.enable_static_pinning
            self.gratuitous_counter_enabled = req.enable_gratuitous_arp_counter

            state_str = "ENABLED" if self.active_defense_enabled else "DISABLED"
        msg = f"[CONFIG] Active Defense Daemon {state_str}. DAI Rules: {self.active_defense_enabled}, Pinning: {self.static_pinning_enabled}"
        self.defensive_actions.append(msg)

        # If defense enabled while poisoned, automatically clean up
        if self.active_defense_enabled and self.mitm_active:
            self.victim.is_compromised = False
            self._reset_arp_table()
            self.victim_arp_table[self.gateway.ip].state = "PINNED"
            self.defensive_actions.append("[REMEDIATION] Active Defense re-enabled: auto-remediated poisoned ARP table entries.")

        await ws_manager.broadcast_event(
            module="NET_ARENA",
            event_type="DEFENSE_TOGGLED",
            severity="LOW",
            message=f"Active defense daemon switched to {state_str} state."
        )

        return self.get_status()

    def generate_synthetic_packets(self, count: int = 5) -> List[PacketEvent]:
        """Generates realistic synthetic packet stream for frontend real-time inspection."""
        packets: List[PacketEvent] = []
        now = datetime.now(timezone.utc).isoformat()
        
        protocols = ["ARP", "DNS", "HTTP", "TCP", "ICMP"]
        for _ in range(count):
            self.total_packets_inspected += 1
            proto = random.choice(protocols)
            pkt_id = f"pkt-{self.total_packets_inspected}"
            
            if proto == "ARP":
                if self.mitm_active and not self.active_defense_enabled:
                    src_ip = self.gateway.ip
                    src_mac = self.attacker.mac  # Forged
                    dst_ip = self.victim.ip
                    dst_mac = self.victim.mac
                    info = f"ARP Reply (Rogue): {self.gateway.ip} is at {self.attacker.mac}"
                    anomalous = True
                else:
                    src_ip = self.gateway.ip
                    src_mac = self.gateway.mac
                    dst_ip = "255.255.255.255"
                    dst_mac = "ff:ff:ff:ff:ff:ff"
                    info = f"ARP Who has {self.victim.ip}? Tell {self.gateway.ip}"
                    anomalous = False
            elif proto == "DNS":
                src_ip = self.victim.ip
                src_mac = self.victim.mac
                dst_ip = self.gateway.ip
                dst_mac = self.attacker.mac if (self.mitm_active and not self.active_defense_enabled) else self.gateway.mac
                info = "Standard query 0x12a4 A test-lab.internal"
                anomalous = False
            elif proto == "HTTP":
                src_ip = self.victim.ip
                src_mac = self.victim.mac
                dst_ip = "192.168.100.80"
                dst_mac = self.attacker.mac if (self.mitm_active and not self.active_defense_enabled) else self.gateway.mac
                info = "GET /api/v1/telemetry HTTP/1.1 (Host: lab.internal)"
                anomalous = self.mitm_active and not self.active_defense_enabled
            else:
                src_ip = self.victim.ip
                src_mac = self.victim.mac
                dst_ip = self.gateway.ip
                dst_mac = self.gateway.mac
                info = "TCP [SYN] Seq=0 Win=64240 Len=0 MSS=1460"
                anomalous = False

            packets.append(PacketEvent(
                id=pkt_id,
                timestamp=now,
                source_ip=src_ip,
                source_mac=src_mac,
                dest_ip=dst_ip,
                dest_mac=dst_mac,
                protocol=proto,
                length=random.randint(64, 1514),
                info=info,
                is_anomalous=anomalous
            ))
            
        return packets

net_arena_engine = NetArenaEngine()
