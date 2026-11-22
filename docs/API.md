# AegisForge REST & WebSocket API Reference

The AegisForge backend provides a high-performance asynchronous REST API and real-time WebSocket telemetry broadcaster.

- **Base URL**: `http://127.0.0.1:8000/api/v1`
- **Interactive Swagger Docs**: `http://127.0.0.1:8000/docs`
- **ReDoc Specification**: `http://127.0.0.1:8000/redoc`
- **WebSocket Telemetry Stream**: `ws://127.0.0.1:8000/ws/telemetry`
- **Prometheus Metrics**: `http://127.0.0.1:8000/metrics`

---

## Table of Contents
1. [Security, Guardrails & Rate Limiting](#1-security-guardrails--rate-limiting)
2. [Health & System Endpoints](#2-health--system-endpoints)
3. [Module 1: Recon & CVD Endpoints](#3-module-1-recon--cvd-endpoints)
4. [Module 2: Network Arena Endpoints](#4-module-2-network-arena-endpoints)
5. [Module 3: Exploit Studio Endpoints](#5-module-3-exploit-studio-endpoints)
6. [Module 4: Fuzzing & Reverse Engineering Endpoints](#6-module-4-fuzzing--reverse-engineering-endpoints)
7. [Module 5: Malware Triage Endpoints](#7-module-5-malware-triage-endpoints)
8. [Module 6: Purple-Team Scenarios Endpoints](#8-module-6-purple-team-scenarios-endpoints)
9. [WebSocket Real-Time Telemetry Protocol](#9-websocket-real-time-telemetry-protocol)

---

## 1. Security, Guardrails & Rate Limiting

### Target Safety Guard (`SafetyGuard`)
All network scanning, fuzzing, and packet endpoints are guarded by `SafetyGuard`. Targets must fall within:
- **Loopback**: `127.0.0.0/8`, `::1`
- **RFC 1918 Private Subnets**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- **Link-Local**: `169.254.0.0/16`
- **Internal Domains**: `*.local`, `*.internal`, `*.sandbox`, `localhost`

Attempting to target any public WAN IP or external domain will result in an immediate `400 Bad Request` safety block.

### Rate Limiting
Requests are metered by an in-memory sliding-window rate limiter (120 requests/minute per client IP).
- `X-RateLimit-Limit`: Maximum requests per window (default: 120).
- `X-RateLimit-Remaining`: Remaining request budget.
- `X-RateLimit-Reset`: Time in epoch seconds when the sliding window clears.
- **HTTP 429**: Returned when limit is exceeded with header `Retry-After: 60`.

### Standard Error Format
```json
{
  "detail": "SAFETY VIOLATION: Target '8.8.8.8' is a public WAN address. AegisForge strictly forbids external network probing."
}
```

---

## 2. Health & System Endpoints

### `GET /api/v1/health`
Returns the operational health, execution mode, active WebSocket connections, and safety guard status.

**Example Request:**
```bash
curl -X GET http://127.0.0.1:8000/api/v1/health
```

**Response (`200 OK`):**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "mode": "simulation",
  "safety_guard_active": true,
  "active_websockets": 1,
  "timestamp": "2026-11-22T15:00:00.000Z"
}
```

---

### `GET /api/v1/metrics`
Returns application performance and operational counters in structured JSON format.

**Example Request:**
```bash
curl -X GET http://127.0.0.1:8000/api/v1/metrics
```

**Response (`200 OK`):**
```json
{
  "total_requests": 142,
  "active_websockets": 1,
  "safety_violations_blocked": 3,
  "rate_limit_hits": 0,
  "scenarios_executed": 4,
  "fuzz_cases_generated": 400,
  "crashes_detected": 12,
  "artifacts_triaged": 8,
  "uptime_seconds": 1240.5
}
```

---

### `GET /metrics`
Exposes system telemetry formatted for Prometheus / OpenMetrics scraping.

**Example Request:**
```bash
curl -X GET http://127.0.0.1:8000/metrics
```

**Response (`200 OK`):**
```text
# HELP aegisforge_requests_total Total number of HTTP requests
# TYPE aegisforge_requests_total counter
aegisforge_requests_total 142
# HELP aegisforge_safety_violations_total Total safety guard violations prevented
# TYPE aegisforge_safety_violations_total counter
aegisforge_safety_violations_total 3
# HELP aegisforge_active_websockets Current active WebSocket clients
# TYPE aegisforge_active_websockets gauge
aegisforge_active_websockets 1
```

---

## 3. Module 1: Recon & CVD Endpoints

### `POST /api/v1/recon/scope`
Validates whether a given IP address, CIDR range, or hostname falls within the authorized local test boundary.

**Request Body (`ScopeVerificationRequest`):**
```json
{
  "target": "192.168.1.100"
}
```

**Response (`200 OK`):**
```json
{
  "target": "192.168.1.100",
  "is_authorized": true,
  "scope_classification": "RFC1918_PRIVATE",
  "guardrail_note": "Target is within private range 192.168.0.0/16. Authorized for security assessments."
}
```

---

### `POST /api/v1/recon/scan`
Executes an asynchronous port scan against an authorized target with service banner grabbing and CVE correlation.

**Request Body (`PortScanRequest`):**
```json
{
  "target": "127.0.0.1",
  "start_port": 20,
  "end_port": 1024,
  "scan_type": "TCP_SYN"
}
```

**Response (`200 OK`):**
```json
{
  "target": "127.0.0.1",
  "scan_duration_ms": 34.2,
  "total_ports_probed": 1005,
  "open_ports_count": 3,
  "open_ports": [
    {
      "port": 22,
      "protocol": "TCP",
      "state": "OPEN",
      "service": "SSH",
      "banner": "OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
      "cve_hints": ["CVE-2023-38408", "CVE-2024-6387"]
    },
    {
      "port": 80,
      "protocol": "TCP",
      "state": "OPEN",
      "service": "HTTP",
      "banner": "nginx/1.24.0",
      "cve_hints": []
    }
  ],
  "scope_verified": true,
  "mode": "simulation"
}
```

---

### `POST /api/v1/recon/cvss`
Calculates CVSS v3.1 base score, severity rating, and vector string based on standard metric parameters.

**Request Body (`CVSSCalculationRequest`):**
```json
{
  "attack_vector": "NETWORK",
  "attack_complexity": "LOW",
  "privileges_required": "NONE",
  "user_interaction": "NONE",
  "scope": "UNCHANGED",
  "confidentiality": "HIGH",
  "integrity": "HIGH",
  "availability": "HIGH"
}
```

**Response (`200 OK`):**
```json
{
  "base_score": 9.8,
  "severity_rating": "CRITICAL",
  "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "metrics_breakdown": {
    "Attack Vector": "Network (0.85)",
    "Attack Complexity": "Low (0.77)",
    "Privileges Required": "None (0.85)",
    "User Interaction": "None (0.85)",
    "Scope": "Unchanged",
    "Confidentiality": "High (0.56)",
    "Integrity": "High (0.56)",
    "Availability": "High (0.56)"
  },
  "formula_components": {
    "iss": 0.915,
    "impact": 5.86,
    "exploitability": 3.89
  }
}
```

---

### `POST /api/v1/recon/report`
Generates an exportable, standardized Coordinated Vulnerability Disclosure (CVD) advisory in Markdown and HTML.

**Request Body (`CVDReportRequest`):**
```json
{
  "advisory_id": "AEGIS-2026-001",
  "vulnerability_title": "Remote Buffer Overflow in MiniProto Header Parser",
  "affected_component": "mini_proto_server.py:5000",
  "target_environment": "AegisForge Virtual Lab",
  "summary": "Boundary check failure allows execution flow diversion.",
  "technical_description": "Sending > 256 bytes into PROTO_PARSE triggers a stack overflow.",
  "reproduction_steps": [
    "Connect to port 5000 via TCP",
    "Send oversized header payload (>256 bytes)",
    "Observe service crash / SIGSEGV"
  ],
  "remediation_recommendations": [
    "Compile with -fstack-protector-strong",
    "Enforce strict input length bounding"
  ],
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "cvss_score": 9.8,
  "severity": "CRITICAL",
  "reporter_contact": "researcher@aegisforge.internal"
}
```

**Response (`200 OK`):**
```json
{
  "advisory_id": "AEGIS-2026-001",
  "markdown_content": "# SECURITY ADVISORY: AEGIS-2026-001\n...",
  "html_content": "<div class=\"advisory-container\">...</div>",
  "json_metadata": { "score": 9.8, "severity": "CRITICAL" },
  "generated_at": "2026-11-22T15:00:00Z"
}
```

---

## 4. Module 2: Network Arena Endpoints

### `GET /api/v1/netarena/status`
Returns the state of all 3 virtual nodes (`Gateway`, `Victim`, `Monitor/Attacker`), current ARP table mappings, and active countermeasure flags.

**Response (`200 OK`):**
```json
{
  "nodes": [
    { "id": "node-gw", "label": "Default Gateway", "ip": "192.168.100.1", "mac": "02:42:c0:a8:64:01", "role": "GATEWAY", "is_compromised": false },
    { "id": "node-vic", "label": "Victim Host", "ip": "192.168.100.105", "mac": "02:42:c0:a8:64:69", "role": "VICTIM", "is_compromised": false },
    { "id": "node-atk", "label": "Security Node", "ip": "192.168.100.200", "mac": "02:42:c0:a8:64:c8", "role": "MONITOR_ATTACKER", "is_compromised": false }
  ],
  "arp_table": [
    { "ip": "192.168.100.1", "mac": "02:42:c0:a8:64:01", "hostname": "gateway.internal", "state": "VALID", "last_seen": "2026-11-22T15:00:00Z" }
  ],
  "mitm_active": false,
  "active_defense_enabled": false,
  "total_packets_inspected": 240,
  "spoofed_packets_detected": 0,
  "defensive_actions_taken": []
}
```

---

### `POST /api/v1/netarena/mitm`
Toggles simulated ARP cache poisoning between Victim and Gateway nodes.

**Request Body (`ToggleMITMRequest`):**
```json
{
  "enable": true,
  "target_ip": "192.168.100.105",
  "gateway_ip": "192.168.100.1"
}
```

**Response (`200 OK`):**
Returns updated `NetArenaStatusResponse`.

---

### `POST /api/v1/netarena/defense`
Activates or deactivates the Dynamic ARP Inspection (DAI) and static table pinning defensive countermeasure.

**Request Body (`ToggleActiveDefenseRequest`):**
```json
{
  "enable": true,
  "enable_static_pinning": true,
  "enable_gratuitous_arp_counter": true
}
```

**Response (`200 OK`):**
Returns updated `NetArenaStatusResponse`.

---

### `GET /api/v1/netarena/packets`
Retrieves recent network packets from the ring buffer.

**Query Parameters:**
- `count` (int, default: 50, min: 1, max: 200)

**Response (`200 OK`):**
```json
[
  {
    "id": "pkt-1042",
    "timestamp": "2026-11-22T15:00:01.210Z",
    "source_ip": "192.168.100.200",
    "source_mac": "02:42:c0:a8:64:c8",
    "dest_ip": "192.168.100.105",
    "dest_mac": "02:42:c0:a8:64:69",
    "protocol": "ARP",
    "length": 42,
    "info": "ARP Reply: 192.168.100.1 is-at 02:42:c0:a8:64:c8 (POISONING ATTEMPT)",
    "is_anomalous": true
  }
]
```

---

## 5. Module 3: Exploit Studio Endpoints

### `POST /api/v1/exploit/shellcode`
Disassembles x86/x64 shellcode using Capstone, identifies forbidden null/bad bytes, detects NOP sleds, and outputs heuristic safety verdicts.

**Request Body (`ShellcodeAnalyzeRequest`):**
```json
{
  "hex_payload": "9090909031c050682f2f7368682f62696e89e3505389e131d2b00bcd80",
  "architecture": "x86",
  "forbidden_chars": ["00", "0a", "0d", "20"]
}
```

**Response (`200 OK`):**
```json
{
  "total_bytes": 28,
  "null_byte_count": 0,
  "null_byte_percentage": 0.0,
  "bad_chars_found": [],
  "has_nop_sled": true,
  "nop_sled_length": 4,
  "heuristic_classification": "EXECVE_SHELLCODE",
  "instructions": [
    { "address": "0x00000000", "hex_bytes": "90", "mnemonic": "nop", "operands": "", "is_badchar_present": false },
    { "address": "0x00000004", "hex_bytes": "31c0", "mnemonic": "xor", "operands": "eax, eax", "is_badchar_present": false }
  ],
  "safety_verdict": "ANOMALOUS_SHELLCODE_DETECTED"
}
```

---

### `POST /api/v1/exploit/stack-simulate`
Simulates CPU stack memory layout under buffer overflow conditions, demonstrating the impact of Stack Canaries, NX/DEP, and ASLR/PIE mitigations.

**Request Body (`StackFrameSimulateRequest`):**
```json
{
  "buffer_allocated_bytes": 32,
  "input_payload_bytes": 56,
  "architecture": "x86_64",
  "enable_stack_canary": true,
  "enable_nx_dep": true,
  "enable_aslr": true,
  "enable_pie": true,
  "enable_relro": true
}
```

**Response (`200 OK`):**
```json
{
  "architecture": "x86_64",
  "total_frame_size": 56,
  "buffer_overflowed": true,
  "bytes_overflowed": 24,
  "canary_tripped": true,
  "saved_fp_overwritten": true,
  "return_address_overwritten": true,
  "execution_verdict": "CANARY_TERMINATION",
  "mitigations_active": {
    "canary": true,
    "nx_dep": true,
    "aslr": true,
    "pie": true,
    "relro": true
  },
  "stack_regions": [
    { "name": "Local Buffer", "offset_start": 0, "offset_end": 32, "size_bytes": 32, "corrupted": false, "current_content_hex": "41414141...", "role": "USER_DATA" },
    { "name": "Stack Canary", "offset_start": 32, "offset_end": 40, "size_bytes": 8, "corrupted": true, "current_content_hex": "4141414141414141", "role": "GUARD_SSP" }
  ],
  "explanation": "Input payload exceeded allocated buffer by 24 bytes. Stack Canary corrupted; application terminated via __stack_chk_fail before return address dereference."
}
```

---

## 6. Module 4: Fuzzing & Reverse Engineering Endpoints

### `POST /api/v1/fuzz/protocol`
Executes mutation-based protocol fuzzing against a target port, recording case throughput, mutations, and crash register snapshots.

**Request Body (`ProtocolFuzzRequest`):**
```json
{
  "target_host": "127.0.0.1",
  "target_port": 5000,
  "max_cases": 100,
  "mutation_strategies": ["BIT_FLIP", "BOUNDARY_INTEGER", "OVERSIZE_BUFFER"]
}
```

**Response (`200 OK`):**
```json
{
  "target": "127.0.0.1:5000",
  "total_cases_run": 100,
  "cases_per_second": 325.4,
  "crashes_detected": 2,
  "unique_crashes": [
    {
      "case_id": 42,
      "strategy": "OVERSIZE_BUFFER",
      "payload_hex": "41414141...",
      "payload_preview": "AAAAAA... [512 bytes]",
      "crash_reason": "SIGSEGV (Memory access violation at 0x41414141)",
      "registers_snapshot": { "RIP": "0x41414141", "RSP": "0x7fffffffe000" },
      "reproduction_command": "python -c 'print(\"A\"*512)' | nc 127.0.0.1 5000"
    }
  ],
  "test_cases": []
}
```

---

### `POST /api/v1/fuzz/acl-audit`
Audits Windows Access Control List (ACL) security descriptors from JSON input, flagging excessive privileges (`Everyone: FullControl`, weak system write permissions).

**Request Body (`ACLAuditRequest`):**
```json
{
  "policy_json": {
    "rules": [
      {
        "path": "C:\\ProgramData\\App\\service.exe",
        "principal": "Everyone",
        "permission": "FullControl",
        "inheritance": "Inherited"
      }
    ]
  }
}
```

**Response (`200 OK`):**
```json
{
  "total_rules_analyzed": 1,
  "high_risk_findings": 1,
  "findings": [
    {
      "target_path": "C:\\ProgramData\\App\\service.exe",
      "principal": "Everyone",
      "permission": "FullControl",
      "risk_level": "CRITICAL",
      "description": "Unrestricted write/modify privileges granted to Everyone principal.",
      "remediation_cmd": "icacls \"C:\\ProgramData\\App\\service.exe\" /remove \"Everyone\""
    }
  ],
  "compliance_summary": "1 high-risk privilege misconfiguration detected."
}
```

---

### `POST /api/v1/fuzz/binary-audit`
Parses ELF32/64 or PE32/PE32+ binary headers, maps section entropy, and evaluates compiler mitigation flags (Canary, NX, PIE, RELRO).

**Request Body (`BinaryAuditRequest`):**
```json
{
  "filename": "sample_synthetic.elf"
}
```

**Response (`200 OK`):**
```json
{
  "filename": "sample_synthetic.elf",
  "binary_format": "ELF64",
  "architecture": "x86_64",
  "endianness": "Little-Endian",
  "entry_point": "0x401000",
  "mitigations": {
    "canary": true,
    "nx_dep": true,
    "pie_aslr": true,
    "relro": "FULL",
    "fortify": true
  },
  "sections": [
    { "name": ".text", "virtual_address": "0x401000", "raw_size": 2048, "entropy": 5.82, "flags": "RX" }
  ],
  "security_score": 9.5,
  "verdict": "HARDENED_BINARY",
  "findings": ["All modern compiler security mitigations active."]
}
```

---

## 7. Module 5: Malware Triage Endpoints

### `POST /api/v1/maltriage/analyze`
Triages a benign binary or payload: computes Shannon entropy sliding windows, extracts and classifies IOC strings, matches YARA rules, and maps findings to the MITRE ATT&CK matrix.

**Request Body (`TriageArtifactRequest`):**
```json
{
  "filename": "sample_synthetic.elf"
}
```

**Response (`200 OK`):**
```json
{
  "filename": "sample_synthetic.elf",
  "file_size_bytes": 10240,
  "file_type": "ELF 64-bit LSB executable, x86-64",
  "hashes": {
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "overall_entropy": 5.42,
  "is_high_entropy": false,
  "entropy_sliding_window": [
    { "offset": 0, "size": 256, "entropy": 4.12 }
  ],
  "extracted_strings_count": 45,
  "classified_strings": {
    "urls": ["http://127.0.0.1:8000/telemetry"],
    "ips": ["192.168.100.1"],
    "registry_keys": [],
    "suspicious_apis": ["ptrace", "sys_execve"]
  },
  "detected_iocs": {
    "ips": ["192.168.100.1"],
    "urls": ["http://127.0.0.1:8000/telemetry"]
  },
  "yara_matches": [
    {
      "rule_id": "SYNTH_ELF_HEADER",
      "rule_name": "Synthetic Safe ELF Header",
      "severity": "INFO",
      "mitre_technique": "T1059",
      "matched_strings": ["\\x7fELF"],
      "description": "Standard Linux Executable and Linkable Format magic bytes."
    }
  ],
  "mitre_attack_matrix": [
    {
      "id": "T1059",
      "name": "Command and Scripting Interpreter",
      "tactic": "Execution",
      "confidence": "HIGH",
      "evidence": "Matched synthetic execution strings"
    }
  ],
  "risk_score": 1.5,
  "verdict": "BENIGN_SYNTHETIC_ARTIFACT"
}
```

---

### `GET /api/v1/maltriage/samples`
Returns the list of deterministically generated benign test artifacts available in the sandbox.

**Response (`200 OK`):**
```json
[
  {
    "filename": "sample_synthetic.elf",
    "description": "Harmless synthetic ELF64 binary with standard sections.",
    "size_bytes": 10240
  },
  {
    "filename": "sample_synthetic.exe",
    "description": "Harmless synthetic PE32+ executable header and stub.",
    "size_bytes": 8192
  },
  {
    "filename": "sample_eicar_test.txt",
    "description": "Standard benign EICAR anti-malware test signature.",
    "size_bytes": 68
  }
]
```

---

## 8. Module 6: Purple-Team Scenarios Endpoints

### `POST /api/v1/scenarios/run-purple-team`
Orchestrates an automated 6-stage end-to-end Purple-Team simulation across all security engines, broadcasting real-time progress via WebSocket.

**Stages Executed:**
1. **Reconnaissance**: Scoped port probe and RFC 1918 verification.
2. **Adversary Emulation**: Simulated ARP spoofing and traffic diversion.
3. **Active Defense**: Dynamic ARP Inspection and static table pinning.
4. **Vulnerability Discovery**: Protocol fuzzing and crash register triage.
5. **Exploit Analysis**: Shellcode badchar audit and stack mitigation simulation.
6. **Artifact Triage**: Static binary entropy mapping and MITRE ATT&CK correlation.

**Response (`200 OK`):**
```json
{
  "scenario_id": "scen-20261122-150230",
  "scenario_title": "Full Purple-Team Lifecycle Simulation",
  "started_at": "2026-11-22T15:02:30.120Z",
  "completed_at": "2026-11-22T15:02:33.450Z",
  "total_steps": 6,
  "status": "COMPLETED",
  "steps": [
    {
      "step_id": 1,
      "name": "Target Scope & Reconnaissance",
      "module": "RECON",
      "status": "SUCCESS",
      "details": "Port scan completed. 3 ports open on 127.0.0.1.",
      "telemetry": { "open_ports": [22, 80, 5000] }
    }
  ],
  "final_report_summary": "Purple-team lifecycle executed successfully. All defensive countermeasures verified."
}
```

---

### `GET /api/v1/scenarios/history`
Returns historical scenario execution records stored in the SQLite database.

**Query Parameters:**
- `limit` (int, default: 20)

**Response (`200 OK`):**
```json
{
  "total": 5,
  "runs": [
    {
      "scenario_id": "scen-20261122-150230",
      "scenario_title": "Full Purple-Team Lifecycle Simulation",
      "status": "COMPLETED",
      "total_steps": 6,
      "created_at": "2026-11-22 15:02:33"
    }
  ]
}
```

---

## 9. WebSocket Real-Time Telemetry Protocol

The WebSocket endpoint provides high-frequency event streaming for the React dashboard and connected CLI clients.

- **URL**: `ws://127.0.0.1:8000/ws/telemetry`

### Protocol Messages

#### 1. Heartbeat Ping / Pong
Clients should send periodic heartbeat messages:
- Client to Server: `{"type": "ping"}`
- Server to Client: `{"type": "pong"}`

#### 2. Telemetry Broadcast Event
```json
{
  "id": "evt-812739",
  "timestamp": "2026-11-22T15:00:02.124Z",
  "module": "NET_ARENA",
  "severity": "CRITICAL",
  "message": "Rogue gratuitous ARP detected from 02:42:c0:a8:64:c8 claiming 192.168.100.1. Poisoning blocked by DAI.",
  "data": {
    "source_mac": "02:42:c0:a8:64:c8",
    "claimed_ip": "192.168.100.1",
    "mitigation": "STATIC_PINNING_APPLIED"
  }
}
```

### Event Severity Levels
- `INFO`: Normal operational progress and diagnostic milestones.
- `WARNING`: Anomalous network frame or boundary condition detected.
- `ERROR`: Protocol crash or service communication failure.
- `CRITICAL`: Active MITM attempt, corrupted stack canary, or high-risk finding.
- `SUCCESS`: Defensive mitigation successfully deployed and confirmed.
