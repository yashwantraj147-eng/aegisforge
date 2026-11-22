# AegisForge Architecture & Engineering Specification

## 1. System Overview
AegisForge is an integrated purple-team cyber range and defensive vulnerability analysis platform. It provides a synchronized environment where offensive discovery techniques and defensive mitigations are studied side-by-side within strictly bounded local sandbox environments.

```mermaid
flowchart TD
    subgraph Client["Client Tier"]
        UI["Cyber-Ops Dashboard (React 19 + TypeScript + Vite + Tailwind CSS v4)"]
        CLI["aegisctl (Python Typer + Rich)"]
    end

    subgraph Backend["FastAPI Telemetry Hub & Application Layer"]
        API_GW["FastAPI REST & WebSocket Hub"]
        Limiter["Sliding-Window Rate Limiter (120 req/min)"]
        Safety_Guard["SafetyGuard (RFC1918 & Localhost Boundary)"]
        Metrics_Svc["Telemetry & Prometheus Metrics Engine"]
        WS_Bus["WebSocket Broadcaster (30s Heartbeat)"]
        DB["SQLite Persistence Engine (WAL Mode)"]

        subgraph Engines["Specialized Security Engines"]
            Eng_Recon["Recon & CVD Engine"]
            Eng_Net["Net Arena & Active Defense Daemon"]
            Eng_Exploit["Exploit Studio & Stack Simulator"]
            Eng_Fuzz["Protocol Fuzzer & ACL/Binary Parser"]
            Eng_Triage["Static Triage & Entropy Engine"]
        end

        Orchestrator["Purple-Team Scenario Orchestrator"]
    end

    subgraph Sandbox["Isolated Sandbox Tier (Zero External WAN)"]
        Mock_Targets["MiniProto Stateful TCP Service (:5000)"]
        Virtual_Net["Isolated 3-Node Subnet (192.168.100.0/24)"]
        Benign_Artifacts["Harmless Synthetic ELF / PE / EICAR Test Files"]
    end

    UI <-->|REST & WebSocket| API_GW
    CLI <-->|REST & Local Execution| API_GW
    API_GW --> Limiter
    Limiter --> Safety_Guard
    Safety_Guard --> Orchestrator
    Safety_Guard --> Engines
    Orchestrator --> Engines
    Engines --> DB
    Engines --> WS_Bus
    WS_Bus -.->|Real-time Events| UI
    WS_Bus -.->|Real-time Events| CLI
    API_GW --> Metrics_Svc

    Eng_Recon --> Mock_Targets
    Eng_Net --> Virtual_Net
    Eng_Fuzz --> Mock_Targets
    Eng_Triage --> Benign_Artifacts
```

---

## 2. Telemetry and Event Flow
During active testing or when running an automated end-to-end purple-team scenario, events flow through the central telemetry broadcaster:

```mermaid
sequenceDiagram
    autonumber
    actor Operator as Security Engineer
    participant UI as Cyber-Ops Dashboard
    participant API as FastAPI Router
    participant Limit as Rate Limiter
    participant Guard as SafetyGuard
    participant Engine as Security Engine
    participant DB as SQLite (WAL)
    participant Bus as WebSocket Manager

    Operator->>UI: Trigger Action or Scenario
    UI->>API: HTTP Request / WebSocket Handshake
    API->>Limit: Check sliding window (IP budget)
    alt Rate Limit Exceeded
        Limit-->>API: 429 Too Many Requests
        API-->>UI: 429 Rate Limit Error
    else Budget Available
        API->>Guard: Validate Target Destination & Payload Size
        alt Public WAN Target or Oversized Payload
            Guard-->>API: SafetyViolationException (Blocked)
            API-->>UI: 400 Bad Request (Safety Policy Enforced)
        else RFC 1918 / Localhost Permitted
            Guard-->>API: Authorized Target Confirmed
            API->>Engine: Dispatch Task Execution
            Engine->>Bus: broadcast_event(module, severity, message)
            Bus-->>UI: Real-Time Event Push
            Engine->>DB: Persist Task Result (async thread)
            Engine-->>API: Structured Result Schema
            API-->>UI: 200 OK Response
        end
    end
```

---

## 3. Security Engine Sequence Architectures

### 3.1 Module 1: Recon & Coordinated Vulnerability Disclosure (CVD)
The Recon module ensures target IP/CIDR boundaries are verified before any network socket connection is established. It maps open ports, gathers service banners, correlates known CVE identifiers, calculates CVSS v3.1 base metrics, and formats standardized disclosure advisories.

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as Purple-Team Analyst
    participant API as Recon API Router
    participant Guard as SafetyGuard
    participant Scanner as Async Port Scanner
    participant CVSS as CVSS 3.1 Engine
    participant Report as CVD Generator

    Analyst->>API: POST /api/v1/recon/scan (target, start_port, end_port)
    API->>Guard: validate_target(target)
    Guard-->>API: Verified (RFC 1918 private)
    API->>Scanner: scan_target(target, ports)
    Scanner->>Scanner: Async TCP Connect / Banner Grab
    Scanner-->>API: Open Ports, Services & CVE hints
    Analyst->>API: POST /api/v1/recon/cvss (metric vector)
    API->>CVSS: calculate(metrics)
    CVSS-->>API: Base Score (e.g., 9.8 CRITICAL)
    Analyst->>API: POST /api/v1/recon/report (metadata, findings)
    API->>Report: generate_advisory(data)
    Report-->>API: Markdown (.md) + HTML formatted advisory
    API-->>Analyst: Complete CVD Report Package
```

---

### 3.2 Module 2: Network Arena & Active Defense Daemon
The Network Arena models an internal virtual bridge between three nodes:
1. **Gateway** (`192.168.100.1`)
2. **Victim** (`192.168.100.105`)
3. **Monitor/Attacker** (`192.168.100.200`)

It simulates adversary ARP cache poisoning and demonstrates Dynamic ARP Inspection (DAI) defense.

```mermaid
sequenceDiagram
    autonumber
    actor Attacker as Attacker Simulation
    participant Arena as Net Arena Engine
    participant Defense as Active Defense Daemon
    participant Table as ARP Cache Table
    participant Bus as WebSocket Stream

    Attacker->>Arena: POST /api/v1/netarena/mitm (enable: true)
    Arena->>Table: Inject Gratuitous ARP (Gateway is-at Attacker MAC)
    Table-->>Arena: State marked POISONED
    Arena->>Bus: Broadcast WARNING: ARP Cache Poisoned
    alt Active Defense Enabled
        Defense->>Arena: Inspect Incoming ARP Frames (DAI)
        Defense->>Defense: Detect MAC-IP mismatch against pinned lease
        Defense->>Arena: Issue Authoritative Counter-ARP Broadcast
        Defense->>Table: Pin Valid Gateway IP -> Gateway MAC (State: PINNED)
        Defense->>Bus: Broadcast SUCCESS: Dynamic ARP Inspection Mitigated Attack
    else Defense Disabled
        Arena->>Bus: Broadcast CRITICAL: Traffic Intercept Active
    end
```

---

### 3.3 Module 3: Exploit Studio & Memory Simulation
Exploit Studio disassembles raw x86/x64 shellcode using Capstone, audits for forbidden null/bad bytes, and provides an interactive visualizer for x86/x64 CPU stack call frames under buffer overflow conditions.

```mermaid
sequenceDiagram
    autonumber
    actor Researcher as Exploit Researcher
    participant API as Exploit API Router
    participant Disasm as Capstone Disassembler
    participant Auditor as Bad-Char Auditor
    participant Stack as Stack Frame Simulator

    Researcher->>API: POST /api/v1/exploit/shellcode (hex_payload)
    API->>Disasm: Disassemble instruction stream
    Disasm-->>API: Assembly mnemonics, operands, offsets
    API->>Auditor: Audit for forbidden bytes (\\x00, \\x0a, \\x0d, \\x20)
    Auditor-->>API: Badchar offsets & NOP sled detection
    Researcher->>API: POST /api/v1/exploit/stack-simulate (buffer: 32, payload: 56)
    API->>Stack: Construct Frame Layout (Buffer, Canary, Saved RBP, Return RIP)
    alt Canary Tripped
        Stack-->>API: Verdict: CANARY_TERMINATION (__stack_chk_fail)
    else Canary Disabled & NX Active
        Stack-->>API: Verdict: SEGFAULT_NX (Non-executable stack)
    else Canary Disabled & NX Disabled & ASLR Active
        Stack-->>API: Verdict: CONTROL_FLOW_HIJACK_BLOCKED (Entropy failure)
    else All Mitigations Disabled
        Stack-->>API: Verdict: EXECUTION_HIJACKED (Control flow hijacked)
    end
    API-->>Researcher: Interactive memory visualization
```

---

### 3.4 Module 4: Fuzzing & Reverse Engineering Engine
This engine combines a stateful protocol mutation fuzzer (with bit-flip, boundary integer, format string, and oversized buffer strategies) with static ELF/PE binary header analysis and Windows ACL security descriptor auditing.

```mermaid
sequenceDiagram
    autonumber
    actor Tester as Fuzzing Engineer
    participant Fuzzer as Protocol Mutation Engine
    participant Target as MiniProto Target (:5000)
    participant Triage as Crash Triage & Register Capture
    participant Auditor as Binary / ACL Auditor

    Tester->>Fuzzer: POST /api/v1/fuzz/protocol (cases: 100, target: :5000)
    loop Mutation Cycle
        Fuzzer->>Fuzzer: Generate mutated test case payload
        Fuzzer->>Target: Dispatch socket frame
        alt Socket Closes Abruptly / SIGSEGV
            Target-->>Fuzzer: Connection reset / Timeout
            Fuzzer->>Triage: Capture crashing payload & register dump
            Triage-->>Fuzzer: FuzzCrashReport (RIP/RSP snapshot)
        else Normal Response
            Target-->>Fuzzer: Protocol ACK / Error code
        end
    end
    Fuzzer-->>Tester: ProtocolFuzzResponse (Cases/sec, Crashes, Payloads)
    Tester->>Auditor: POST /api/v1/fuzz/binary-audit (sample_synthetic.elf)
    Auditor->>Auditor: Parse ELF/PE headers, measure section entropy, check NX/PIE
    Auditor-->>Tester: BinaryAuditResponse (Security Score & Mitigations)
```

---

### 3.5 Module 5: Malware Triage Engine
The static artifact triage engine evaluates benign synthetic binaries and test files: calculating overall and sliding-window Shannon entropy, extracting and categorizing strings and IOCs, matching detection signatures, and mapping findings to the MITRE ATT&CK framework.

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as Malware Analyst
    participant API as Triage Router
    participant Entropy as Shannon Entropy Calculator
    participant Extractor as String & IOC Extractor
    participant YARA as YARA Signature Engine
    participant MITRE as MITRE ATT&CK Mapper

    Analyst->>API: POST /api/v1/maltriage/analyze (filename / base64)
    API->>Entropy: Calculate overall & 256-byte sliding window entropy
    Entropy-->>API: Entropy profile (e.g. 5.42 bits/byte)
    API->>Extractor: Extract ASCII/Unicode strings >= 4 chars
    Extractor->>Extractor: Regex classify IPv4, URLs, APIs, Registry keys
    Extractor-->>API: Classified IOCs
    API->>YARA: Evaluate detection signatures against ruleset
    YARA-->>API: Matched signatures (e.g., EICAR, Packed Stub, Shellcode)
    API->>MITRE: Map matched behaviors to ATT&CK tactics & techniques
    MITRE-->>API: ATT&CK Matrix (T1059, T1027, etc.)
    API-->>Analyst: Comprehensive MalwareTriageResponse & Risk Score
```

---

### 3.6 Automated Purple-Team Scenario Orchestrator
The orchestrator coordinates a synchronized, multi-phase exercise spanning all five security engines:

```mermaid
sequenceDiagram
    autonumber
    actor Commander as Purple-Team Lead
    participant Orch as Scenario Orchestrator
    participant WS as WebSocket Hub
    participant Recon as Recon Engine
    participant Net as Net Arena
    participant Fuzz as Fuzzing Engine
    participant Exploit as Exploit Studio
    participant Triage as Triage Engine
    participant DB as SQLite DB

    Commander->>Orch: POST /api/v1/scenarios/run-purple-team
    Orch->>WS: Broadcast START: Purple-Team Scenario
    
    rect rgb(20, 30, 50)
        Note over Orch,Recon: Phase 1: Reconnaissance
        Orch->>Recon: Execute port probe on local range
        Recon-->>Orch: Discovered services
        Orch->>WS: Broadcast Step 1 SUCCESS
    end

    rect rgb(50, 20, 20)
        Note over Orch,Net: Phase 2: Adversary Emulation
        Orch->>Net: Trigger ARP cache poisoning
        Net-->>Orch: Poisoning established
        Orch->>WS: Broadcast Step 2 COMPROMISED
    end

    rect rgb(20, 50, 20)
        Note over Orch,Net: Phase 3: Active Defense
        Orch->>Net: Deploy Dynamic ARP Inspection & Pinning
        Net-->>Orch: Countermeasure verified, ARP restored
        Orch->>WS: Broadcast Step 3 MITIGATED
    end

    rect rgb(20, 30, 50)
        Note over Orch,Fuzz: Phase 4: Vulnerability Fuzzing
        Orch->>Fuzz: Fuzz MiniProto service
        Fuzz-->>Orch: Boundary crash captured
        Orch->>WS: Broadcast Step 4 VULNERABILITY FOUND
    end

    rect rgb(50, 20, 20)
        Note over Orch,Exploit: Phase 5: Exploit Simulation
        Orch->>Exploit: Simulate stack frame overflow & mitigations
        Exploit-->>Orch: Canary tripped, execution halted safely
        Orch->>WS: Broadcast Step 5 DEFENSE VERIFIED
    end

    rect rgb(20, 30, 50)
        Note over Orch,Triage: Phase 6: Artifact Triage
        Orch->>Triage: Triage synthetic artifact
        Triage-->>Orch: Shannon entropy & MITRE ATT&CK mapping
        Orch->>WS: Broadcast Step 6 COMPLETE
    end

    Orch->>DB: Save complete scenario run
    Orch-->>Commander: ScenarioRunResponse (Full summary & audit trail)
```

---

## 4. Database Architecture & Persistence Layer

AegisForge utilizes a high-throughput, non-blocking SQLite database operating in **Write-Ahead Logging (WAL)** mode.

### Schema Specifications

```sql
-- Scenario execution records
CREATE TABLE IF NOT EXISTS scenario_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario_id TEXT UNIQUE NOT NULL,
    scenario_title TEXT NOT NULL,
    status TEXT NOT NULL,
    total_steps INTEGER NOT NULL,
    steps_json TEXT NOT NULL,
    summary TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Network recon scan history
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    open_ports_count INTEGER NOT NULL,
    open_ports_json TEXT NOT NULL,
    scan_duration_ms REAL NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Protocol fuzzing campaign results
CREATE TABLE IF NOT EXISTS fuzz_campaigns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    total_cases INTEGER NOT NULL,
    crashes_count INTEGER NOT NULL,
    cases_per_second REAL NOT NULL,
    crashes_json TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Static binary triage records
CREATE TABLE IF NOT EXISTS triage_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    file_type TEXT NOT NULL,
    overall_entropy REAL NOT NULL,
    risk_score REAL NOT NULL,
    verdict TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Threading Model
- All SQLite queries are executed inside worker threads using `asyncio.to_thread` to ensure zero event-loop blocking.
- WAL mode (`PRAGMA journal_mode=WAL`) allows concurrent read transactions alongside background write operations.
