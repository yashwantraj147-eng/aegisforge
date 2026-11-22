# AegisForge Architecture & Engineering Specification

## 1. System Overview
AegisForge is an integrated purple-team cyber range and defensive vulnerability analysis platform. It provides a synchronized environment where offensive discovery techniques and defensive mitigations are studied side-by-side within strictly bounded local sandbox environments.

```mermaid
flowchart TD
    subgraph Frontend["Cyber-Ops Dashboard (React + TypeScript + Vite)"]
        UI_Overview["Command Matrix & Telemetry"]
        UI_Recon["Recon & CVSS Calculator"]
        UI_Net["3-Node Network Arena"]
        UI_Exploit["Stack & Shellcode Studio"]
        UI_Fuzz["Protocol Fuzzer & ACL Auditor"]
        UI_Triage["Static Artifact Triage"]
    end

    subgraph Backend["FastAPI Telemetry Hub & Engines"]
        API_Gateway["FastAPI HTTP & WebSocket Router"]
        Safety_Guard["RFC1918 & Localhost SafetyGuard"]
        WS_Bus["Real-Time Telemetry Event Bus"]

        Eng_Recon["Recon & CVD Engine"]
        Eng_Net["Net Arena & Active Defense Daemon"]
        Eng_Exploit["Exploit Studio & Stack Simulator"]
        Eng_Fuzz["Protocol Fuzzer & ACL Parser"]
        Eng_Triage["Static Triage & Entropy Engine"]
    end

    subgraph Sandbox["Isolated Sandbox Environment"]
        Mock_Targets["MiniProto Stateful TCP Service (:5000)"]
        Virtual_Net["Isolated Bridge Subnet (192.168.100.0/24)"]
        Benign_Artifacts["Harmless Synthetic Test Files"]
    end

    Frontend <-->|REST & WebSocket| API_Gateway
    API_Gateway --> Safety_Guard
    Safety_Guard --> Eng_Recon
    Safety_Guard --> Eng_Fuzz
    API_Gateway --> WS_Bus
    WS_Bus -.->|Real-time Events| Frontend

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
    participant Guard as SafetyGuard
    participant Engine as Security Engine
    participant Bus as WebSocket Manager

    Operator->>UI: Trigger Scenario / Module Action
    UI->>API: POST /api/v1/... (Target IP / Parameters)
    API->>Guard: Validate Target Destination
    alt Public WAN IP / External Domain
        Guard-->>API: SafetyViolationException (Blocked)
        API-->>UI: 400 Bad Request (Safety Policy Enforced)
    else RFC1918 / Localhost Allowed
        Guard-->>API: Target Verified
        API->>Engine: Dispatch Task Execution
        Engine->>Bus: broadcast_event(module, severity, message)
        Bus-->>UI: Real-Time Telemetry Push
        Engine-->>API: Structured Result Schema
        API-->>UI: JSON Response
    end
```

---

## 3. Defense-in-Depth Mechanisms

### 3.1 Strict Safety Guardrails
The `SafetyGuard` module is positioned at the entrypoint of every network probe or socket invocation:
- Permits only RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), link-local addresses, and `.internal` / `.sandbox` hostnames.
- Rejects any external WAN IP or non-whitelisted domain immediately with structured feedback.

### 3.2 Dynamic ARP Inspection & Table Pinning
The Network Arena models an internal virtual bridge with three designated nodes:
1. **Gateway** (`192.168.100.1`)
2. **Victim** (`192.168.100.105`)
3. **Monitor/Attacker** (`192.168.100.200`)

When a rogue gratuitous ARP announcement is detected, the Active Defense Daemon flags the conflict, broadcasts an authoritative correction, and applies static ARP table pinning to neutralize redirection.

### 3.3 Stack Memory & Mitigation Mechanics
The Exploit Studio models standard x86 and x64 call frame structures:
- **Stack Canary (SSP)**: Detects buffer boundary overrun and aborts via `__stack_chk_fail` before the return address can be dereferenced.
- **NX / DEP**: Enforces write-xor-execute permissions, blocking code execution on stack pages.
- **ASLR & PIE**: Randomizes memory layout offsets to prevent fixed-address exploitation.
