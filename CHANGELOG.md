# Changelog

All notable changes to the **AegisForge** project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-11-22

### Added
- **Module 1: Recon & CVD Engine**:
  - Asynchronous TCP SYN and banner-grabbing network port scanner with CVE hint correlation.
  - Interactive CVSS v3.1 calculator supporting complete Base metric group calculation.
  - Coordinated Vulnerability Disclosure (CVD) advisory generator exporting to Markdown and HTML.
  - Target boundary validation via `SafetyGuard` ensuring RFC 1918 / localhost-only scoping.
- **Module 2: Network Arena**:
  - Simulated 3-node micro-network topology (`Gateway`, `Victim`, `Monitor/Attacker`).
  - Adversary ARP cache poisoning simulation.
  - Active Defense Daemon implementing Dynamic ARP Inspection (DAI), counter-ARP broadcasts, and static table pinning.
  - High-frequency packet ring buffer and packet inspector.
- **Module 3: Exploit Studio**:
  - x86 and x64 shellcode disassembler powered by Capstone.
  - Forbidden byte (bad-char) detector with NOP sled length calculation and heuristic classification.
  - Interactive CPU call stack memory simulator with selectable security flags: Stack Canary (SSP), NX/DEP, ASLR, and PIE.
- **Module 4: Fuzzing & Reverse Engineering**:
  - Stateful protocol mutation fuzzer supporting Bit Flip, Boundary Integer, Format String, Oversized Buffer, and Delimiter Injection strategies.
  - Crash triage engine capturing registers (RIP, RSP) and reproduction commands.
  - Windows Access Control List (ACL) JSON policy auditor identifying overly permissive access rules.
  - Static ELF32/64 and PE32/PE32+ binary mitigation analyzer (Canary, NX, PIE, RELRO).
- **Module 5: Malware Triage**:
  - Static binary triage engine with whole-file and 256-byte sliding-window Shannon entropy calculation.
  - ASCII and Unicode string extractor with automated regex classification for IPs, URLs, and dangerous APIs.
  - Built-in YARA-style signature rule engine (`default_yara_rules.json`).
  - Automated MITRE ATT&CK technique and tactic mapper.
- **Purple-Team Scenario Orchestrator**:
  - Automated 6-stage end-to-end attack and defense exercise executing across all five security engines.
  - Real-time WebSocket telemetry event streaming with severity levels (`INFO`, `WARNING`, `ERROR`, `CRITICAL`, `SUCCESS`).
- **Persistence & Operational Telemetry**:
  - Non-blocking SQLite persistence engine in WAL mode for scenario runs, port scans, fuzzing campaigns, and triage reports.
  - Prometheus `/metrics` exposition and structured JSON `/api/v1/metrics` summary endpoints.
  - Pure-Python sliding-window rate limiter (120 req/min per IP) with 429 response handling.
  - 30-second WebSocket heartbeat loop with automated stale client eviction.
- **Frontend Cyber-Ops Dashboard**:
  - Dark-mode React 19 + TypeScript + Vite + Tailwind CSS v4 dashboard.
  - Interactive SVG Network Topology Graph with real-time animated traffic arcs.
  - Client-side hash routing (`#overview`, `#recon`, `#netarena`, `#exploit`, `#fuzzre`, `#maltriage`).
  - Zero-dependency toast notification system (`Toast.tsx`).
  - Error boundary wrapper (`ErrorBoundary.tsx`) and skeleton loaders (`Skeleton.tsx`).
  - Mobile responsive navigation drawer.
- **CLI Companion (`aegisctl`)**:
  - Rich terminal application supporting `demo`, `recon`, `shellcode`, `fuzz`, `triage`, `report`, `health`, and `version`.
- **Sandbox & Testing Infrastructure**:
  - Benign test artifact generator (`sample_synthetic.elf`, `sample_synthetic.exe`, `sample_eicar_test.txt`, `sample_windows_acl.json`).
  - 49 integration and unit tests passing in pytest with `pytest-cov` code coverage reporting.
  - GitHub Actions CI workflow (`.github/workflows/ci.yml`).
- **Docker & Production Readiness**:
  - Multi-stage Docker builds for backend and frontend separating compilation from runtime footprint.
  - Dedicated production Nginx reverse proxy configuration (`frontend/nginx.conf`) with HTTP/1.1 WebSocket upgrade streaming, SPA fallback, gzip compression, and defensive HTTP headers (`CSP`, `X-Frame-Options`, `X-Content-Type-Options`).
  - Container security hardening with unprivileged system user `aegis` (`UID 10001`).
  - Container health checks (`HEALTHCHECK`) and automated dependency ordering (`condition: service_healthy`).
  - Resource consumption limits (`cpus`, `memory`, `pids`) preventing container starvation.
  - Strictly isolated sandbox bridge subnet (`192.168.100.0/24`, `internal: true`) barring external internet transit.
  - Automated Docker configuration validation test suite (`test_docker_compose_config.py`).
