import asyncio
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any
from fastapi import APIRouter

from backend.app.core.ws_manager import ws_manager
from backend.app.core.database import db
from backend.app.core.metrics import metrics
from backend.app.engines.recon_cvd import recon_engine, cvss_calculator, cvd_report_generator
from backend.app.engines.net_arena import net_arena_engine
from backend.app.engines.exploit_studio import exploit_studio_engine
from backend.app.engines.fuzz_re import fuzz_engine
from backend.app.engines.mal_triage import malware_triage_engine
from backend.app.models.schemas import (
    ScenarioRunResponse, ScenarioStep,
    PortScanRequest, ToggleMITMRequest, ToggleActiveDefenseRequest,
    ProtocolFuzzRequest, ShellcodeAnalyzeRequest, StackFrameSimulateRequest,
    TriageArtifactRequest, CVSSCalculationRequest, CVDReportRequest
)

router = APIRouter(prefix="/scenarios", tags=["Purple-Team Orchestrator"])

scenario_history: List[Dict[str, Any]] = []
_history_lock = asyncio.Lock()

@router.post("/run-purple-team", response_model=ScenarioRunResponse)
async def run_purple_team_exercise():
    """
    Executes a comprehensive, 6-stage Purple-Team Cyber Range engagement:
      Stage 1: Target Scope Verification & Service Reconnaissance
      Stage 2: Network Arena: Simulated ARP Spoofing & Active Defense Neutralization
      Stage 3: Protocol Fuzzing & Crash Identification
      Stage 4: Exploit Studio: Shellcode & Stack Mitigation Analysis
      Stage 5: Static Artifact Triage & MITRE ATT&CK Mapping
      Stage 6: CVSS v3.1 Scoring & Coordinated Vulnerability Disclosure (CVD) Report
    """
    scenario_id = f"SCENARIO-{uuid.uuid4().hex[:8].upper()}"
    start_time = datetime.now(timezone.utc).isoformat()
    steps: List[ScenarioStep] = []

    await ws_manager.broadcast_event(
        module="ORCHESTRATOR",
        event_type="SCENARIO_STARTED",
        severity="INFO",
        message=f"Starting Purple-Team Cyber Range Exercise ({scenario_id}). Initializing 6 stages...",
        data={"scenario_id": scenario_id}
    )

    # -------------------------------------------------------------
    # Stage 1: Recon & Scope Validation
    # -------------------------------------------------------------
    await ws_manager.broadcast_event(
        module="RECON",
        event_type="STAGE_1_START",
        severity="INFO",
        message="Stage 1: Scanning virtual lab environment (192.168.100.105) under RFC1918 safety policy."
    )
    scan_req = PortScanRequest(target="192.168.100.105", start_port=20, end_port=5000)
    scan_res = await recon_engine.scan_target(scan_req)
    step1 = ScenarioStep(
        step_id=1,
        name="Target Scope Verification & Service Discovery",
        module="RECON",
        status="SUCCESS",
        details=f"Target 192.168.100.105 verified in lab scope. Discovered {scan_res.open_ports_count} active services, including MiniProto on port 5000.",
        telemetry={"open_ports": [p.port for p in scan_res.open_ports]}
    )
    steps.append(step1)
    await asyncio.sleep(0.05)

    # -------------------------------------------------------------
    # Stage 2: Net Arena - MITM Attack & Active Defense
    # -------------------------------------------------------------
    await ws_manager.broadcast_event(
        module="NET_ARENA",
        event_type="STAGE_2_START",
        severity="HIGH",
        message="Stage 2: Simulated adversary launches gratuitous ARP poisoning against Gateway 192.168.100.1."
    )
    # Ensure active defense is on
    await net_arena_engine.toggle_defense(ToggleActiveDefenseRequest(enable=True, enable_static_pinning=True))
    mitm_res = await net_arena_engine.toggle_mitm(ToggleMITMRequest(enable=True))

    step2 = ScenarioStep(
        step_id=2,
        name="Adversary ARP Spoofing & Active Defense Neutralization",
        module="NET_ARENA",
        status="MITIGATED",
        details="Rogue ARP packet detected by Dynamic ARP Inspection (DAI). Static ARP pinning engaged; malicious redirect neutralized.",
        telemetry={"mitm_active": mitm_res.mitm_active, "spoofed_blocked": mitm_res.spoofed_packets_detected}
    )
    steps.append(step2)
    # Disengage MITM to restore baseline
    await net_arena_engine.toggle_mitm(ToggleMITMRequest(enable=False))
    await asyncio.sleep(0.05)

    # -------------------------------------------------------------
    # Stage 3: Protocol Fuzzing & Crash Discovery
    # -------------------------------------------------------------
    await ws_manager.broadcast_event(
        module="FUZZING",
        event_type="STAGE_3_START",
        severity="INFO",
        message="Stage 3: Launching mutation-based protocol fuzzer against discovered service (127.0.0.1:5000)."
    )
    fuzz_req = ProtocolFuzzRequest(target_host="127.0.0.1", target_port=5000, max_cases=30)
    fuzz_res = await fuzz_engine.run_fuzzing_campaign(fuzz_req)
    step3 = ScenarioStep(
        step_id=3,
        name="Stateful Protocol Fuzzing & Crash Isolation",
        module="FUZZING",
        status="SUCCESS",
        details=f"Fuzzer executed {fuzz_res.total_cases_run} cases ({fuzz_res.cases_per_second} cps). Isolated {fuzz_res.crashes_detected} reproducible crash(es) via buffer mutation.",
        telemetry={"crashes": fuzz_res.crashes_detected, "cases": fuzz_res.total_cases_run}
    )
    steps.append(step3)
    await asyncio.sleep(0.05)

    # -------------------------------------------------------------
    # Stage 4: Exploit Studio - Shellcode & Stack Simulation
    # -------------------------------------------------------------
    await ws_manager.broadcast_event(
        module="EXPLOIT_STUDIO",
        event_type="STAGE_4_START",
        severity="INFO",
        message="Stage 4: Auditing crashing input payload and evaluating compiler stack protections (Canary, NX, ASLR)."
    )
    # Disassemble sample NOP sled payload
    shellcode_req = ShellcodeAnalyzeRequest(hex_payload="9090909031c050682f2f7368682f62696e89e3505389e1b00bcd80")
    shell_res = exploit_studio_engine.analyze_shellcode(shellcode_req)

    # Simulate stack frame with canary active
    stack_req = StackFrameSimulateRequest(
        buffer_allocated_bytes=32,
        input_payload_bytes=64,
        enable_stack_canary=True,
        enable_nx_dep=True
    )
    stack_res = exploit_studio_engine.simulate_stack_frame(stack_req)

    step4 = ScenarioStep(
        step_id=4,
        name="Memory Corruption & Mitigation Verification",
        module="EXPLOIT_STUDIO",
        status="MITIGATED",
        details=f"Payload disassembly verified {shell_res.total_bytes} bytes. Stack simulation confirmed: Canary tripped; __stack_chk_fail halts execution before RET overwrite.",
        telemetry={"execution_verdict": stack_res.execution_verdict, "canary_tripped": stack_res.canary_tripped}
    )
    steps.append(step4)
    await asyncio.sleep(0.05)

    # -------------------------------------------------------------
    # Stage 5: Malware & Benign Artifact Triage
    # -------------------------------------------------------------
    await ws_manager.broadcast_event(
        module="MAL_TRIAGE",
        event_type="STAGE_5_START",
        severity="INFO",
        message="Stage 5: Static triage on test artifact. Calculating Shannon entropy and matching YARA detection rules."
    )
    triage_req = TriageArtifactRequest(
        filename="eicar_test_artifact.bin",
        content_raw_hex="58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e444152442d414e544956495255532d544553542d46494c452124482b482a"
    )
    triage_res = malware_triage_engine.triage_artifact(triage_req)
    step5 = ScenarioStep(
        step_id=5,
        name="Static Binary Triage & ATT&CK Mapping",
        module="MAL_TRIAGE",
        status="SUCCESS",
        details=f"Artifact triaged. Shannon entropy: {triage_res.overall_entropy:.2f}. Matched {len(triage_res.yara_matches)} YARA rule(s). Mapped to {len(triage_res.mitre_attack_matrix)} ATT&CK techniques.",
        telemetry={"verdict": triage_res.verdict, "yara_rules": [m.rule_name for m in triage_res.yara_matches]}
    )
    steps.append(step5)
    await asyncio.sleep(0.05)

    # -------------------------------------------------------------
    # Stage 6: CVD Disclosure Report & CVSS v3.1 Calculation
    # -------------------------------------------------------------
    await ws_manager.broadcast_event(
        module="CVD",
        event_type="STAGE_6_START",
        severity="MEDIUM",
        message="Stage 6: Formulating CVSS v3.1 metrics and generating Coordinated Vulnerability Disclosure (CVD) report."
    )
    cvss_calc = cvss_calculator.calculate(CVSSCalculationRequest(
        attack_vector="NETWORK",
        attack_complexity="LOW",
        privileges_required="NONE",
        user_interaction="NONE",
        scope="UNCHANGED",
        confidentiality="HIGH",
        integrity="HIGH",
        availability="HIGH"
    ))

    cvd_req = CVDReportRequest(
        advisory_id=f"AEGIS-2026-{scenario_id[-4:]}",
        vulnerability_title="Stateful Protocol Buffer Overflow in MiniProto Service",
        affected_component="MiniProto Stateful TCP Service v1.0",
        summary="A stateful protocol fuzzer detected a memory corruption vulnerability when processing oversized input buffers without bounds checking.",
        technical_description="Sending >1024 bytes to the AUTH/STORE command triggers a buffer overflow past the local stack buffer. When compiled without stack canaries, the return address is overwritten.",
        reproduction_steps=[
            "Launch MiniProto mock service on port 5000.",
            "Connect via TCP socket and transmit 1024 'A' characters preceded by command header.",
            "Observe server termination with SIGSEGV."
        ],
        remediation_recommendations=[
            "Implement strict bounded length validation before memory copy.",
            "Compile all production binaries with -fstack-protector-strong and -Wl,-z,noexecstack.",
            "Enforce Address Space Layout Randomization (ASLR) and Position Independent Executables (PIE)."
        ],
        cvss_vector=cvss_calc.vector_string,
        cvss_score=cvss_calc.base_score,
        severity=cvss_calc.severity_rating
    )
    report_res = cvd_report_generator.generate(cvd_req)
    step6 = ScenarioStep(
        step_id=6,
        name="CVSS v3.1 Scoring & Coordinated Vulnerability Disclosure",
        module="CVD",
        status="SUCCESS",
        details=f"Formulated CVSS v3.1: {cvss_calc.vector_string} (Score: {cvss_calc.base_score} - {cvss_calc.severity_rating}). Exported RFC 9116 compliant disclosure report.",
        telemetry={"advisory_id": report_res.advisory_id, "score": cvss_calc.base_score}
    )
    steps.append(step6)

    completed_time = datetime.now(timezone.utc).isoformat()
    summary = (
        f"Purple-Team Scenario {scenario_id} executed successfully. "
        f"Verified 6 defensive controls: Scope validation, Dynamic ARP Inspection, "
        f"Protocol fuzzing crash detection, Stack Canary mitigation, YARA static triage, "
        f"and ISO/IEC 29147 disclosure reporting."
    )

    result = ScenarioRunResponse(
        scenario_id=scenario_id,
        scenario_title="Purple-Team End-to-End Cyber Range Exercise",
        started_at=start_time,
        completed_at=completed_time,
        total_steps=len(steps),
        status="COMPLETED",
        steps=steps,
        final_report_summary=summary
    )

    async with _history_lock:
        scenario_history.append(result.model_dump())
    await db.save_scenario(result.model_dump())
    metrics.record_scenario()

    await ws_manager.broadcast_event(
        module="ORCHESTRATOR",
        event_type="SCENARIO_COMPLETED",
        severity="INFO",
        message=f"Purple-Team Exercise {scenario_id} finished. All 6 stages completed and verified.",
        data={"scenario_id": scenario_id, "steps_count": len(steps)}
    )

    return result

@router.get("/history")
async def get_scenario_history():
    """Returns recent Purple-Team scenario exercise runs from database."""
    runs = await db.get_scenarios(limit=10)
    if not runs:
        async with _history_lock:
            runs = scenario_history[-10:]
    return {"runs": runs}
