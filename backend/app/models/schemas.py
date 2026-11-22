from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, Field

# ==========================================
# Common & Health Models
# ==========================================
class HealthResponse(BaseModel):
    status: str
    version: str
    mode: str
    safety_guard_active: bool
    active_websockets: int
    timestamp: str

# ==========================================
# Module 1: Recon & CVD Schemas
# ==========================================
class PortScanRequest(BaseModel):
    target: str = Field(default="127.0.0.1", description="RFC1918 IP, CIDR, or local sandbox hostname")
    start_port: int = Field(default=20, ge=1, le=65535)
    end_port: int = Field(default=1024, ge=1, le=65535)
    scan_type: str = Field(default="TCP_SYN", description="TCP_SYN | TCP_CONNECT | BANNER_GRAB")

class DiscoveredPort(BaseModel):
    port: int
    protocol: str
    state: str
    service: str
    banner: Optional[str] = None
    cve_hints: List[str] = []

class ScopeVerificationRequest(BaseModel):
    target: str = Field(default="127.0.0.1", description="RFC1918 IP, CIDR, or local sandbox hostname")

class ScopeVerificationResponse(BaseModel):
    target: str
    is_authorized: bool
    scope_classification: str
    guardrail_note: str

class ScanResultResponse(BaseModel):
    target: str
    scan_duration_ms: float
    total_ports_probed: int
    open_ports_count: int
    open_ports: List[DiscoveredPort]
    scope_verified: bool
    mode: str

class CVSSCalculationRequest(BaseModel):
    vector_string: Optional[str] = None
    # Base Metric Group
    attack_vector: str = Field(default="NETWORK", description="NETWORK | ADJACENT | LOCAL | PHYSICAL")
    attack_complexity: str = Field(default="LOW", description="LOW | HIGH")
    privileges_required: str = Field(default="NONE", description="NONE | LOW | HIGH")
    user_interaction: str = Field(default="NONE", description="NONE | REQUIRED")
    scope: str = Field(default="UNCHANGED", description="UNCHANGED | CHANGED")
    confidentiality: str = Field(default="HIGH", description="NONE | LOW | HIGH")
    integrity: str = Field(default="HIGH", description="NONE | LOW | HIGH")
    availability: str = Field(default="HIGH", description="NONE | LOW | HIGH")

class CVSSCalculationResponse(BaseModel):
    base_score: float
    severity_rating: str
    vector_string: str
    metrics_breakdown: Dict[str, str]
    formula_components: Dict[str, float]

class CVDReportRequest(BaseModel):
    advisory_id: str = "AEGIS-2026-001"
    vulnerability_title: str
    affected_component: str
    target_environment: str = "AegisForge Virtual Lab"
    summary: str
    technical_description: str
    reproduction_steps: List[str]
    remediation_recommendations: List[str]
    cvss_vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    cvss_score: float = 9.8
    severity: str = "CRITICAL"
    reporter_contact: str = "security@aegisforge.internal"
    disclosure_timeline: Dict[str, str] = {}

class CVDReportResponse(BaseModel):
    advisory_id: str
    markdown_content: str
    html_content: str
    json_metadata: Dict[str, Any]
    generated_at: str

# ==========================================
# Module 2: Net Arena Schemas
# ==========================================
class ARPEntry(BaseModel):
    ip: str
    mac: str
    hostname: str
    state: str  # VALID | POISONED | PINNED
    last_seen: str

class NetNode(BaseModel):
    id: str
    label: str
    ip: str
    mac: str
    role: str  # GATEWAY | VICTIM | MONITOR_ATTACKER
    is_compromised: bool = False

class PacketEvent(BaseModel):
    id: str
    timestamp: str
    source_ip: str
    source_mac: str
    dest_ip: str
    dest_mac: str
    protocol: str  # ARP | DNS | HTTP | TCP | ICMP
    length: int
    info: str
    is_anomalous: bool = False

class NetArenaStatusResponse(BaseModel):
    nodes: List[NetNode]
    arp_table: List[ARPEntry]
    mitm_active: bool
    active_defense_enabled: bool
    total_packets_inspected: int
    spoofed_packets_detected: int
    defensive_actions_taken: List[str]

class ToggleMITMRequest(BaseModel):
    enable: bool
    target_ip: Optional[str] = "192.168.100.105"
    gateway_ip: Optional[str] = "192.168.100.1"

class ToggleActiveDefenseRequest(BaseModel):
    enable: bool
    enable_static_pinning: bool = True
    enable_gratuitous_arp_counter: bool = True

# ==========================================
# Module 3: Exploit Studio Schemas
# ==========================================
class ShellcodeAnalyzeRequest(BaseModel):
    hex_payload: str = Field(description="Hex string or escaped hex (e.g. 909031c0 or \\x90\\x90\\x31\\xc0)")
    architecture: str = Field(default="x86_64", description="x86 | x86_64")
    forbidden_chars: List[str] = Field(default=["00", "0a", "0d", "20"], description="Hex byte badchars to detect")

class DisassembledInstruction(BaseModel):
    address: str
    hex_bytes: str
    mnemonic: str
    operands: str
    is_badchar_present: bool

class ShellcodeAnalyzeResponse(BaseModel):
    total_bytes: int
    null_byte_count: int
    null_byte_percentage: float
    bad_chars_found: List[str]
    has_nop_sled: bool
    nop_sled_length: int
    heuristic_classification: str
    instructions: List[DisassembledInstruction]
    safety_verdict: str

class StackFrameSimulateRequest(BaseModel):
    buffer_allocated_bytes: int = Field(default=32, ge=8, le=256)
    input_payload_bytes: int = Field(default=48, ge=0, le=512)
    architecture: str = Field(default="x86_64", description="x86 | x86_64")
    enable_stack_canary: bool = True
    enable_nx_dep: bool = True
    enable_aslr: bool = True
    enable_pie: bool = True
    enable_relro: bool = True
    hex_payload: Optional[str] = Field(default=None, description="Optional raw hex string to trace through memory regions")

class StackMemoryRegion(BaseModel):
    name: str
    offset_start: int
    offset_end: int
    size_bytes: int
    description: str
    corrupted: bool
    current_content_hex: str
    role: str

class StackFrameSimulateResponse(BaseModel):
    architecture: str
    total_frame_size: int
    buffer_overflowed: bool
    bytes_overflowed: int
    canary_tripped: bool
    saved_fp_overwritten: bool
    return_address_overwritten: bool
    execution_verdict: str  # NORMAL_RETURN | CANARY_TERMINATION | SEGFAULT_NX | CONTROL_FLOW_HIJACK_BLOCKED | EXECUTION_HIJACKED
    mitigations_active: Dict[str, bool]
    stack_regions: List[StackMemoryRegion]
    explanation: str

# ==========================================
# Module 4: Fuzz & RE Schemas
# ==========================================
class ProtocolFuzzRequest(BaseModel):
    target_host: str = Field(default="127.0.0.1")
    target_port: int = Field(default=5000, ge=1, le=65535)
    max_cases: int = Field(default=100, ge=10, le=2000)
    mutation_strategies: List[str] = Field(
        default=["BIT_FLIP", "BOUNDARY_INTEGER", "FORMAT_STRING", "OVERSIZE_BUFFER", "DELIMITER_INJECTION"]
    )

class FuzzTestCase(BaseModel):
    case_id: int
    strategy: str
    payload_repr: str
    payload_length: int
    response_code: Optional[int] = None
    response_latency_ms: float
    status: str  # PASS | TIMEOUT | SERVER_ERROR | CRASH

class FuzzCrashReport(BaseModel):
    case_id: int
    strategy: str
    payload_hex: str
    payload_preview: str
    crash_reason: str
    registers_snapshot: Dict[str, str]
    reproduction_command: str

class ProtocolFuzzResponse(BaseModel):
    target: str
    total_cases_run: int
    cases_per_second: float
    crashes_detected: int
    unique_crashes: List[FuzzCrashReport]
    test_cases: List[FuzzTestCase]

class ACLAuditRequest(BaseModel):
    policy_json: Union[Dict[str, Any], str]

class ACLFinding(BaseModel):
    target_path: str
    principal: str
    permission: str
    risk_level: str  # HIGH | CRITICAL | MEDIUM
    description: str
    remediation_cmd: str

class ACLAuditResponse(BaseModel):
    total_rules_analyzed: int
    high_risk_findings: int
    findings: List[ACLFinding]
    compliance_summary: str

class BinaryAuditRequest(BaseModel):
    filename: str = Field(default="sample_synthetic.elf", description="Binary artifact name or path")
    content_raw_hex: Optional[str] = None
    file_bytes_base64: Optional[str] = None

class BinarySectionInfo(BaseModel):
    name: str
    virtual_address: str
    raw_size: int
    entropy: float
    flags: str

class BinaryMitigations(BaseModel):
    canary: bool
    nx_dep: bool
    pie_aslr: bool
    relro: str  # FULL | PARTIAL | NONE
    fortify: bool

class BinaryAuditResponse(BaseModel):
    filename: str
    binary_format: str  # ELF32 | ELF64 | PE32 | PE32+ (x64) | UNKNOWN
    architecture: str
    endianness: str
    entry_point: str
    mitigations: BinaryMitigations
    sections: List[BinarySectionInfo]
    security_score: float
    verdict: str
    findings: List[str]

# ==========================================
# Module 5: Malware Triage Schemas
# ==========================================
class TriageArtifactRequest(BaseModel):
    filename: str
    file_bytes_base64: Optional[str] = None
    content_raw_hex: Optional[str] = None

class EntropyBlock(BaseModel):
    offset: int
    size: int
    entropy: float

class YARAMatch(BaseModel):
    rule_id: str
    rule_name: str
    severity: str
    mitre_technique: str
    matched_strings: List[str]
    description: str

class ATTACKTechnique(BaseModel):
    id: str
    name: str
    tactic: str
    confidence: str
    evidence: str

class MalwareTriageResponse(BaseModel):
    filename: str
    file_size_bytes: int
    file_type: str
    hashes: Dict[str, str]  # md5, sha1, sha256
    overall_entropy: float
    is_high_entropy: bool
    entropy_sliding_window: List[EntropyBlock]
    extracted_strings_count: int
    classified_strings: Dict[str, List[str]]
    detected_iocs: Dict[str, List[str]]  # ips, urls, emails
    yara_matches: List[YARAMatch]
    mitre_attack_matrix: List[ATTACKTechnique]
    risk_score: float
    verdict: str

# ==========================================
# Purple-Team Scenario Orchestrator Schemas
# ==========================================
class ScenarioStep(BaseModel):
    step_id: int
    name: str
    module: str
    status: str  # PENDING | IN_PROGRESS | SUCCESS | MITIGATED
    details: str
    telemetry: Dict[str, Any] = {}

class ScenarioRunResponse(BaseModel):
    scenario_id: str
    scenario_title: str
    started_at: str
    completed_at: str
    total_steps: int
    status: str
    steps: List[ScenarioStep]
    final_report_summary: str
