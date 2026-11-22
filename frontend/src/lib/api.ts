export interface HealthData {
  status: string;
  version: string;
  mode: string;
  safety_guard_active: boolean;
  active_websockets: number;
  timestamp: string;
}

export interface DiscoveredPort {
  port: number;
  protocol: string;
  state: string;
  service: string;
  banner?: string;
  cve_hints: string[];
}

export interface ScanResult {
  target: string;
  scan_duration_ms: number;
  total_ports_probed: number;
  open_ports_count: number;
  open_ports: DiscoveredPort[];
  scope_verified: boolean;
  mode: string;
}

export interface CVSSResponse {
  base_score: number;
  severity_rating: string;
  vector_string: string;
  metrics_breakdown: Record<string, string>;
  formula_components: Record<string, number>;
}

export interface CVDResponse {
  advisory_id: string;
  markdown_content: string;
  html_content: string;
  json_metadata: Record<string, any>;
  generated_at: string;
}

export interface NetNode {
  id: string;
  label: string;
  ip: string;
  mac: string;
  role: string;
  is_compromised: boolean;
}

export interface ARPEntry {
  ip: string;
  mac: string;
  hostname: string;
  state: string;
  last_seen: string;
}

export interface PacketEvent {
  id: string;
  timestamp: string;
  source_ip: string;
  source_mac: string;
  dest_ip: string;
  dest_mac: string;
  protocol: string;
  length: number;
  info: string;
  is_anomalous: boolean;
}

export interface NetArenaStatus {
  nodes: NetNode[];
  arp_table: ARPEntry[];
  mitm_active: boolean;
  active_defense_enabled: boolean;
  total_packets_inspected: number;
  spoofed_packets_detected: number;
  defensive_actions_taken: string[];
}

export interface DisassembledInstruction {
  address: string;
  hex_bytes: string;
  mnemonic: string;
  operands: string;
  is_badchar_present: boolean;
}

export interface ShellcodeResponse {
  total_bytes: number;
  null_byte_count: number;
  null_byte_percentage: number;
  bad_chars_found: string[];
  has_nop_sled: boolean;
  nop_sled_length: number;
  heuristic_classification: string;
  instructions: DisassembledInstruction[];
  safety_verdict: string;
}

export interface StackRegion {
  name: string;
  offset_start: number;
  offset_end: number;
  size_bytes: number;
  description: string;
  corrupted: boolean;
  current_content_hex: string;
  role: string;
}

export interface StackSimulateResponse {
  architecture: string;
  total_frame_size: number;
  buffer_overflowed: boolean;
  bytes_overflowed: number;
  canary_tripped: boolean;
  saved_fp_overwritten: boolean;
  return_address_overwritten: boolean;
  execution_verdict: string;
  mitigations_active: Record<string, boolean>;
  stack_regions: StackRegion[];
  explanation: string;
}

export interface FuzzCase {
  case_id: number;
  strategy: string;
  payload_repr: string;
  payload_length: number;
  response_code?: number;
  response_latency_ms: number;
  status: string;
}

export interface FuzzCrash {
  case_id: number;
  strategy: string;
  payload_hex: string;
  payload_preview: string;
  crash_reason: string;
  registers_snapshot: Record<string, string>;
  reproduction_command: string;
}

export interface ProtocolFuzzResponse {
  target: string;
  total_cases_run: number;
  cases_per_second: number;
  crashes_detected: number;
  unique_crashes: FuzzCrash[];
  test_cases: FuzzCase[];
}

export interface ACLFinding {
  target_path: string;
  principal: string;
  permission: string;
  risk_level: string;
  description: string;
  remediation_cmd: string;
}

export interface ACLAuditResponse {
  total_rules_analyzed: number;
  high_risk_findings: number;
  findings: ACLFinding[];
  compliance_summary: string;
}

export interface YARAMatch {
  rule_id: string;
  rule_name: string;
  severity: string;
  mitre_technique: string;
  matched_strings: string[];
  description: string;
}

export interface ATTACKTechnique {
  id: string;
  name: string;
  tactic: string;
  confidence: string;
  evidence: string;
}

export interface MalwareTriageResponse {
  filename: string;
  file_size_bytes: number;
  file_type: string;
  hashes: Record<string, string>;
  overall_entropy: number;
  is_high_entropy: boolean;
  entropy_sliding_window: Array<{ offset: number; size: number; entropy: number }>;
  extracted_strings_count: number;
  classified_strings: Record<string, string[]>;
  detected_iocs: Record<string, string[]>;
  yara_matches: YARAMatch[];
  mitre_attack_matrix: ATTACKTechnique[];
  risk_score: number;
  verdict: string;
}

export interface ScenarioStep {
  step_id: number;
  name: string;
  module: string;
  status: string;
  details: string;
  telemetry: Record<string, any>;
}

export interface ScenarioRunResponse {
  scenario_id: string;
  scenario_title: string;
  started_at: string;
  completed_at: string;
  total_steps: number;
  status: string;
  steps: ScenarioStep[];
  final_report_summary: string;
}

const API_BASE = '/api/v1';

async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  });
  if (!res.ok) {
    let errorDetail = `Request failed with status ${res.status}`;
    try {
      const errJson = await res.json();
      errorDetail = errJson.message || errJson.detail || errorDetail;
    } catch (_) {}
    throw new Error(errorDetail);
  }
  return res.json();
}

export interface BinarySectionInfo {
  name: string;
  virtual_address: string;
  raw_size: number;
  entropy: number;
  flags: string;
}

export interface BinaryMitigations {
  canary: boolean;
  nx_dep: boolean;
  pie_aslr: boolean;
  relro: string;
  fortify: boolean;
}

export interface BinaryAuditResponse {
  filename: string;
  binary_format: string;
  architecture: string;
  endianness: string;
  entry_point: string;
  mitigations: BinaryMitigations;
  sections: BinarySectionInfo[];
  security_score: number;
  verdict: string;
  findings: string[];
}

export const api = {
  getHealth: () => fetchJson<HealthData>(`${API_BASE}/health`),
  
  // Recon & CVD
  verifyScope: (target: string) => fetchJson<any>(`${API_BASE}/recon/scope?target=${encodeURIComponent(target)}`, { method: 'POST' }),
  scanPorts: (target: string, start_port: number = 20, end_port: number = 1024) =>
    fetchJson<ScanResult>(`${API_BASE}/recon/scan`, {
      method: 'POST',
      body: JSON.stringify({ target, start_port, end_port }),
    }),
  calculateCvss: (params: Record<string, string>) =>
    fetchJson<CVSSResponse>(`${API_BASE}/recon/cvss`, {
      method: 'POST',
      body: JSON.stringify(params),
    }),
  generateCvdReport: (params: any) =>
    fetchJson<CVDResponse>(`${API_BASE}/recon/report`, {
      method: 'POST',
      body: JSON.stringify(params),
    }),

  // Net Arena
  getNetArenaStatus: () => fetchJson<NetArenaStatus>(`${API_BASE}/netarena/status`),
  toggleMitm: (enable: boolean) =>
    fetchJson<NetArenaStatus>(`${API_BASE}/netarena/mitm`, {
      method: 'POST',
      body: JSON.stringify({ enable }),
    }),
  toggleDefense: (enable: boolean, enable_static_pinning = true) =>
    fetchJson<NetArenaStatus>(`${API_BASE}/netarena/defense`, {
      method: 'POST',
      body: JSON.stringify({ enable, enable_static_pinning }),
    }),
  getPackets: (count = 5) => fetchJson<PacketEvent[]>(`${API_BASE}/netarena/packets?count=${count}`),

  // Exploit Studio
  analyzeShellcode: (hex_payload: string, architecture = 'x86_64', forbidden_chars = ['00', '0a', '0d', '20']) =>
    fetchJson<ShellcodeResponse>(`${API_BASE}/exploit/shellcode`, {
      method: 'POST',
      body: JSON.stringify({ hex_payload, architecture, forbidden_chars }),
    }),
  simulateStackFrame: (params: any) =>
    fetchJson<StackSimulateResponse>(`${API_BASE}/exploit/stack-simulate`, {
      method: 'POST',
      body: JSON.stringify(params),
    }),

  // Fuzz & RE
  fuzzProtocol: (target_host = '127.0.0.1', target_port = 5000, max_cases = 50) =>
    fetchJson<ProtocolFuzzResponse>(`${API_BASE}/fuzz/protocol`, {
      method: 'POST',
      body: JSON.stringify({ target_host, target_port, max_cases }),
    }),
  auditAcl: (policy_json: any) =>
    fetchJson<ACLAuditResponse>(`${API_BASE}/fuzz/acl-audit`, {
      method: 'POST',
      body: JSON.stringify({ policy_json }),
    }),
  auditBinary: (filename: string, content_raw_hex?: string, file_bytes_base64?: string) =>
    fetchJson<BinaryAuditResponse>(`${API_BASE}/fuzz/binary-audit`, {
      method: 'POST',
      body: JSON.stringify({ filename, content_raw_hex, file_bytes_base64 }),
    }),

  // Malware Triage
  triageArtifact: (filename: string, content_raw_hex?: string, file_bytes_base64?: string) =>
    fetchJson<MalwareTriageResponse>(`${API_BASE}/maltriage/analyze`, {
      method: 'POST',
      body: JSON.stringify({ filename, content_raw_hex, file_bytes_base64 }),
    }),
  listSamples: () => fetchJson<{ available_samples: any[] }>(`${API_BASE}/maltriage/samples`),

  // Purple-Team Scenarios
  runPurpleTeam: () => fetchJson<ScenarioRunResponse>(`${API_BASE}/scenarios/run-purple-team`, { method: 'POST' }),
  getScenarioHistory: () => fetchJson<{ runs: any[] }>(`${API_BASE}/scenarios/history`),
};
