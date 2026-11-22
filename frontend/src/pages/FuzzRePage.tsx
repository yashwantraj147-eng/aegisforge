import React, { useState, useEffect } from 'react';
import { api, ProtocolFuzzResponse, ACLAuditResponse, BinaryAuditResponse } from '../lib/api';
import { useToast } from '../components/Toast';
import {
  Bug,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Play,
  RotateCcw,
  Zap,
  Lock,
  FileCode,
  Terminal,
  Layers,
  Cpu,
  CheckCircle2,
  XCircle
} from 'lucide-react';

export const FuzzRePage: React.FC = () => {
  const toast = useToast();
  const [activeSubTab, setActiveSubTab] = useState<'fuzzer' | 'binary' | 'acl'>('fuzzer');

  // Fuzzing Campaign State
  const [targetHost, setTargetHost] = useState('127.0.0.1');
  const [targetPort, setTargetPort] = useState(5000);
  const [maxCases, setMaxCases] = useState(50);
  const [fuzzing, setFuzzing] = useState(false);
  const [fuzzResult, setFuzzResult] = useState<ProtocolFuzzResponse | null>(null);

  // Binary Audit State
  const [selectedBinary, setSelectedBinary] = useState('sample_synthetic.elf');
  const [binaryAuditResult, setBinaryAuditResult] = useState<BinaryAuditResponse | null>(null);
  const [binaryLoading, setBinaryLoading] = useState(false);

  // Windows ACL Policy State
  const [aclInput, setAclInput] = useState(`{
  "rules": [
    {
      "path": "C:\\\\Windows\\\\System32\\\\mock_service.exe",
      "principal": "Everyone",
      "permission": "FullControl",
      "type": "Allow"
    },
    {
      "path": "C:\\\\Program Files\\\\AegisLab\\\\config.ini",
      "principal": "BUILTIN\\\\Users",
      "permission": "WriteData",
      "type": "Allow"
    },
    {
      "path": "C:\\\\Windows\\\\safe.dll",
      "principal": "NT AUTHORITY\\\\SYSTEM",
      "permission": "FullControl",
      "type": "Allow"
    }
  ]
}`);
  const [aclResult, setAclResult] = useState<ACLAuditResponse | null>(null);

  const handleRunFuzzing = async () => {
    setFuzzing(true);
    try {
      const res = await api.fuzzProtocol(targetHost, targetPort, maxCases);
      setFuzzResult(res);
    } catch (e: any) {
      toast.error(`Fuzzing error: ${e.message}`);
    } finally {
      setFuzzing(false);
    }
  };

  const handleAuditBinary = async (filename: string) => {
    setSelectedBinary(filename);
    setBinaryLoading(true);
    try {
      const res = await api.auditBinary(filename);
      setBinaryAuditResult(res);
    } catch (e: any) {
      toast.error(`Binary audit error: ${e.message}`);
    } finally {
      setBinaryLoading(false);
    }
  };

  const handleAuditAcl = async () => {
    try {
      const parsed = JSON.parse(aclInput);
      const res = await api.auditAcl(parsed);
      setAclResult(res);
    } catch (e: any) {
      toast.error(`ACL Audit error: ${e.message}`);
    }
  };

  useEffect(() => {
    handleAuditBinary('sample_synthetic.elf');
  }, []);

  return (
    <div className="space-y-6">
      {/* Sub-Tabs Switcher */}
      <div className="flex items-center gap-2 p-1.5 bg-slate-900 border border-slate-800 rounded-xl w-fit">
        <button
          onClick={() => setActiveSubTab('fuzzer')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition cursor-pointer ${
            activeSubTab === 'fuzzer'
              ? 'bg-cyan-500 text-slate-950 font-bold shadow'
              : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
          }`}
        >
          <Bug className="w-4 h-4" />
          Stateful Protocol Fuzzer
        </button>
        <button
          onClick={() => setActiveSubTab('binary')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition cursor-pointer ${
            activeSubTab === 'binary'
              ? 'bg-cyan-500 text-slate-950 font-bold shadow'
              : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
          }`}
        >
          <FileCode className="w-4 h-4" />
          Static Binary (ELF / PE) Auditor
        </button>
        <button
          onClick={() => setActiveSubTab('acl')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition cursor-pointer ${
            activeSubTab === 'acl'
              ? 'bg-cyan-500 text-slate-950 font-bold shadow'
              : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
          }`}
        >
          <Lock className="w-4 h-4" />
          Windows ACL Policy Auditor
        </button>
      </div>

      {/* Tab 1: Stateful Protocol Fuzzer */}
      {activeSubTab === 'fuzzer' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
          <div className="flex items-center justify-between pb-4 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <Bug className="w-5 h-5 text-cyan-400" />
              <h3 className="font-bold text-white text-base">Stateful Protocol Mutation Fuzzer</h3>
            </div>
            <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800/60 px-2.5 py-0.5 rounded">
              Target: MiniProto / RFC1918 Lab Target
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <label className="text-xs font-semibold text-slate-400 block mb-1">Target Host</label>
              <input
                type="text"
                value={targetHost}
                onChange={(e) => setTargetHost(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="text-xs font-semibold text-slate-400 block mb-1">Port</label>
              <input
                type="number"
                value={targetPort}
                onChange={(e) => setTargetPort(parseInt(e.target.value))}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="text-xs font-semibold text-slate-400 block mb-1">Cases to Generate</label>
              <input
                type="number"
                value={maxCases}
                onChange={(e) => setMaxCases(parseInt(e.target.value))}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div className="flex items-end">
              <button
                onClick={handleRunFuzzing}
                disabled={fuzzing}
                className="w-full flex items-center justify-center gap-2 py-2 px-4 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition cursor-pointer disabled:opacity-50"
              >
                <Zap className="w-4 h-4 fill-slate-950" />
                {fuzzing ? 'Fuzzing Service...' : 'Launch Fuzzing'}
              </button>
            </div>
          </div>

          {fuzzResult && (
            <div className="space-y-4 pt-3 border-t border-slate-800">
              {/* KPI Badges */}
              <div className="grid grid-cols-3 gap-4">
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-center">
                  <div className="text-[11px] text-slate-400 font-mono">Total Cases Run</div>
                  <div className="text-xl font-bold text-white mt-1">{fuzzResult.total_cases_run}</div>
                </div>
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-center">
                  <div className="text-[11px] text-slate-400 font-mono">Execution Rate</div>
                  <div className="text-xl font-bold text-cyan-400 mt-1">{fuzzResult.cases_per_second} <span className="text-xs font-normal">cps</span></div>
                </div>
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-center">
                  <div className="text-[11px] text-slate-400 font-mono">Crashes Detected</div>
                  <div className={`text-xl font-bold mt-1 ${fuzzResult.crashes_detected > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                    {fuzzResult.crashes_detected}
                  </div>
                </div>
              </div>

              {/* Isolated Crashes Inspector */}
              {fuzzResult.unique_crashes.length > 0 && (
                <div className="p-4 bg-red-950/20 border border-red-800/80 rounded-xl space-y-3">
                  <div className="flex items-center gap-2 text-red-400 font-bold text-xs uppercase tracking-wider">
                    <AlertTriangle className="w-4 h-4" />
                    Isolated Crash Reproducers ({fuzzResult.unique_crashes.length} Unique Signature)
                  </div>
                  {fuzzResult.unique_crashes.map((crash, idx) => (
                    <div key={idx} className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-2 font-mono text-xs">
                      <div className="flex items-center justify-between">
                        <span className="text-yellow-400 font-bold">Strategy: {crash.strategy}</span>
                        <span className="text-red-400">{crash.crash_reason}</span>
                      </div>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-[11px] bg-slate-900 p-2 rounded border border-slate-800">
                        {Object.entries(crash.registers_snapshot).map(([reg, val]) => (
                          <div key={reg}>
                            <span className="text-slate-500">{reg}:</span> <span className="text-cyan-400 font-semibold">{val}</span>
                          </div>
                        ))}
                      </div>
                      <div className="text-[10px] text-slate-400">
                        <span className="text-slate-500">Reproduction:</span> <code className="text-emerald-400 break-all">{crash.reproduction_command}</code>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Recent Cases Stream */}
              <div className="overflow-x-auto rounded-lg border border-slate-800 max-h-[220px]">
                <table className="w-full text-xs font-mono text-left">
                  <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 sticky top-0">
                    <tr>
                      <th className="py-2 px-3">Case ID</th>
                      <th className="py-2 px-3">Strategy</th>
                      <th className="py-2 px-3">Payload Repr</th>
                      <th className="py-2 px-3">Len</th>
                      <th className="py-2 px-3">Latency</th>
                      <th className="py-2 px-3">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 bg-slate-900/40">
                    {fuzzResult.test_cases.slice(0, 20).map((tc) => (
                      <tr key={tc.case_id} className={tc.status === 'CRASH' ? 'bg-red-950/30' : 'hover:bg-slate-800/40'}>
                        <td className="py-1.5 px-3 text-slate-500">#{tc.case_id}</td>
                        <td className="py-1.5 px-3 text-cyan-400">{tc.strategy}</td>
                        <td className="py-1.5 px-3 text-slate-300 font-mono truncate max-w-[200px]">{tc.payload_repr}</td>
                        <td className="py-1.5 px-3 text-slate-400">{tc.payload_length}</td>
                        <td className="py-1.5 px-3 text-slate-400">{tc.response_latency_ms} ms</td>
                        <td className="py-1.5 px-3">
                          <span
                            className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                              tc.status === 'CRASH'
                                ? 'bg-red-950 text-red-400 border border-red-800'
                                : 'bg-emerald-950 text-emerald-400'
                            }`}
                          >
                            {tc.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Static Binary (ELF / PE) Header Auditor */}
      {activeSubTab === 'binary' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
          <div className="flex items-center justify-between pb-4 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <FileCode className="w-5 h-5 text-cyan-400" />
              <h3 className="font-bold text-white text-base">Static Binary (ELF / PE) Security Auditor</h3>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => handleAuditBinary('sample_synthetic.elf')}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer ${
                  selectedBinary === 'sample_synthetic.elf'
                    ? 'bg-cyan-500 text-slate-950 font-bold'
                    : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                }`}
              >
                Audit ELF Sample
              </button>
              <button
                onClick={() => handleAuditBinary('sample_synthetic.exe')}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer ${
                  selectedBinary === 'sample_synthetic.exe'
                    ? 'bg-cyan-500 text-slate-950 font-bold'
                    : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                }`}
              >
                Audit PE Sample
              </button>
            </div>
          </div>

          {binaryAuditResult && (
            <div className="space-y-4">
              {/* Header Info Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                  <div className="text-[11px] text-slate-400">Binary Format</div>
                  <div className="text-base font-bold text-white mt-0.5">{binaryAuditResult.binary_format}</div>
                  <div className="text-[10px] text-slate-500 font-mono">{binaryAuditResult.endianness}</div>
                </div>
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                  <div className="text-[11px] text-slate-400">Target Architecture</div>
                  <div className="text-base font-bold text-cyan-400 mt-0.5">{binaryAuditResult.architecture}</div>
                  <div className="text-[10px] text-slate-500 font-mono">Entry: {binaryAuditResult.entry_point}</div>
                </div>
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                  <div className="text-[11px] text-slate-400">Hardening Score</div>
                  <div className="text-base font-bold text-amber-400 mt-0.5">{binaryAuditResult.security_score} / 10.0</div>
                  <div className="text-[10px] text-slate-400">{binaryAuditResult.verdict}</div>
                </div>
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                  <div className="text-[11px] text-slate-400">Artifact Target</div>
                  <div className="text-base font-bold text-white truncate mt-0.5">{binaryAuditResult.filename}</div>
                  <div className="text-[10px] text-emerald-400">Verified Sandbox Sample</div>
                </div>
              </div>

              {/* Mitigation Badges */}
              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                  Compile-Time Security Mitigations Detected
                </div>
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3 pt-1">
                  <div className={`p-2.5 rounded-lg border flex items-center justify-between text-xs ${
                    binaryAuditResult.mitigations.nx_dep
                      ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                      : 'bg-red-950/40 border-red-800 text-red-300'
                  }`}>
                    <span>NX / DEP</span>
                    <span className="font-bold">{binaryAuditResult.mitigations.nx_dep ? 'ENABLED' : 'DISABLED'}</span>
                  </div>
                  <div className={`p-2.5 rounded-lg border flex items-center justify-between text-xs ${
                    binaryAuditResult.mitigations.canary
                      ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                      : 'bg-red-950/40 border-red-800 text-red-300'
                  }`}>
                    <span>Stack Canary</span>
                    <span className="font-bold">{binaryAuditResult.mitigations.canary ? 'PRESENT' : 'MISSING'}</span>
                  </div>
                  <div className={`p-2.5 rounded-lg border flex items-center justify-between text-xs ${
                    binaryAuditResult.mitigations.pie_aslr
                      ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                      : 'bg-red-950/40 border-red-800 text-red-300'
                  }`}>
                    <span>PIE / ASLR</span>
                    <span className="font-bold">{binaryAuditResult.mitigations.pie_aslr ? 'ENABLED' : 'DISABLED'}</span>
                  </div>
                  <div className={`p-2.5 rounded-lg border flex items-center justify-between text-xs ${
                    binaryAuditResult.mitigations.relro === 'FULL'
                      ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                      : binaryAuditResult.mitigations.relro === 'PARTIAL'
                      ? 'bg-amber-950/40 border-amber-800 text-amber-300'
                      : 'bg-red-950/40 border-red-800 text-red-300'
                  }`}>
                    <span>RELRO</span>
                    <span className="font-bold">{binaryAuditResult.mitigations.relro}</span>
                  </div>
                  <div className={`p-2.5 rounded-lg border flex items-center justify-between text-xs ${
                    binaryAuditResult.mitigations.fortify
                      ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                      : 'bg-slate-900 border-slate-800 text-slate-400'
                  }`}>
                    <span>Fortify / CFG</span>
                    <span className="font-bold">{binaryAuditResult.mitigations.fortify ? 'ACTIVE' : 'NO'}</span>
                  </div>
                </div>
              </div>

              {/* Findings List */}
              {binaryAuditResult.findings.length > 0 && (
                <div className="p-4 bg-red-950/20 border border-red-800/80 rounded-xl space-y-2">
                  <div className="flex items-center gap-2 text-red-400 font-bold text-xs uppercase tracking-wider">
                    <AlertTriangle className="w-4 h-4" />
                    Security Hardening Recommendations ({binaryAuditResult.findings.length})
                  </div>
                  <div className="space-y-1.5 text-xs text-red-300">
                    {binaryAuditResult.findings.map((finding, idx) => (
                      <div key={idx} className="flex items-start gap-2">
                        <span className="text-red-500 font-bold">&bull;</span>
                        <span>{finding}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Section Table */}
              <div className="space-y-2">
                <div className="text-xs font-semibold text-slate-300">Binary Section Breakdown</div>
                <div className="overflow-x-auto rounded-lg border border-slate-800 max-h-[180px]">
                  <table className="w-full text-xs font-mono text-left">
                    <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 sticky top-0">
                      <tr>
                        <th className="py-2 px-3">Section Name</th>
                        <th className="py-2 px-3">Virtual Address</th>
                        <th className="py-2 px-3">Raw Size</th>
                        <th className="py-2 px-3">Entropy</th>
                        <th className="py-2 px-3">Flags</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 bg-slate-900/40">
                      {binaryAuditResult.sections.map((sec, idx) => (
                        <tr key={idx} className="hover:bg-slate-800/40">
                          <td className="py-1.5 px-3 text-cyan-400 font-bold">{sec.name}</td>
                          <td className="py-1.5 px-3 text-slate-300">{sec.virtual_address}</td>
                          <td className="py-1.5 px-3 text-slate-400">{sec.raw_size} B</td>
                          <td className="py-1.5 px-3 text-slate-300">{sec.entropy}</td>
                          <td className="py-1.5 px-3 text-slate-400">{sec.flags}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Windows ACL Policy Auditor */}
      {activeSubTab === 'acl' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
          <div className="flex items-center justify-between pb-4 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <Lock className="w-5 h-5 text-cyan-400" />
              <h3 className="font-bold text-white text-base">Windows Security Descriptor & ACL Policy Auditor</h3>
            </div>
            <button
              onClick={handleAuditAcl}
              className="px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition cursor-pointer"
            >
              Audit ACL Snapshot
            </button>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div>
              <label className="text-xs font-semibold text-slate-400 block mb-1">
                ACL Policy JSON Snapshot (Active Directory / Host Hardening)
              </label>
              <textarea
                rows={8}
                value={aclInput}
                onChange={(e) => setAclInput(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="space-y-3">
              <div className="text-xs font-semibold text-slate-400">Audit Findings & Remediation</div>
              {aclResult ? (
                <div className="space-y-3 font-mono text-xs max-h-[220px] overflow-y-auto">
                  <div className="text-xs text-slate-300 font-sans">{aclResult.compliance_summary}</div>
                  {aclResult.findings.map((f, idx) => (
                    <div key={idx} className="p-3 bg-slate-950 rounded-lg border border-red-800/80 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-red-400">{f.target_path}</span>
                        <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-red-950 text-red-400 border border-red-800">
                          {f.risk_level}
                        </span>
                      </div>
                      <div className="text-slate-400 text-[11px] font-sans">{f.description}</div>
                      <div className="p-1.5 bg-slate-900 rounded border border-slate-800 text-[10px] text-emerald-400">
                        <code>{f.remediation_cmd}</code>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="h-full flex items-center justify-center p-8 bg-slate-950 rounded-lg border border-slate-800 text-slate-500 text-xs text-center">
                  Click "Audit ACL Snapshot" to evaluate security descriptors.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
