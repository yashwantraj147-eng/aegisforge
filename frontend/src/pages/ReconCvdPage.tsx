import React, { useState } from 'react';
import { api, ScanResult, CVSSResponse, CVDResponse } from '../lib/api';
import { useToast } from '../components/Toast';
import {
  Radar,
  ShieldCheck,
  ShieldAlert,
  Calculator,
  FileText,
  Play,
  Copy,
  Check,
  Download,
  Printer,
  AlertTriangle
} from 'lucide-react';

export const ReconCvdPage: React.FC = () => {
  const toast = useToast();
  // Recon State
  const [target, setTarget] = useState('192.168.100.105');
  const [startPort, setStartPort] = useState(20);
  const [endPort, setEndPort] = useState(5000);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  // CVSS State
  const [cvssMetrics, setCvssMetrics] = useState({
    attack_vector: 'NETWORK',
    attack_complexity: 'LOW',
    privileges_required: 'NONE',
    user_interaction: 'NONE',
    scope: 'UNCHANGED',
    confidentiality: 'HIGH',
    integrity: 'HIGH',
    availability: 'HIGH',
  });
  const [cvssResult, setCvssResult] = useState<CVSSResponse | null>(null);

  // CVD Report State
  const [advisoryId, setAdvisoryId] = useState('AEGIS-2026-001');
  const [vulnTitle, setVulnTitle] = useState('Stateful Protocol Buffer Overflow in MiniProto');
  const [affectedComp, setAffectedComp] = useState('MiniProto Stateful TCP Service v1.0');
  const [summary, setSummary] = useState(
    'A memory corruption vulnerability allows denial-of-service or potential execution via oversized buffer transmission.'
  );
  const [cvdResult, setCvdResult] = useState<CVDResponse | null>(null);
  const [copiedMd, setCopiedMd] = useState(false);

  const handleScan = async () => {
    setScanning(true);
    setScanError(null);
    try {
      const res = await api.scanPorts(target, startPort, endPort);
      setScanResult(res);
    } catch (e: any) {
      setScanError(e.message);
    } finally {
      setScanning(false);
    }
  };

  const handleCalculateCvss = async () => {
    try {
      const res = await api.calculateCvss(cvssMetrics);
      setCvssResult(res);
    } catch (e: any) {
      toast.error(`CVSS Calc error: ${e.message}`);
    }
  };

  const handleGenerateCvd = async () => {
    try {
      const res = await api.generateCvdReport({
        advisory_id: advisoryId,
        vulnerability_title: vulnTitle,
        affected_component: affectedComp,
        summary: summary,
        technical_description:
          'Input lengths exceeding 1024 bytes trigger an unbounded memory copy in the local stack buffer.',
        reproduction_steps: [
          'Step 1: Connect to 192.168.100.105:5000 via TCP socket.',
          'Step 2: Transmit 1024 bytes payload.',
          'Step 3: Monitor daemon process crash with SIGSEGV.',
        ],
        remediation_recommendations: [
          'Enforce strict input length checking prior to memory copy.',
          'Compile target binaries with -fstack-protector-strong and -Wl,-z,noexecstack.',
        ],
        cvss_vector: cvssResult?.vector_string || 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        cvss_score: cvssResult?.base_score || 9.8,
        severity: cvssResult?.severity_rating || 'CRITICAL',
      });
      setCvdResult(res);
      toast.success('Coordinated Vulnerability Disclosure (CVD) advisory generated!');
    } catch (e: any) {
      toast.error(`CVD Report error: ${e.message}`);
    }
  };

  const handleCopyMd = () => {
    if (!cvdResult) return;
    navigator.clipboard.writeText(cvdResult.markdown_content);
    setCopiedMd(true);
    toast.info('Advisory markdown copied to clipboard');
    setTimeout(() => setCopiedMd(false), 2000);
  };

  const handleDownloadMd = () => {
    if (!cvdResult) return;
    const blob = new Blob([cvdResult.markdown_content], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${advisoryId || 'advisory'}.md`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success('Advisory downloaded as Markdown file');
  };

  const handlePrintAdvisory = () => {
    if (!cvdResult) return;
    const printWindow = window.open('', '_blank');
    if (!printWindow) return;
    printWindow.document.write(`
      <html>
        <head>
          <title>${advisoryId} - Security Advisory</title>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 40px; color: #111; line-height: 1.6; }
            pre { background: #f4f4f4; padding: 12px; border-radius: 6px; overflow-x: auto; font-family: monospace; }
            h1, h2, h3 { color: #0f172a; }
            hr { border: none; border-top: 1px solid #e2e8f0; margin: 24px 0; }
          </style>
        </head>
        <body>
          <div style="font-family: monospace; white-space: pre-wrap;">${cvdResult.markdown_content}</div>
        </body>
      </html>
    `);
    printWindow.document.close();
    printWindow.focus();
    setTimeout(() => {
      printWindow.print();
    }, 250);
  };

  return (
    <div className="space-y-6">
      {/* Scope Scanner Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Radar className="w-5 h-5 text-cyan-400" />
            <h3 className="font-bold text-white text-base">ToE Scope Mapper & Service Discovery</h3>
          </div>
          <span className="text-xs text-emerald-400 bg-emerald-950/60 border border-emerald-800/60 px-2 py-0.5 rounded font-mono">
            Safety Guard Active (RFC1918 Enforced)
          </span>
        </div>

        <div className="mt-4 grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="md:col-span-2">
            <label className="text-xs font-semibold text-slate-400 block mb-1">Target Host / IP</label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
              placeholder="e.g. 192.168.100.105 or 127.0.0.1"
            />
          </div>
          <div>
            <label className="text-xs font-semibold text-slate-400 block mb-1">Start Port</label>
            <input
              type="number"
              value={startPort}
              onChange={(e) => setStartPort(parseInt(e.target.value))}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
            />
          </div>
          <div>
            <label className="text-xs font-semibold text-slate-400 block mb-1">End Port</label>
            <input
              type="number"
              value={endPort}
              onChange={(e) => setEndPort(parseInt(e.target.value))}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>

        <div className="mt-4 flex justify-between items-center">
          <p className="text-[11px] text-slate-500">
            Note: AegisForge SafetyGuard rejects any public WAN destinations (e.g. 8.8.8.8, external domains).
          </p>
          <button
            onClick={handleScan}
            disabled={scanning}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition cursor-pointer disabled:opacity-50"
          >
            <Play className="w-3.5 h-3.5 fill-slate-950" />
            {scanning ? 'Probing Target...' : 'Execute Scoped Scan'}
          </button>
        </div>

        {scanError && (
          <div className="mt-4 p-3 rounded-lg bg-red-950/60 border border-red-800 text-red-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{scanError}</span>
          </div>
        )}

        {scanResult && (
          <div className="mt-5 border-t border-slate-800 pt-4 space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">
                Scan Target: <strong className="text-white">{scanResult.target}</strong> ({scanResult.scan_duration_ms} ms)
              </span>
              <span className="text-cyan-400 font-mono font-semibold">
                {scanResult.open_ports_count} Open Service(s) Discovered
              </span>
            </div>

            <div className="overflow-x-auto rounded-lg border border-slate-800">
              <table className="w-full text-xs font-mono text-left">
                <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="py-2 px-3">Port</th>
                    <th className="py-2 px-3">Protocol</th>
                    <th className="py-2 px-3">State</th>
                    <th className="py-2 px-3">Service</th>
                    <th className="py-2 px-3">Banner / Service Info</th>
                    <th className="py-2 px-3">Known CVE Hints</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 bg-slate-900/40">
                  {scanResult.open_ports.map((p) => (
                    <tr key={p.port} className="hover:bg-slate-800/40">
                      <td className="py-2 px-3 text-cyan-400 font-bold">{p.port}</td>
                      <td className="py-2 px-3 text-slate-400">{p.protocol}</td>
                      <td className="py-2 px-3 text-emerald-400 font-semibold">{p.state}</td>
                      <td className="py-2 px-3 text-white font-semibold">{p.service}</td>
                      <td className="py-2 px-3 text-slate-300">{p.banner || '-'}</td>
                      <td className="py-2 px-3">
                        {p.cve_hints.length > 0 ? (
                          <div className="flex gap-1 flex-wrap">
                            {p.cve_hints.map((cve) => (
                              <span key={cve} className="px-1.5 py-0.2 rounded text-[10px] bg-red-950 text-red-400 border border-red-800">
                                {cve}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <span className="text-slate-600">-</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* CVSS v3.1 Calculator & CVD Generator Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* CVSS v3.1 Calculator */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <Calculator className="w-5 h-5 text-cyan-400" />
              <h3 className="font-bold text-white text-sm">FIRST CVSS v3.1 Calculator</h3>
            </div>
            <button
              onClick={handleCalculateCvss}
              className="px-2.5 py-1 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 text-xs font-semibold hover:bg-cyan-900 transition"
            >
              Compute Score
            </button>
          </div>

          <div className="grid grid-cols-2 gap-3 text-xs">
            <div>
              <label className="text-slate-400 font-medium block mb-1">Attack Vector (AV)</label>
              <select
                value={cvssMetrics.attack_vector}
                onChange={(e) => setCvssMetrics({ ...cvssMetrics, attack_vector: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded p-1.5 text-white"
              >
                <option value="NETWORK">Network (N - 0.85)</option>
                <option value="ADJACENT">Adjacent (A - 0.62)</option>
                <option value="LOCAL">Local (L - 0.55)</option>
                <option value="PHYSICAL">Physical (P - 0.20)</option>
              </select>
            </div>
            <div>
              <label className="text-slate-400 font-medium block mb-1">Attack Complexity (AC)</label>
              <select
                value={cvssMetrics.attack_complexity}
                onChange={(e) => setCvssMetrics({ ...cvssMetrics, attack_complexity: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded p-1.5 text-white"
              >
                <option value="LOW">Low (L - 0.77)</option>
                <option value="HIGH">High (H - 0.44)</option>
              </select>
            </div>
            <div>
              <label className="text-slate-400 font-medium block mb-1">Privileges Required (PR)</label>
              <select
                value={cvssMetrics.privileges_required}
                onChange={(e) => setCvssMetrics({ ...cvssMetrics, privileges_required: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded p-1.5 text-white"
              >
                <option value="NONE">None (N - 0.85)</option>
                <option value="LOW">Low (L - 0.62)</option>
                <option value="HIGH">High (H - 0.27)</option>
              </select>
            </div>
            <div>
              <label className="text-slate-400 font-medium block mb-1">User Interaction (UI)</label>
              <select
                value={cvssMetrics.user_interaction}
                onChange={(e) => setCvssMetrics({ ...cvssMetrics, user_interaction: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded p-1.5 text-white"
              >
                <option value="NONE">None (N - 0.85)</option>
                <option value="REQUIRED">Required (R - 0.62)</option>
              </select>
            </div>
            <div>
              <label className="text-slate-400 font-medium block mb-1">Scope (S)</label>
              <select
                value={cvssMetrics.scope}
                onChange={(e) => setCvssMetrics({ ...cvssMetrics, scope: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded p-1.5 text-white"
              >
                <option value="UNCHANGED">Unchanged (U)</option>
                <option value="CHANGED">Changed (C)</option>
              </select>
            </div>
            <div>
              <label className="text-slate-400 font-medium block mb-1">Confidentiality (C)</label>
              <select
                value={cvssMetrics.confidentiality}
                onChange={(e) => setCvssMetrics({ ...cvssMetrics, confidentiality: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded p-1.5 text-white"
              >
                <option value="HIGH">High (H - 0.56)</option>
                <option value="LOW">Low (L - 0.22)</option>
                <option value="NONE">None (N - 0.0)</option>
              </select>
            </div>
            <div>
              <label className="text-slate-400 font-medium block mb-1">Integrity (I)</label>
              <select
                value={cvssMetrics.integrity}
                onChange={(e) => setCvssMetrics({ ...cvssMetrics, integrity: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded p-1.5 text-white"
              >
                <option value="HIGH">High (H - 0.56)</option>
                <option value="LOW">Low (L - 0.22)</option>
                <option value="NONE">None (N - 0.0)</option>
              </select>
            </div>
            <div>
              <label className="text-slate-400 font-medium block mb-1">Availability (A)</label>
              <select
                value={cvssMetrics.availability}
                onChange={(e) => setCvssMetrics({ ...cvssMetrics, availability: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded p-1.5 text-white"
              >
                <option value="HIGH">High (H - 0.56)</option>
                <option value="LOW">Low (L - 0.22)</option>
                <option value="NONE">None (N - 0.0)</option>
              </select>
            </div>
          </div>

          {cvssResult && (
            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-center justify-between">
              <div>
                <span className="text-xs text-slate-400 font-mono">CVSS v3.1 Base Score</span>
                <div className="text-2xl font-bold text-red-400">{cvssResult.base_score}</div>
                <div className="text-[11px] font-mono text-slate-500 mt-0.5">{cvssResult.vector_string}</div>
              </div>
              <span
                className={`px-3 py-1 rounded text-xs font-bold ${
                  cvssResult.severity_rating === 'CRITICAL'
                    ? 'bg-red-950 text-red-400 border border-red-800'
                    : 'bg-orange-950 text-orange-400 border border-orange-800'
                }`}
              >
                {cvssResult.severity_rating}
              </span>
            </div>
          )}
        </div>

        {/* Coordinated Vulnerability Disclosure (CVD) Form */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <FileText className="w-5 h-5 text-cyan-400" />
              <h3 className="font-bold text-white text-sm">RFC 9116 / ISO 29147 CVD Exporter</h3>
            </div>
            <button
              onClick={handleGenerateCvd}
              className="px-2.5 py-1 rounded bg-cyan-500 text-slate-950 text-xs font-bold hover:bg-cyan-400 transition"
            >
              Generate Advisory
            </button>
          </div>

          <div className="space-y-3 text-xs">
            <div>
              <label className="text-slate-400 block mb-1 font-medium">Advisory Tracking ID</label>
              <input
                type="text"
                value={advisoryId}
                onChange={(e) => setAdvisoryId(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white font-mono"
              />
            </div>
            <div>
              <label className="text-slate-400 block mb-1 font-medium">Vulnerability Title</label>
              <input
                type="text"
                value={vulnTitle}
                onChange={(e) => setVulnTitle(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white"
              />
            </div>
            <div>
              <label className="text-slate-400 block mb-1 font-medium">Affected Component</label>
              <input
                type="text"
                value={affectedComp}
                onChange={(e) => setAffectedComp(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white"
              />
            </div>
            <div>
              <label className="text-slate-400 block mb-1 font-medium">Executive Summary</label>
              <textarea
                rows={2}
                value={summary}
                onChange={(e) => setSummary(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white"
              />
            </div>
          </div>

          {cvdResult && (
            <div className="border-t border-slate-800 pt-3 flex items-center justify-between flex-wrap gap-2">
              <span className="text-xs text-emerald-400 font-medium">Advisory generated successfully</span>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleCopyMd}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-white transition cursor-pointer"
                  title="Copy to clipboard"
                >
                  {copiedMd ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copiedMd ? 'Copied' : 'Copy'}
                </button>
                <button
                  onClick={handleDownloadMd}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-cyan-950 hover:bg-cyan-900 border border-cyan-800 text-xs text-cyan-300 transition cursor-pointer"
                  title="Download Markdown advisory"
                >
                  <Download className="w-3.5 h-3.5" />
                  Download .md
                </button>
                <button
                  onClick={handlePrintAdvisory}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 transition cursor-pointer"
                  title="Print or save as PDF"
                >
                  <Printer className="w-3.5 h-3.5" />
                  Print / PDF
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
