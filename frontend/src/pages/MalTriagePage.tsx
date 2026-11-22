import React, { useState, useEffect } from 'react';
import { api, MalwareTriageResponse } from '../lib/api';
import { CodeHexViewer } from '../components/CodeHexViewer';
import {
  Biohazard,
  FileCode,
  ShieldAlert,
  Search,
  CheckCircle,
  Hash,
  Activity,
  Layers,
  ArrowRight
} from 'lucide-react';

export const MalTriagePage: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState('sample_eicar.com');
  const [activeTabString, setActiveTabString] = useState<'network' | 'filesystem' | 'apis' | 'commands'>('apis');
  const [searchQuery, setSearchQuery] = useState('');
  const [customHex, setCustomHex] = useState('');
  const [showCustomInput, setShowCustomInput] = useState(false);
  const [triageData, setTriageData] = useState<MalwareTriageResponse | null>(null);
  const [availableSamples, setAvailableSamples] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    api.listSamples().then((res) => {
      if (res && res.available_samples) {
        setAvailableSamples(res.available_samples.map((s: any) => s.filename));
      }
    }).catch(() => {});
  }, []);

  const handleTriage = async (filename: string, hexOverride?: string) => {
    setSelectedFile(filename);
    setLoading(true);
    try {
      let contentRawHex: string | undefined = hexOverride;

      if (!contentRawHex) {
        // Provide standard mock hex bytes based on preset if needed
        if (filename === 'sample_eicar.com') {
          contentRawHex = '58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e444152442d414e544956495255532d544553542d46494c452124482b482a';
        } else if (filename === 'sample_synthetic.elf') {
          contentRawHex = '7f454c4602010100000000000000000002003e000100000000104000000000004000000000000000000000000000000000000000400038000100400000000000909090905669727475616c416c6c6f63457800577269746550726f636573734d656d6f72790043726561746552656d6f746554687265616400687474703a2f2f3139322e3136382e3130302e313a383038302f626561636f6e00';
        } else if (filename === 'sample_synthetic.exe') {
          contentRawHex = '4d5a90000300000004000000ffff0000b80000000000000040000000000000005045000064860100000000000000000000000000f0000200446f776e6c6f6164537472696e67202d456e636f646564436f6d6d616e6420535142464158414b41474e656477417441453841596a456a51413d3d';
        }
      }

      const res = await api.triageArtifact(filename, contentRawHex);
      setTriageData(res);
    } catch (e: any) {
      alert(`Triage error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleCustomTriage = () => {
    if (!customHex.trim()) {
      alert('Please enter hexadecimal payload bytes.');
      return;
    }
    handleTriage('custom_artifact.bin', customHex.trim());
  };

  useEffect(() => {
    handleTriage('sample_eicar.com');
  }, []);

  return (
    <div className="space-y-6">
      {/* Top Bar: Artifact Selector */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Biohazard className="w-5 h-5 text-cyan-400" />
            <h3 className="font-bold text-white text-base">Static Binary & Benign Test Artifact Triage</h3>
          </div>
          <span className="text-xs text-slate-400 font-mono">100% Safe / Zero Live Malware Policy</span>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <span className="text-xs font-semibold text-slate-400">Select Test Artifact:</span>
          <button
            onClick={() => handleTriage('sample_eicar.com')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer ${
              selectedFile === 'sample_eicar.com'
                ? 'bg-cyan-500 text-slate-950 font-bold'
                : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
            }`}
          >
            EICAR Anti-Virus Standard String
          </button>
          <button
            onClick={() => handleTriage('sample_synthetic.elf')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer ${
              selectedFile === 'sample_synthetic.elf'
                ? 'bg-cyan-500 text-slate-950 font-bold'
                : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
            }`}
          >
            Synthetic Linux ELF (Process Injection Strings)
          </button>
          <button
            onClick={() => handleTriage('sample_synthetic.exe')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer ${
              selectedFile === 'sample_synthetic.exe'
                ? 'bg-cyan-500 text-slate-950 font-bold'
                : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
            }`}
          >
            Synthetic Windows PE (PowerShell Launcher)
          </button>
          <button
            onClick={() => setShowCustomInput(!showCustomInput)}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer border ${
              showCustomInput
                ? 'bg-cyan-950 text-cyan-400 border-cyan-700'
                : 'bg-slate-800 text-slate-300 border-slate-700 hover:bg-slate-700'
            }`}
          >
            Custom Payload / Hex String
          </button>
        </div>

        {showCustomInput && (
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-2 mt-3">
            <label className="text-xs font-semibold text-slate-300 block">
              Paste Raw Hex / Byte Stream:
            </label>
            <textarea
              rows={2}
              value={customHex}
              onChange={(e) => setCustomHex(e.target.value)}
              placeholder="e.g. 7f 45 4c 46 02 01 01 00 ... or 58354f215025..."
              className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
            />
            <div className="flex justify-end">
              <button
                onClick={handleCustomTriage}
                disabled={loading}
                className="px-3 py-1.5 bg-cyan-500 text-slate-950 font-bold text-xs rounded hover:bg-cyan-400 transition"
              >
                Triage Custom Payload
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Main Analysis View */}
      {triageData && (
        <div className="space-y-6">
          {/* Metadata & Entropy Overview Grid */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-1">
              <span className="text-xs text-slate-400 font-medium">File Format</span>
              <div className="text-sm font-bold text-white truncate">{triageData.file_type}</div>
              <div className="text-[11px] text-slate-500 font-mono">{triageData.file_size_bytes} bytes</div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-1">
              <span className="text-xs text-slate-400 font-medium">Shannon Entropy</span>
              <div className="text-xl font-bold font-mono text-cyan-400">
                {triageData.overall_entropy.toFixed(2)} <span className="text-xs text-slate-500">/ 8.0</span>
              </div>
              <div className="text-[11px] text-slate-400">
                {triageData.is_high_entropy ? (
                  <span className="text-red-400 font-bold">Packed / Encrypted</span>
                ) : (
                  <span className="text-emerald-400">Standard Code / Data</span>
                )}
              </div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-1">
              <span className="text-xs text-slate-400 font-medium">Risk Score</span>
              <div className="text-xl font-bold font-mono text-amber-400">
                {triageData.risk_score} <span className="text-xs text-slate-500">/ 10.0</span>
              </div>
              <div className="text-[11px] text-amber-400 truncate">{triageData.verdict}</div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-1">
              <span className="text-xs text-slate-400 font-medium">SHA-256 Digest</span>
              <div className="text-[11px] font-mono text-slate-300 truncate" title={triageData.hashes.sha256}>
                {triageData.hashes.sha256.slice(0, 18)}...
              </div>
              <div className="text-[10px] text-slate-500 font-mono">MD5: {triageData.hashes.md5.slice(0, 12)}...</div>
            </div>
          </div>

          {/* Entropy Sliding Window Bar */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-bold text-white text-xs uppercase tracking-wider flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                Shannon Entropy Block Heatmap
              </span>
              <span className="text-[11px] font-mono text-slate-400">Threshold: &gt;7.2 = Potential Packing</span>
            </div>

            <div className="flex gap-1 h-8 rounded-lg overflow-hidden bg-slate-950 p-1 border border-slate-800">
              {triageData.entropy_sliding_window.length > 0 ? (
                triageData.entropy_sliding_window.map((blk, idx) => {
                  const pct = (blk.entropy / 8.0) * 100;
                  const isHigh = blk.entropy >= 7.2;
                  return (
                    <div
                      key={idx}
                      style={{ width: `${100 / triageData.entropy_sliding_window.length}%` }}
                      className={`h-full rounded-sm transition-all hover:scale-105 cursor-pointer ${
                        isHigh ? 'bg-red-500' : blk.entropy > 5.0 ? 'bg-cyan-500' : 'bg-blue-600'
                      }`}
                      title={`Offset ${blk.offset}: Entropy ${blk.entropy}`}
                    />
                  );
                })
              ) : (
                <div
                  className="h-full bg-cyan-600 rounded"
                  style={{ width: `${(triageData.overall_entropy / 8.0) * 100}%` }}
                />
              )}
            </div>
          </div>

          {/* Grid: YARA Signatures & MITRE ATT&CK Matrix */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Matched YARA Signatures */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-3">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <h4 className="font-bold text-white text-sm">Matched YARA Detection Rules</h4>
                <span className="text-xs text-cyan-400 font-mono font-bold">
                  {triageData.yara_matches.length} Matches
                </span>
              </div>

              <div className="space-y-2.5 max-h-[250px] overflow-y-auto">
                {triageData.yara_matches.length === 0 ? (
                  <div className="py-6 text-center text-slate-500 text-xs">No signatures matched.</div>
                ) : (
                  triageData.yara_matches.map((m) => (
                    <div key={m.rule_id} className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-white text-xs">{m.rule_name}</span>
                        <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-red-950 text-red-400 border border-red-800">
                          {m.severity}
                        </span>
                      </div>
                      <p className="text-slate-400 text-[11px] leading-relaxed">{m.description}</p>
                      <div className="text-[10px] font-mono text-cyan-400 mt-1">
                        Matched: {m.matched_strings.join(', ')}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* MITRE ATT&CK Matrix Mapping */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-3">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <h4 className="font-bold text-white text-sm">MITRE ATT&CK Matrix Mapping</h4>
                <span className="text-xs text-purple-400 font-mono font-bold">
                  {triageData.mitre_attack_matrix.length} Techniques
                </span>
              </div>

              <div className="overflow-x-auto rounded-lg border border-slate-800 max-h-[250px]">
                <table className="w-full text-xs font-mono text-left">
                  <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 sticky top-0">
                    <tr>
                      <th className="py-2 px-3">Technique ID</th>
                      <th className="py-2 px-3">Name</th>
                      <th className="py-2 px-3">Tactic</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 bg-slate-900/40">
                    {triageData.mitre_attack_matrix.map((t) => (
                      <tr key={t.id} className="hover:bg-slate-800/40">
                        <td className="py-2 px-3 text-cyan-400 font-bold">{t.id}</td>
                        <td className="py-2 px-3 text-white">{t.name}</td>
                        <td className="py-2 px-3 text-purple-400">{t.tactic}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Categorized Strings & Indicators of Compromise */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800 flex-wrap gap-2">
              <h4 className="font-bold text-white text-sm">Extracted Strings & Indicators of Compromise (IOCs)</h4>
              <div className="flex items-center gap-2">
                <div className="relative">
                  <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Filter strings..."
                    className="pl-8 pr-2 py-1 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-36"
                  />
                </div>
                <div className="flex gap-1.5">
                  {(['apis', 'network', 'filesystem', 'commands'] as const).map((tab) => (
                    <button
                      key={tab}
                      onClick={() => setActiveTabString(tab)}
                      className={`px-2.5 py-1 rounded text-xs capitalize transition cursor-pointer ${
                        activeTabString === tab
                          ? 'bg-cyan-500 text-slate-950 font-bold'
                          : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                      }`}
                    >
                      {tab} ({triageData.classified_strings[tab]?.length || 0})
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="md:col-span-2 p-3 bg-slate-950 rounded-lg border border-slate-800 max-h-[200px] overflow-y-auto font-mono text-xs space-y-1">
                {(triageData.classified_strings[activeTabString] || [])
                  .filter((s) => !searchQuery || s.toLowerCase().includes(searchQuery.toLowerCase()))
                  .map((s, idx) => (
                    <div key={idx} className="text-slate-300 hover:text-cyan-400 py-0.5">
                      {s}
                    </div>
                  ))}
              </div>

              {/* Detected IOC summary */}
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-3 font-mono text-xs">
                <div>
                  <span className="text-slate-500 block text-[10px]">IPv4 Endpoints:</span>
                  <div className="text-cyan-400">
                    {triageData.detected_iocs.ipv4_addresses?.length > 0
                      ? triageData.detected_iocs.ipv4_addresses.join(', ')
                      : 'None'}
                  </div>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">URLs Detected:</span>
                  <div className="text-cyan-400 truncate">
                    {triageData.detected_iocs.urls?.length > 0
                      ? triageData.detected_iocs.urls.join(', ')
                      : 'None'}
                  </div>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Emails:</span>
                  <div className="text-cyan-400">
                    {triageData.detected_iocs.emails?.length > 0
                      ? triageData.detected_iocs.emails.join(', ')
                      : 'None'}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
