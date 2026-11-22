import React, { useState, useEffect } from 'react';
import { api, NetArenaStatus, PacketEvent } from '../lib/api';
import {
  Network,
  Shield,
  ShieldAlert,
  Server,
  Laptop,
  Radio,
  RefreshCw,
  AlertTriangle,
  Lock,
  ArrowRight
} from 'lucide-react';

export const NetArenaPage: React.FC = () => {
  const [status, setStatus] = useState<NetArenaStatus | null>(null);
  const [packets, setPackets] = useState<PacketEvent[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchStatus = async () => {
    try {
      const s = await api.getNetArenaStatus();
      setStatus(s);
      const pkts = await api.getPackets(6);
      setPackets(pkts);
    } catch (_) {}
  };

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(() => {
      fetchStatus();
    }, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleToggleMitm = async () => {
    if (!status) return;
    setLoading(true);
    try {
      const nextMitm = !status.mitm_active;
      const res = await api.toggleMitm(nextMitm);
      setStatus(res);
      const pkts = await api.getPackets(6);
      setPackets(pkts);
    } catch (e: any) {
      alert(`Error toggling MITM: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleToggleDefense = async () => {
    if (!status) return;
    setLoading(true);
    try {
      const nextDefense = !status.active_defense_enabled;
      const res = await api.toggleDefense(nextDefense);
      setStatus(res);
    } catch (e: any) {
      alert(`Error toggling Defense: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Topology & Controls Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Network className="w-5 h-5 text-cyan-400" />
            <h3 className="font-bold text-white text-base">3-Node Micro-Network Arena (Isolated Bridge)</h3>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleToggleDefense}
              disabled={loading}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5 cursor-pointer ${
                status?.active_defense_enabled
                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                  : 'bg-slate-800 text-slate-400 hover:text-white'
              }`}
            >
              <Shield className="w-3.5 h-3.5" />
              Active Defense: {status?.active_defense_enabled ? 'ENABLED' : 'DISABLED'}
            </button>
            <button
              onClick={handleToggleMitm}
              disabled={loading}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5 cursor-pointer ${
                status?.mitm_active
                  ? 'bg-red-950 text-red-400 border border-red-800 animate-pulse'
                  : 'bg-cyan-500 hover:bg-cyan-400 text-slate-950'
              }`}
            >
              <Radio className="w-3.5 h-3.5" />
              {status?.mitm_active ? 'Disengage ARP Spoof' : 'Simulate ARP Spoof Attack'}
            </button>
          </div>
        </div>

        {/* Visual 3-Node Topology Diagram */}
        <div className="py-8 px-4 grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
          {/* Node 1: Gateway */}
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-center relative group">
            <div className="w-12 h-12 mx-auto rounded-xl bg-blue-950 border border-blue-800 flex items-center justify-center text-blue-400 mb-2">
              <Server className="w-6 h-6" />
            </div>
            <div className="font-bold text-sm text-white">Default Gateway</div>
            <div className="font-mono text-xs text-cyan-400 mt-1">192.168.100.1</div>
            <div className="font-mono text-[10px] text-slate-500">MAC: 00:11:22:33:44:01</div>
            <div className="mt-2 text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-400 inline-block">
              Role: Internal Router
            </div>
          </div>

          {/* Node 2: Attacker / Monitor */}
          <div
            className={`p-4 rounded-xl border text-center transition-all ${
              status?.mitm_active
                ? 'bg-red-950/40 border-red-800 text-red-200 shadow-lg shadow-red-950/50'
                : 'bg-slate-950 border-slate-800 text-slate-200'
            }`}
          >
            <div
              className={`w-12 h-12 mx-auto rounded-xl flex items-center justify-center mb-2 ${
                status?.mitm_active
                  ? 'bg-red-950 border border-red-700 text-red-400'
                  : 'bg-slate-900 border border-slate-800 text-slate-400'
              }`}
            >
              <Radio className="w-6 h-6" />
            </div>
            <div className="font-bold text-sm">Monitor / Rogue Attacker</div>
            <div className="font-mono text-xs text-amber-400 mt-1">192.168.100.200</div>
            <div className="font-mono text-[10px] text-slate-500">MAC: 00:11:22:33:44:03</div>
            <div className="mt-2 text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-400 inline-block">
              {status?.mitm_active ? 'ARP POISONING ACTIVE' : 'Passive Sandbox Monitor'}
            </div>
          </div>

          {/* Node 3: Victim */}
          <div
            className={`p-4 rounded-xl border text-center transition-all ${
              status?.nodes.find((n) => n.id === 'node-victim')?.is_compromised && !status?.active_defense_enabled
                ? 'bg-orange-950/40 border-orange-800 text-orange-200'
                : 'bg-slate-950 border-slate-800 text-slate-200'
            }`}
          >
            <div className="w-12 h-12 mx-auto rounded-xl bg-purple-950 border border-purple-800 flex items-center justify-center text-purple-400 mb-2">
              <Laptop className="w-6 h-6" />
            </div>
            <div className="font-bold text-sm">Victim Workstation</div>
            <div className="font-mono text-xs text-purple-400 mt-1">192.168.100.105</div>
            <div className="font-mono text-[10px] text-slate-500">MAC: 00:11:22:33:44:02</div>
            <div className="mt-2 text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-400 inline-block">
              {status?.nodes.find((n) => n.id === 'node-victim')?.is_compromised && !status?.active_defense_enabled
                ? 'TRAFFIC INTERCEPTED'
                : 'Protected by DAI'}
            </div>
          </div>
        </div>
      </div>

      {/* Grid: ARP Table & Defensive Action Daemon Log */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Victim Host ARP Table */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-3">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h4 className="font-bold text-white text-sm">Victim Node ARP Cache Table</h4>
            <span className="text-[11px] font-mono text-slate-400">Target: 192.168.100.105</span>
          </div>

          <div className="overflow-x-auto rounded-lg border border-slate-800">
            <table className="w-full text-xs font-mono text-left">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-2 px-3">IP Address</th>
                  <th className="py-2 px-3">Resolved MAC</th>
                  <th className="py-2 px-3">Hostname</th>
                  <th className="py-2 px-3">State</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 bg-slate-900/40">
                {status?.arp_table.map((entry) => (
                  <tr key={entry.ip} className="hover:bg-slate-800/40">
                    <td className="py-2 px-3 text-cyan-400 font-bold">{entry.ip}</td>
                    <td className="py-2 px-3 text-slate-200">{entry.mac}</td>
                    <td className="py-2 px-3 text-slate-400">{entry.hostname}</td>
                    <td className="py-2 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          entry.state === 'POISONED'
                            ? 'bg-red-950 text-red-400 border border-red-800 animate-pulse'
                            : entry.state === 'PINNED'
                            ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                            : 'bg-blue-950 text-blue-400 border border-blue-800'
                        }`}
                      >
                        {entry.state}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Active Defense Daemon Action Log */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-3 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h4 className="font-bold text-white text-sm">Dynamic ARP Inspection (DAI) Action Log</h4>
              <span className="text-[11px] font-mono text-emerald-400">
                Spoofed Blocked: {status?.spoofed_packets_detected}
              </span>
            </div>

            <div className="mt-3 space-y-2 font-mono text-[11px] max-h-[190px] overflow-y-auto">
              {status?.defensive_actions_taken.map((action, idx) => (
                <div key={idx} className="p-2 rounded bg-slate-950 border border-slate-800/80 text-slate-300">
                  {action}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Live Packet Stream Inspector */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-3">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <h4 className="font-bold text-white text-sm">Live Synthetic Packet Inspection Stream</h4>
          <span className="text-xs text-slate-400 font-mono">Total Packets Inspected: {status?.total_packets_inspected}</span>
        </div>

        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full text-xs font-mono text-left">
            <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-2 px-3">Frame ID</th>
                <th className="py-2 px-3">Protocol</th>
                <th className="py-2 px-3">Source (IP / MAC)</th>
                <th className="py-2 px-3">Destination (IP / MAC)</th>
                <th className="py-2 px-3">Len</th>
                <th className="py-2 px-3">Frame Payload Information</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 bg-slate-900/40">
              {packets.map((pkt) => (
                <tr key={pkt.id} className={pkt.is_anomalous ? 'bg-red-950/30' : 'hover:bg-slate-800/40'}>
                  <td className="py-2 px-3 text-slate-500">{pkt.id}</td>
                  <td className="py-2 px-3">
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        pkt.protocol === 'ARP'
                          ? 'bg-amber-950 text-amber-400'
                          : pkt.protocol === 'HTTP'
                          ? 'bg-blue-950 text-blue-400'
                          : 'bg-slate-800 text-slate-300'
                      }`}
                    >
                      {pkt.protocol}
                    </span>
                  </td>
                  <td className="py-2 px-3 text-slate-300">
                    <div>{pkt.source_ip}</div>
                    <div className="text-[10px] text-slate-500">{pkt.source_mac}</div>
                  </td>
                  <td className="py-2 px-3 text-slate-300">
                    <div>{pkt.dest_ip}</div>
                    <div className="text-[10px] text-slate-500">{pkt.dest_mac}</div>
                  </td>
                  <td className="py-2 px-3 text-slate-400">{pkt.length}</td>
                  <td className="py-2 px-3 text-slate-300">
                    {pkt.info}
                    {pkt.is_anomalous && (
                      <span className="ml-2 px-1 rounded bg-red-950 text-red-400 text-[10px] font-bold border border-red-800">
                        ANOMALOUS
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
