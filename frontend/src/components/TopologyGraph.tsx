import React, { useState } from 'react';
import { Server, Radio, Laptop, Shield, ShieldAlert, ShieldCheck } from 'lucide-react';
import { NetArenaStatusResponse } from '../lib/api';

interface TopologyGraphProps {
  status: NetArenaStatusResponse | null;
  onToggleMitm: () => void;
  onToggleDefense: () => void;
  isEngaging: boolean;
}

export const TopologyGraph: React.FC<TopologyGraphProps> = ({
  status,
  onToggleMitm,
  onToggleDefense,
  isEngaging,
}) => {
  const [selectedNode, setSelectedNode] = useState<'gw' | 'attacker' | 'victim' | null>(null);

  const isMitm = status?.mitm_active ?? false;
  const isDefense = status?.active_defense_enabled ?? true;
  const isPoisoned = isMitm && !isDefense;

  return (
    <div className="space-y-4">
      {/* SVG Interactive Canvas */}
      <div className="relative w-full h-[320px] bg-slate-950 rounded-2xl border border-slate-800 overflow-hidden shadow-inner flex flex-col justify-between p-4">
        {/* Top telemetry bar */}
        <div className="flex items-center justify-between text-xs z-10">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping" />
            <span className="font-mono text-slate-300 font-bold">192.168.100.0/24 Sandbox Bridge</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-mono text-slate-400">
              Flow Status:{' '}
              {isPoisoned ? (
                <span className="text-red-400 font-bold">ARP CACHE POISONED (MITM)</span>
              ) : isMitm && isDefense ? (
                <span className="text-cyan-400 font-bold">DAI MITIGATION ACTIVE</span>
              ) : (
                <span className="text-emerald-400 font-bold">LEGITIMATE TRAFFIC</span>
              )}
            </span>
          </div>
        </div>

        {/* SVG Wiring & Animated Traffic Arcs */}
        <svg className="absolute inset-0 w-full h-full pointer-events-none">
          <defs>
            <linearGradient id="grad-legit" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#06b6d4" />
              <stop offset="100%" stopColor="#a855f7" />
            </linearGradient>
            <linearGradient id="grad-poison" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#ef4444" />
              <stop offset="100%" stopColor="#f59e0b" />
            </linearGradient>
          </defs>

          {/* Connection Arc 1: Gateway (left: 20%, 55%) to Victim (right: 80%, 55%) */}
          <path
            d="M 160 170 C 300 240, 500 240, 680 170"
            fill="none"
            stroke={isPoisoned ? '#475569' : '#0ea5e9'}
            strokeWidth={isPoisoned ? '1.5' : '3'}
            strokeDasharray={isPoisoned ? '4 4' : '6 6'}
            className={!isPoisoned ? 'animate-[dash_1.5s_linear_infinite]' : ''}
          />

          {/* Connection Arc 2: Attacker (top: 50%, 25%) to Gateway (left: 20%, 55%) */}
          <path
            d="M 420 90 C 300 90, 200 120, 160 160"
            fill="none"
            stroke={isMitm ? '#ef4444' : '#334155'}
            strokeWidth={isMitm ? '2.5' : '1.5'}
            strokeDasharray={isMitm ? '4 4' : 'none'}
            className={isMitm ? 'animate-[dash_1s_linear_infinite]' : ''}
          />

          {/* Connection Arc 3: Attacker (top: 50%, 25%) to Victim (right: 80%, 55%) */}
          <path
            d="M 420 90 C 540 90, 640 120, 680 160"
            fill="none"
            stroke={isMitm ? (isPoisoned ? '#ef4444' : '#06b6d4') : '#334155'}
            strokeWidth={isMitm ? '2.5' : '1.5'}
            strokeDasharray={isMitm ? '4 4' : 'none'}
            className={isMitm ? 'animate-[dash_1s_linear_infinite]' : ''}
          />
        </svg>

        {/* 3 Clickable Nodes positioned inside canvas */}
        <div className="relative w-full h-[220px] flex items-center justify-between px-6 z-10">
          {/* Node 1: Gateway */}
          <div
            onClick={() => setSelectedNode('gw')}
            className={`w-44 p-3 rounded-xl border transition-all cursor-pointer select-none ${
              selectedNode === 'gw'
                ? 'bg-blue-950/90 border-cyan-400 ring-2 ring-cyan-500/30'
                : 'bg-slate-900/90 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-center gap-2 mb-1.5">
              <div className="p-1.5 rounded-lg bg-blue-950 border border-blue-800 text-blue-400">
                <Server className="w-4 h-4" />
              </div>
              <div>
                <div className="font-bold text-xs text-white">Default Gateway</div>
                <div className="font-mono text-[10px] text-cyan-400">192.168.100.1</div>
              </div>
            </div>
            <div className="text-[10px] font-mono text-slate-400 truncate">MAC: 00:11:22:33:44:01</div>
            <div className="mt-1 text-[9px] font-semibold text-emerald-400">● Dynamic Routing Online</div>
          </div>

          {/* Node 2: Rogue Attacker / Sandbox Monitor (Top Center) */}
          <div
            onClick={() => setSelectedNode('attacker')}
            className={`w-48 p-3 rounded-xl border transition-all cursor-pointer select-none -translate-y-8 ${
              isMitm
                ? 'bg-red-950/90 border-red-700 shadow-lg shadow-red-950/60 ring-2 ring-red-500/20'
                : 'bg-slate-900/90 border-slate-800 hover:border-slate-700'
            } ${selectedNode === 'attacker' ? 'ring-2 ring-amber-400/50' : ''}`}
          >
            <div className="flex items-center gap-2 mb-1.5">
              <div
                className={`p-1.5 rounded-lg border ${
                  isMitm ? 'bg-red-950 border-red-600 text-red-400' : 'bg-slate-800 border-slate-700 text-slate-400'
                }`}
              >
                <Radio className="w-4 h-4" />
              </div>
              <div>
                <div className="font-bold text-xs text-white">Sandbox Attacker</div>
                <div className="font-mono text-[10px] text-amber-400">192.168.100.200</div>
              </div>
            </div>
            <div className="text-[10px] font-mono text-slate-400 truncate">MAC: 00:11:22:33:44:03</div>
            <div className="mt-1 text-[9px] font-semibold">
              {isMitm ? (
                <span className="text-red-400 animate-pulse">● Spoofing Gratuitous ARPs</span>
              ) : (
                <span className="text-slate-500">● Passive Monitor Mode</span>
              )}
            </div>
          </div>

          {/* Node 3: Victim Workstation */}
          <div
            onClick={() => setSelectedNode('victim')}
            className={`w-44 p-3 rounded-xl border transition-all cursor-pointer select-none ${
              isPoisoned
                ? 'bg-orange-950/90 border-orange-700 shadow-lg shadow-orange-950/60 ring-2 ring-orange-500/20'
                : 'bg-slate-900/90 border-slate-800 hover:border-slate-700'
            } ${selectedNode === 'victim' ? 'ring-2 ring-purple-400/50' : ''}`}
          >
            <div className="flex items-center gap-2 mb-1.5">
              <div className="p-1.5 rounded-lg bg-purple-950 border border-purple-800 text-purple-400">
                <Laptop className="w-4 h-4" />
              </div>
              <div>
                <div className="font-bold text-xs text-white">Victim Node</div>
                <div className="font-mono text-[10px] text-purple-400">192.168.100.105</div>
              </div>
            </div>
            <div className="text-[10px] font-mono text-slate-400 truncate">MAC: 00:11:22:33:44:02</div>
            <div className="mt-1 text-[9px] font-semibold">
              {isPoisoned ? (
                <span className="text-red-400">● ARP Cache Intercepted</span>
              ) : (
                <span className="text-emerald-400">● Protected via DAI & Pinning</span>
              )}
            </div>
          </div>
        </div>

        {/* Bottom Legend and Action Controls */}
        <div className="flex items-center justify-between text-xs border-t border-slate-900 pt-2 z-10">
          <div className="flex items-center gap-4 text-[11px] text-slate-400">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-cyan-400" /> Legitimate Path
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-red-400" /> ARP Poison Stream
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400" /> DAI Shield Active
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={onToggleDefense}
              disabled={isEngaging}
              className={`px-3 py-1 rounded-lg text-xs font-semibold border transition cursor-pointer ${
                isDefense
                  ? 'bg-emerald-950/80 text-emerald-300 border-emerald-700 hover:bg-emerald-900'
                  : 'bg-slate-900 text-slate-400 border-slate-700 hover:bg-slate-800'
              }`}
            >
              {isDefense ? 'DAI Defense: ENABLED' : 'DAI Defense: DISABLED'}
            </button>
            <button
              onClick={onToggleMitm}
              disabled={isEngaging}
              className={`px-3 py-1 rounded-lg text-xs font-bold transition cursor-pointer ${
                isMitm
                  ? 'bg-red-600 hover:bg-red-500 text-white'
                  : 'bg-cyan-500 hover:bg-cyan-400 text-slate-950'
              }`}
            >
              {isMitm ? 'Disengage ARP Attack' : 'Simulate ARP Poisoning'}
            </button>
          </div>
        </div>
      </div>

      {/* Selected Node Inspector Detail Card */}
      {selectedNode && (
        <div className="p-3 bg-slate-900/80 border border-slate-800 rounded-xl text-xs space-y-1">
          <div className="flex items-center justify-between">
            <span className="font-bold text-white uppercase tracking-wider text-[11px]">
              Inspected Node: {selectedNode === 'gw' ? 'Gateway' : selectedNode === 'attacker' ? 'Attacker' : 'Victim'}
            </span>
            <button
              onClick={() => setSelectedNode(null)}
              className="text-slate-500 hover:text-white text-[11px]"
            >
              Dismiss
            </button>
          </div>
          <p className="text-slate-400 leading-relaxed">
            {selectedNode === 'gw' &&
              'Default Gateway (192.168.100.1). Routes all traffic across the virtual bridge. In normal state, ARP broadcasts resolve to 00:11:22:33:44:01.'}
            {selectedNode === 'attacker' &&
              'Attacker / Monitor node (192.168.100.200). Generates rogue unsolicited Gratuitous ARP replies to overwrite the victim host mapping.'}
            {selectedNode === 'victim' &&
              'Victim Workstation (192.168.100.105). Targeted host in this Purple-Team lab. Protected when Dynamic ARP Inspection and Static Binding are engaged.'}
          </p>
        </div>
      )}
    </div>
  );
};
