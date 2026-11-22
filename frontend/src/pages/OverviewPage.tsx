import React, { useState } from 'react';
import {
  ShieldAlert,
  Bug,
  Network,
  FileText,
  Activity,
  ArrowRight,
  CheckCircle,
  ExternalLink
} from 'lucide-react';
import { ThreatFeed } from '../components/ThreatFeed';
import { TelemetryEvent } from '../lib/ws';

interface OverviewPageProps {
  events: TelemetryEvent[];
  onClearEvents: () => void;
  onNavigate: (tab: string) => void;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({ events, onClearEvents, onNavigate }) => {
  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900 to-cyan-950/40 border border-slate-800 p-6 shadow-xl">
        <div className="relative z-10 max-w-3xl space-y-2">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-cyan-950/80 border border-cyan-800 text-cyan-400 text-xs font-mono">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            Active Cyber Range Node: 192.168.100.0/24
          </div>
          <h2 className="text-2xl font-bold text-white tracking-tight">
            AegisForge Purple-Team Defensive & Vulnerability Workbench
          </h2>
          <p className="text-slate-300 text-xs leading-relaxed">
            A unified offensive simulation and defensive mitigation platform. Safely explore memory corruption mechanics,
            test stateful protocol fuzzing resilience, isolate Man-in-the-Middle network attacks via Dynamic ARP Inspection,
            and formulate RFC 9116 Coordinated Vulnerability Disclosure reports inside safe, zero-privilege sandboxes.
          </p>
        </div>
      </div>

      {/* KPI Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <div className="text-xs text-slate-400 font-medium">Scoped Lab Targets</div>
            <div className="text-2xl font-bold text-white mt-1">3 <span className="text-xs font-normal text-slate-500">Nodes</span></div>
            <div className="text-[11px] text-emerald-400 mt-1 flex items-center gap-1">
              <CheckCircle className="w-3 h-3" /> RFC1918 Guard Active
            </div>
          </div>
          <div className="p-3 bg-cyan-950/50 rounded-xl border border-cyan-800/40 text-cyan-400">
            <Network className="w-6 h-6" />
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <div className="text-xs text-slate-400 font-medium">Mitigated Attacks</div>
            <div className="text-2xl font-bold text-emerald-400 mt-1">100%</div>
            <div className="text-[11px] text-slate-400 mt-1">DAI + Static Pinning</div>
          </div>
          <div className="p-3 bg-emerald-950/50 rounded-xl border border-emerald-800/40 text-emerald-400">
            <ShieldAlert className="w-6 h-6" />
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <div className="text-xs text-slate-400 font-medium">Fuzzing Crashes Isolated</div>
            <div className="text-2xl font-bold text-amber-400 mt-1">3 <span className="text-xs font-normal text-slate-500">Vectors</span></div>
            <div className="text-[11px] text-slate-400 mt-1">Buffer, Format, IntMax</div>
          </div>
          <div className="p-3 bg-amber-950/50 rounded-xl border border-amber-800/40 text-amber-400">
            <Bug className="w-6 h-6" />
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <div className="text-xs text-slate-400 font-medium">Disclosed CVE Advisories</div>
            <div className="text-2xl font-bold text-purple-400 mt-1">ISO 29147</div>
            <div className="text-[11px] text-slate-400 mt-1">RFC 9116 Standard</div>
          </div>
          <div className="p-3 bg-purple-950/50 rounded-xl border border-purple-800/40 text-purple-400">
            <FileText className="w-6 h-6" />
          </div>
        </div>
      </div>

      {/* Main Grid: Kill-Chain Matrix + Threat Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* 2 Cols: Purple-Team Matrix */}
        <div className="lg:col-span-2 space-y-4">
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg">
            <div className="flex items-center justify-between pb-4 border-b border-slate-800">
              <h3 className="font-bold text-white text-sm flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                Purple-Team Module Capabilities Matrix
              </h3>
              <span className="text-xs text-slate-500 font-mono">5 Engines Active</span>
            </div>

            <div className="mt-4 space-y-3">
              {/* Module 1 */}
              <div
                onClick={() => onNavigate('recon')}
                className="p-3.5 bg-slate-950 rounded-xl border border-slate-800 hover:border-cyan-500/50 hover:bg-slate-900/60 transition cursor-pointer flex items-center justify-between group"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-cyan-400 text-xs">Module 1</span>
                    <span className="text-sm font-semibold text-white">Reconnaissance & Coordinated Disclosure</span>
                  </div>
                  <p className="text-xs text-slate-400">
                    ToE scope boundary verification, service banner discovery, CVSS v3.1 calculation, and RFC 9116 CVD advisory generation.
                  </p>
                </div>
                <ArrowRight className="w-4 h-4 text-slate-600 group-hover:text-cyan-400 group-hover:translate-x-1 transition shrink-0 ml-4" />
              </div>

              {/* Module 2 */}
              <div
                onClick={() => onNavigate('netarena')}
                className="p-3.5 bg-slate-950 rounded-xl border border-slate-800 hover:border-cyan-500/50 hover:bg-slate-900/60 transition cursor-pointer flex items-center justify-between group"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-cyan-400 text-xs">Module 2</span>
                    <span className="text-sm font-semibold text-white">Network Arena & Active Defense Daemon</span>
                  </div>
                  <p className="text-xs text-slate-400">
                    Simulate ARP cache poisoning MITM attacks on a 3-node micro-network and inspect real-time Dynamic ARP Inspection (DAI) defense.
                  </p>
                </div>
                <ArrowRight className="w-4 h-4 text-slate-600 group-hover:text-cyan-400 group-hover:translate-x-1 transition shrink-0 ml-4" />
              </div>

              {/* Module 3 */}
              <div
                onClick={() => onNavigate('exploit')}
                className="p-3.5 bg-slate-950 rounded-xl border border-slate-800 hover:border-cyan-500/50 hover:bg-slate-900/60 transition cursor-pointer flex items-center justify-between group"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-cyan-400 text-xs">Module 3</span>
                    <span className="text-sm font-semibold text-white">Exploit Studio & Stack Memory Mechanics</span>
                  </div>
                  <p className="text-xs text-slate-400">
                    Interactive Stack Frame diagram with toggleable compiler mitigations (Canary, NX, ASLR, PIE) and Shellcode badchar disassembler.
                  </p>
                </div>
                <ArrowRight className="w-4 h-4 text-slate-600 group-hover:text-cyan-400 group-hover:translate-x-1 transition shrink-0 ml-4" />
              </div>

              {/* Module 4 */}
              <div
                onClick={() => onNavigate('fuzzre')}
                className="p-3.5 bg-slate-950 rounded-xl border border-slate-800 hover:border-cyan-500/50 hover:bg-slate-900/60 transition cursor-pointer flex items-center justify-between group"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-cyan-400 text-xs">Module 4</span>
                    <span className="text-sm font-semibold text-white">Stateful Protocol Fuzzing & Windows ACL Audit</span>
                  </div>
                  <p className="text-xs text-slate-400">
                    Mutation-based fuzzer testing edge-case protocol state machines, plus static JSON Security Descriptor / ACL auditor.
                  </p>
                </div>
                <ArrowRight className="w-4 h-4 text-slate-600 group-hover:text-cyan-400 group-hover:translate-x-1 transition shrink-0 ml-4" />
              </div>

              {/* Module 5 */}
              <div
                onClick={() => onNavigate('maltriage')}
                className="p-3.5 bg-slate-950 rounded-xl border border-slate-800 hover:border-cyan-500/50 hover:bg-slate-900/60 transition cursor-pointer flex items-center justify-between group"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-cyan-400 text-xs">Module 5</span>
                    <span className="text-sm font-semibold text-white">Malware & Benign Artifact Triage</span>
                  </div>
                  <p className="text-xs text-slate-400">
                    Shannon entropy sliding window analyzer, printable strings extractor, regex IOC detector, YARA signature engine, and MITRE mapping.
                  </p>
                </div>
                <ArrowRight className="w-4 h-4 text-slate-600 group-hover:text-cyan-400 group-hover:translate-x-1 transition shrink-0 ml-4" />
              </div>
            </div>
          </div>
        </div>

        {/* 1 Col: Live Threat Feed */}
        <div className="h-[520px]">
          <ThreatFeed events={events} onClear={onClearEvents} />
        </div>
      </div>
    </div>
  );
};
