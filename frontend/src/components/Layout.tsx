import React, { useState } from 'react';
import {
  Shield,
  LayoutDashboard,
  Radar,
  Network,
  Cpu,
  Bug,
  Biohazard,
  Play,
  CheckCircle2,
  XCircle,
  Loader2,
  Activity,
  Server,
  Menu,
  X
} from 'lucide-react';
import { api, ScenarioRunResponse } from '../lib/api';
import { useToast } from './Toast';

interface LayoutProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  isWsConnected: boolean;
  children: React.ReactNode;
}

export const Layout: React.FC<LayoutProps> = ({
  activeTab,
  setActiveTab,
  isWsConnected,
  children,
}) => {
  const [runningScenario, setRunningScenario] = useState(false);
  const [scenarioResult, setScenarioResult] = useState<ScenarioRunResponse | null>(null);
  const [showScenarioModal, setShowScenarioModal] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const toast = useToast();

  const navItems = [
    { id: 'overview', label: 'Command Matrix', icon: LayoutDashboard },
    { id: 'recon', label: 'Recon & CVD Scope', icon: Radar },
    { id: 'netarena', label: 'Network Arena', icon: Network },
    { id: 'exploit', label: 'Exploit Studio & Stack', icon: Cpu },
    { id: 'fuzzre', label: 'Protocol Fuzz & ACL', icon: Bug },
    { id: 'maltriage', label: 'Malware & Artifact Triage', icon: Biohazard },
  ];

  const handleRunScenario = async () => {
    setRunningScenario(true);
    setShowScenarioModal(true);
    setScenarioResult(null);
    try {
      const res = await api.runPurpleTeam();
      setScenarioResult(res);
      toast.success(`Scenario ${res.scenario_id} completed successfully!`);
    } catch (e: any) {
      toast.error(`Scenario failed: ${e.message}`);
    } finally {
      setRunningScenario(false);
    }
  };

  const handleNavClick = (id: string) => {
    setActiveTab(id);
    setMobileMenuOpen(false);
  };

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 overflow-hidden font-sans">
      {/* Mobile Backdrop */}
      {mobileMenuOpen && (
        <div
          onClick={() => setMobileMenuOpen(false)}
          className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-30 md:hidden"
        />
      )}

      {/* Sidebar Navigation */}
      <aside
        className={`fixed md:static inset-y-0 left-0 w-64 bg-slate-900 border-r border-slate-800 flex flex-col justify-between z-40 shrink-0 transform transition-transform duration-200 ease-in-out ${
          mobileMenuOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'
        }`}
      >
        <div>
          {/* Logo Branding */}
          <div className="p-5 border-b border-slate-800/80 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 shadow-md shadow-cyan-500/20">
                <Shield className="w-5 h-5 text-slate-950 stroke-[2.5]" />
              </div>
              <div>
                <h1 className="font-bold text-base tracking-wider text-white">AEGISFORGE</h1>
                <p className="text-[10px] text-cyan-400 font-mono tracking-widest uppercase">Purple-Team Range</p>
              </div>
            </div>
            <button
              onClick={() => setMobileMenuOpen(false)}
              className="md:hidden text-slate-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Mode Pill & Health */}
          <div className="px-4 py-3 border-b border-slate-800/60 bg-slate-950/40 flex items-center justify-between text-xs">
            <div className="flex items-center gap-2">
              <Server className="w-3.5 h-3.5 text-slate-400" />
              <span className="text-slate-400">Mode:</span>
              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-400 border border-cyan-800/60">
                SIMULATION
              </span>
            </div>
            <div className="flex items-center gap-1.5" title={isWsConnected ? "WebSocket Connected" : "Connecting..."}>
              <span className={`w-2 h-2 rounded-full ${isWsConnected ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`} />
              <span className="text-[10px] text-slate-400 font-mono">{isWsConnected ? 'LIVE' : 'SYNC'}</span>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="p-3 space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => handleNavClick(item.id)}
                  className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-xs font-medium transition-all duration-150 cursor-pointer ${
                    isActive
                      ? 'bg-gradient-to-r from-cyan-500/20 to-blue-600/10 text-cyan-400 border border-cyan-500/30 font-semibold shadow-sm shadow-cyan-500/10'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  }`}
                >
                  <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                  {item.label}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Global Purple-Team Trigger */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/60 space-y-3">
          <button
            onClick={handleRunScenario}
            disabled={runningScenario}
            className="w-full flex items-center justify-center gap-2 py-2.5 px-3 rounded-lg text-xs font-bold text-slate-950 bg-gradient-to-r from-cyan-400 to-blue-400 hover:from-cyan-300 hover:to-blue-300 transition shadow-lg shadow-cyan-500/25 disabled:opacity-50 cursor-pointer"
          >
            {runningScenario ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Simulating...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-slate-950" />
                <span>Run Purple-Team Lab</span>
              </>
            )}
          </button>
          <div className="flex items-center justify-between text-[10px] font-mono text-slate-500">
            <span>ISO 29147 & RFC 9116</span>
            <span className="text-cyan-500/80">v1.0.0</span>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Header Bar */}
        <header className="h-14 border-b border-slate-800 bg-slate-900/60 backdrop-blur px-6 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileMenuOpen(true)}
              className="md:hidden p-1.5 rounded-lg bg-slate-800 text-slate-300 hover:text-white"
            >
              <Menu className="w-5 h-5" />
            </button>
            <span className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-widest">
              Workspace &bull;{' '}
              <span className="text-cyan-400">
                {navItems.find((n) => n.id === activeTab)?.label || 'Overview'}
              </span>
            </span>
          </div>

          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 px-3 py-1 bg-slate-950 border border-slate-800 rounded-full text-xs font-mono">
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
              <span className="text-slate-300">Guard: RFC1918 Locked</span>
            </div>
          </div>
        </header>

        {/* Dynamic Page Views */}
        <main className="flex-1 overflow-y-auto p-6 bg-slate-950 relative">
          {children}
        </main>
      </div>

      {/* Scenario Orchestration Progress Modal */}
      {showScenarioModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl flex flex-col max-h-[85vh]">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/40">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-xl bg-cyan-950 border border-cyan-800 text-cyan-400">
                  <Activity className="w-5 h-5 animate-pulse" />
                </div>
                <div>
                  <h3 className="font-bold text-white text-base">Purple-Team Cyber Range Orchestrator</h3>
                  <p className="text-xs text-slate-400 font-mono">
                    {runningScenario ? 'Executing 6-Stage Autonomous Engagement...' : 'Execution Completed'}
                  </p>
                </div>
              </div>
              {!runningScenario && (
                <button
                  onClick={() => setShowScenarioModal(false)}
                  className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white transition"
                >
                  Close
                </button>
              )}
            </div>

            <div className="p-6 space-y-4 overflow-y-auto flex-1">
              {runningScenario && (
                <div className="flex flex-col items-center justify-center py-10 space-y-3">
                  <Loader2 className="w-10 h-10 text-cyan-400 animate-spin" />
                  <p className="text-sm font-medium text-slate-300">
                    Running live offensive probes and defensive mitigations across isolated mock targets...
                  </p>
                </div>
              )}

              {scenarioResult && (
                <div className="space-y-4">
                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs space-y-2">
                    <div className="flex justify-between font-mono text-slate-400">
                      <span>Scenario ID: {scenarioResult.scenario_id}</span>
                      <span>Total Steps: {scenarioResult.total_steps}</span>
                    </div>
                    <div className="text-white font-medium">{scenarioResult.final_report_summary}</div>
                  </div>

                  <div className="space-y-2">
                    <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">
                      Engaged Stages & Telemetry
                    </h4>
                    {scenarioResult.steps.map((st) => (
                      <div
                        key={st.step_id}
                        className="p-3 bg-slate-950/60 rounded-xl border border-slate-800/80 flex items-start gap-3"
                      >
                        <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                        <div className="space-y-1 text-xs">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-white">Stage {st.step_id}: {st.name}</span>
                            <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold bg-slate-900 text-cyan-400 border border-slate-800">
                              {st.module}
                            </span>
                          </div>
                          <p className="text-slate-400 leading-relaxed">{st.details}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
