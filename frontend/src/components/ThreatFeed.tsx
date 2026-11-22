import React, { useState } from 'react';
import { TelemetryEvent } from '../lib/ws';
import { AlertCircle, AlertTriangle, Info, ShieldAlert, CheckCircle2, Trash2, Filter } from 'lucide-react';

interface ThreatFeedProps {
  events: TelemetryEvent[];
  onClear: () => void;
}

export const ThreatFeed: React.FC<ThreatFeedProps> = ({ events, onClear }) => {
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');

  const filteredEvents = events.filter((e) => {
    if (filterSeverity === 'ALL') return true;
    return e.severity === filterSeverity;
  });

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-bold bg-red-950 text-red-400 border border-red-800 animate-pulse">
            <ShieldAlert className="w-3 h-3" /> CRITICAL
          </span>
        );
      case 'HIGH':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-orange-950 text-orange-400 border border-orange-800">
            <AlertTriangle className="w-3 h-3" /> HIGH
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-amber-950 text-amber-300 border border-amber-800">
            <AlertCircle className="w-3 h-3" /> MEDIUM
          </span>
        );
      case 'LOW':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-blue-950 text-blue-300 border border-blue-800">
            <Info className="w-3 h-3" /> LOW
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs text-slate-400 bg-slate-900 border border-slate-800">
            <Info className="w-3 h-3" /> INFO
          </span>
        );
    }
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col h-full shadow-lg">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <div className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping" />
          <h3 className="font-semibold text-slate-100 tracking-wide text-sm flex items-center gap-2">
            Live Threat & Telemetry Feed
            <span className="text-xs font-normal text-slate-500">({filteredEvents.length} events)</span>
          </h3>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1 bg-slate-950 px-2 py-1 rounded border border-slate-800 text-xs text-slate-300">
            <Filter className="w-3 h-3 text-slate-400" />
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="bg-transparent border-none text-xs focus:outline-none cursor-pointer"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="INFO">Info</option>
            </select>
          </div>
          <button
            onClick={onClear}
            className="p-1 hover:bg-slate-800 rounded text-slate-400 hover:text-red-400 transition"
            title="Clear Feed"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto mt-3 space-y-2 pr-1 font-mono text-xs max-h-[400px]">
        {filteredEvents.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 text-slate-500 text-center">
            <CheckCircle2 className="w-8 h-8 mb-2 text-slate-600 stroke-[1.5]" />
            <p>No telemetry events logged yet.</p>
            <p className="text-[11px] text-slate-600 mt-1">Run a scenario or module probe to populate the bus.</p>
          </div>
        ) : (
          filteredEvents.map((evt, idx) => (
            <div
              key={idx}
              className="p-2.5 bg-slate-950/60 rounded-lg border border-slate-800/80 hover:border-slate-700 transition space-y-1.5"
            >
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  {getSeverityBadge(evt.severity)}
                  <span className="text-[10px] font-bold text-cyan-400 uppercase tracking-wider bg-cyan-950/50 px-1.5 py-0.5 rounded border border-cyan-800/40">
                    {evt.module}
                  </span>
                </div>
                <span className="text-[10px] text-slate-500">
                  {new Date(evt.timestamp).toLocaleTimeString()}
                </span>
              </div>
              <p className="text-slate-200 text-xs font-sans leading-relaxed">{evt.message}</p>
              {evt.data && Object.keys(evt.data).length > 0 && (
                <div className="text-[10px] text-slate-400 bg-slate-900/80 p-1.5 rounded border border-slate-800 overflow-x-auto">
                  {JSON.stringify(evt.data)}
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
};
