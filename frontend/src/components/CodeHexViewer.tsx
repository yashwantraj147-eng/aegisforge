import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';

interface CodeHexViewerProps {
  hexData: string; // e.g. "90909031c0c3..."
  title?: string;
  bytesPerRow?: number;
  highlightBadchars?: string[];
}

export const CodeHexViewer: React.FC<CodeHexViewerProps> = ({
  hexData,
  title = 'Hexadecimal & ASCII Inspection',
  bytesPerRow = 16,
  highlightBadchars = ['00', '0a', '0d', '20'],
}) => {
  const [copied, setCopied] = useState(false);

  // Clean raw hex
  const cleanHex = hexData.replace(/[^0-9a-fA-F]/g, '');
  const bytes: string[] = [];
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes.push(cleanHex.substring(i, i + 2).toLowerCase());
  }

  // Group into rows
  const rows: Array<{ offset: string; hex: string[]; ascii: string }> = [];
  for (let i = 0; i < bytes.length; i += bytesPerRow) {
    const chunk = bytes.slice(i, i + bytesPerRow);
    const offsetStr = i.toString(16).padStart(4, '0').toUpperCase();
    
    // ASCII representation
    const asciiStr = chunk
      .map((b) => {
        const charCode = parseInt(b, 16);
        return charCode >= 32 && charCode <= 126 ? String.fromCharCode(charCode) : '.';
      })
      .join('');

    rows.push({ offset: offsetStr, hex: chunk, ascii: asciiStr });
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(cleanHex);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden font-mono text-xs shadow-inner">
      <div className="flex items-center justify-between bg-slate-900 px-3 py-2 border-b border-slate-800">
        <span className="font-semibold text-slate-300 tracking-wide text-xs">{title}</span>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1 px-2 py-0.5 rounded text-[11px] bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
        >
          {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
          {copied ? 'Copied' : 'Copy Hex'}
        </button>
      </div>

      <div className="p-3 overflow-x-auto max-h-[320px] divide-y divide-slate-900/60">
        {rows.length === 0 ? (
          <div className="py-6 text-center text-slate-500">No binary byte data provided.</div>
        ) : (
          rows.map((row, rIdx) => (
            <div key={rIdx} className="flex items-center py-1 hover:bg-slate-900/40 px-1 rounded">
              {/* Offset */}
              <span className="text-slate-500 select-none w-14 font-semibold">{row.offset}</span>

              {/* Hex bytes */}
              <div className="flex-1 flex gap-1.5 flex-wrap">
                {row.hex.map((b, bIdx) => {
                  const isBad = highlightBadchars.includes(b);
                  return (
                    <span
                      key={bIdx}
                      className={`px-1 py-0.5 rounded transition ${
                        isBad
                          ? 'bg-red-950 text-red-400 font-bold border border-red-800/80'
                          : b === '90'
                          ? 'bg-emerald-950 text-emerald-400 font-semibold'
                          : 'text-slate-300 hover:text-cyan-400'
                      }`}
                      title={isBad ? `Bad character detected: 0x${b}` : `Byte 0x${b}`}
                    >
                      {b}
                    </span>
                  );
                })}
              </div>

              {/* ASCII pane */}
              <span className="text-slate-400 pl-4 border-l border-slate-800 select-none tracking-widest text-[11px]">
                {row.ascii}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
