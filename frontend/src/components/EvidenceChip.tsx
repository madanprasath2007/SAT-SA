import React, { useState } from 'react';
import { ExternalLink, Copy, Check } from 'lucide-react';

interface EvidenceChipProps {
  id: string;
  type?: 'alert' | 'ip' | 'asset' | 'user' | 'case' | 'cve' | 'hash';
  label?: string;
  onClick?: () => void;
  showCopy?: boolean;
  className?: string;
}

export const EvidenceChip: React.FC<EvidenceChipProps> = ({
  id,
  type = 'alert',
  label,
  onClick,
  showCopy = true,
  className = '',
}) => {
  const [copied, setCopied] = useState(false);

  const typeConfig: Record<string, { prefix: string; bg: string; text: string; border: string }> = {
    alert: { prefix: 'ALT', bg: 'rgba(6, 182, 212, 0.12)', text: '#22d3ee', border: 'rgba(6, 182, 212, 0.3)' },
    ip:    { prefix: 'IP',  bg: 'rgba(239, 68, 68, 0.12)',  text: '#f87171', border: 'rgba(239, 68, 68, 0.3)' },
    asset: { prefix: 'HST', bg: 'rgba(168, 85, 247, 0.12)', text: '#c084fc', border: 'rgba(168, 85, 247, 0.3)' },
    user:  { prefix: 'USR', bg: 'rgba(59, 130, 246, 0.12)', text: '#60a5fa', border: 'rgba(59, 130, 246, 0.3)' },
    case:  { prefix: 'CAS', bg: 'rgba(245, 158, 11, 0.12)', text: '#fbbf24', border: 'rgba(245, 158, 11, 0.3)' },
    cve:   { prefix: 'CVE', bg: 'rgba(236, 72, 153, 0.12)', text: '#f472b6', border: 'rgba(236, 72, 153, 0.3)' },
    hash:  { prefix: 'SHA', bg: 'rgba(16, 185, 129, 0.12)', text: '#34d399', border: 'rgba(16, 185, 129, 0.3)' },
  };

  const cfg = typeConfig[type] || typeConfig.alert;

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(id);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <span
      onClick={onClick}
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md border font-mono text-xs transition-colors duration-150 select-all ${
        onClick ? 'cursor-pointer hover:brightness-125' : ''
      } ${className}`}
      style={{
        backgroundColor: cfg.bg,
        color: cfg.text,
        borderColor: cfg.border,
      }}
      title={`Click to inspect ${id}`}
    >
      <span className="opacity-60 text-[10px] uppercase font-bold tracking-wider">
        {label || cfg.prefix}
      </span>
      <span className="font-semibold">{id}</span>
      {showCopy && (
        <button
          type="button"
          onClick={handleCopy}
          className="p-0.5 hover:text-white transition-opacity opacity-60 hover:opacity-100"
          title="Copy ID"
        >
          {copied ? <Check size={11} className="text-emerald-400" /> : <Copy size={11} />}
        </button>
      )}
      {onClick && (
        <ExternalLink size={11} className="opacity-60 hover:opacity-100" />
      )}
    </span>
  );
};
