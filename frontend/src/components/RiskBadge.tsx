import React from 'react';

export type SeverityOrRisk = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'MODERATE' | 'LOW' | 'INFO';

interface RiskBadgeProps {
  level: SeverityOrRisk | string;
  score?: number;
  size?: 'sm' | 'md' | 'lg';
  showDot?: boolean;
  className?: string;
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({
  level,
  score,
  size = 'md',
  showDot = false,
  className = '',
}) => {
  const normLevel = (level || 'LOW').toUpperCase();

  const colorMap: Record<string, { bg: string; text: string; border: string; dot: string }> = {
    CRITICAL: {
      bg: 'rgba(239, 68, 68, 0.15)',
      text: '#f87171',
      border: 'rgba(239, 68, 68, 0.4)',
      dot: '#ef4444',
    },
    HIGH: {
      bg: 'rgba(249, 115, 22, 0.15)',
      text: '#fb923c',
      border: 'rgba(249, 115, 22, 0.4)',
      dot: '#f97316',
    },
    MEDIUM: {
      bg: 'rgba(245, 158, 11, 0.15)',
      text: '#fbbf24',
      border: 'rgba(245, 158, 11, 0.4)',
      dot: '#f59e0b',
    },
    MODERATE: {
      bg: 'rgba(245, 158, 11, 0.15)',
      text: '#fbbf24',
      border: 'rgba(245, 158, 11, 0.4)',
      dot: '#f59e0b',
    },
    LOW: {
      bg: 'rgba(59, 130, 246, 0.15)',
      text: '#60a5fa',
      border: 'rgba(59, 130, 246, 0.4)',
      dot: '#3b82f6',
    },
    INFO: {
      bg: 'rgba(6, 182, 212, 0.15)',
      text: '#22d3ee',
      border: 'rgba(6, 182, 212, 0.4)',
      dot: '#06b6d4',
    },
  };

  const style = colorMap[normLevel] || colorMap.LOW;

  const sizeStyles = {
    sm: 'text-xs px-2 py-0.5 gap-1',
    md: 'text-xs px-2.5 py-1 gap-1.5 font-medium',
    lg: 'text-sm px-3.5 py-1.5 gap-2 font-semibold',
  };

  return (
    <span
      className={`inline-flex items-center rounded-full border tracking-wide font-mono transition-all ${sizeStyles[size]} ${className}`}
      style={{
        backgroundColor: style.bg,
        color: style.text,
        borderColor: style.border,
      }}
    >
      {showDot && (
        <span
          className="w-1.5 h-1.5 rounded-full animate-pulse"
          style={{ backgroundColor: style.dot }}
        />
      )}
      <span>{normLevel}</span>
      {score !== undefined && (
        <span className="opacity-90 font-bold ml-0.5">({score})</span>
      )}
    </span>
  );
};
