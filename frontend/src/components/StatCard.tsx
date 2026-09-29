import React from 'react';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon?: LucideIcon;
  variant?: 'cyan' | 'red' | 'orange' | 'amber' | 'blue' | 'emerald' | 'purple';
  trend?: {
    value: string;
    isPositive?: boolean;
  };
  onClick?: () => void;
  className?: string;
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  variant = 'cyan',
  trend,
  onClick,
  className = '',
}) => {
  const variantStyles: Record<string, { border: string; glow: string; text: string; bgIcon: string }> = {
    cyan:    { border: 'border-cyan-500/30 hover:border-cyan-500/60', glow: 'shadow-cyan-500/5', text: 'text-cyan-400', bgIcon: 'bg-cyan-500/10 text-cyan-400' },
    red:     { border: 'border-rose-500/30 hover:border-rose-500/60', glow: 'shadow-rose-500/5', text: 'text-rose-400', bgIcon: 'bg-rose-500/10 text-rose-400' },
    orange:  { border: 'border-orange-500/30 hover:border-orange-500/60', glow: 'shadow-orange-500/5', text: 'text-orange-400', bgIcon: 'bg-orange-500/10 text-orange-400' },
    amber:   { border: 'border-amber-500/30 hover:border-amber-500/60', glow: 'shadow-amber-500/5', text: 'text-amber-400', bgIcon: 'bg-amber-500/10 text-amber-400' },
    blue:    { border: 'border-blue-500/30 hover:border-blue-500/60', glow: 'shadow-blue-500/5', text: 'text-blue-400', bgIcon: 'bg-blue-500/10 text-blue-400' },
    emerald: { border: 'border-emerald-500/30 hover:border-emerald-500/60', glow: 'shadow-emerald-500/5', text: 'text-emerald-400', bgIcon: 'bg-emerald-500/10 text-emerald-400' },
    purple:  { border: 'border-purple-500/30 hover:border-purple-500/60', glow: 'shadow-purple-500/5', text: 'text-purple-400', bgIcon: 'bg-purple-500/10 text-purple-400' },
  };

  const style = variantStyles[variant] || variantStyles.cyan;

  return (
    <div
      onClick={onClick}
      className={`p-4 rounded-xl bg-slate-900/80 border ${style.border} shadow-lg ${style.glow} transition-all duration-200 ${
        onClick ? 'cursor-pointer hover:-translate-y-0.5' : ''
      } ${className}`}
    >
      <div className="flex items-start justify-between gap-3 mb-2">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          {title}
        </span>
        {Icon && (
          <div className={`p-2 rounded-lg ${style.bgIcon}`}>
            <Icon size={16} />
          </div>
        )}
      </div>

      <div className="flex items-baseline gap-2 mb-1">
        <span className={`text-2xl font-bold font-mono tracking-tight ${style.text}`}>
          {value}
        </span>
        {trend && (
          <span
            className={`text-xs font-mono font-medium ${
              trend.isPositive ? 'text-emerald-400' : 'text-rose-400'
            }`}
          >
            {trend.value}
          </span>
        )}
      </div>

      {subtitle && (
        <p className="text-[11px] text-slate-400 line-clamp-1">{subtitle}</p>
      )}
    </div>
  );
};
