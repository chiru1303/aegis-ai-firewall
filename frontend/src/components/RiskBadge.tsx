import React from 'react';
import clsx from 'clsx';
import { RiskLevel } from '../types';
import { ShieldCheck, AlertCircle, AlertTriangle, ShieldAlert } from 'lucide-react';

interface RiskBadgeProps {
  level: RiskLevel | string;
  size?: 'sm' | 'md';
}

export default function RiskBadge({ level, size = 'sm' }: RiskBadgeProps) {
  const norm = (level || '').toLowerCase();

  const getConfig = () => {
    switch (norm) {
      case 'low':
      case RiskLevel.LOW:
        return {
          label: 'LOW',
          icon: ShieldCheck,
          className: 'bg-[rgba(53,201,138,0.12)] text-[#35C98A] border-[rgba(53,201,138,0.3)]',
        };
      case 'medium':
      case RiskLevel.MEDIUM:
        return {
          label: 'MEDIUM',
          icon: AlertCircle,
          className: 'bg-[rgba(233,180,76,0.12)] text-[#E9B44C] border-[rgba(233,180,76,0.3)]',
        };
      case 'high':
      case RiskLevel.HIGH:
        return {
          label: 'HIGH',
          icon: AlertTriangle,
          className: 'bg-[rgba(249,115,22,0.12)] text-[#F97316] border-[rgba(249,115,22,0.3)]',
        };
      case 'critical':
      case RiskLevel.CRITICAL:
        return {
          label: 'CRITICAL',
          icon: ShieldAlert,
          className: 'bg-[rgba(239,98,111,0.15)] text-[#EF626F] border-[rgba(239,98,111,0.35)]',
        };
      default:
        return {
          label: norm.toUpperCase() || 'UNKNOWN',
          icon: ShieldCheck,
          className: 'bg-[#172033] text-[#C0C8D6] border-[#263247]',
        };
    }
  };

  const { label, icon: Icon, className } = getConfig();

  return (
    <span
      className={clsx(
        'inline-flex items-center rounded border font-mono font-semibold uppercase tracking-wide select-none',
        className,
        size === 'sm' ? 'px-2 py-0.5 text-[11px] gap-1' : 'px-2.5 py-1 text-xs gap-1.5'
      )}
      role="status"
      aria-label={`Risk Level: ${label}`}
    >
      <Icon size={size === 'sm' ? 12 : 14} aria-hidden="true" className="shrink-0" />
      <span>{label}</span>
    </span>
  );
}
