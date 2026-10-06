import React from 'react';
import clsx from 'clsx';
import { Decision } from '../types';
import { CheckCircle2, ShieldBan, ShieldAlert, Eye, Sliders } from 'lucide-react';

interface DecisionBadgeProps {
  decision: Decision | string;
  showIcon?: boolean;
  size?: 'sm' | 'md' | 'lg';
}

export default function DecisionBadge({ decision, showIcon = true, size = 'sm' }: DecisionBadgeProps) {
  const norm = (decision || '').toLowerCase().replace(/_/g, ' ');

  const getBadgeConfig = () => {
    switch (decision?.toLowerCase()) {
      case Decision.ALLOW:
      case 'allow':
        return {
          label: 'ALLOW',
          icon: CheckCircle2,
          className: 'bg-[rgba(53,201,138,0.12)] text-[#35C98A] border-[rgba(53,201,138,0.3)]',
        };
      case Decision.BLOCK:
      case 'block':
        return {
          label: 'BLOCK',
          icon: ShieldBan,
          className: 'bg-[rgba(239,98,111,0.12)] text-[#EF626F] border-[rgba(239,98,111,0.3)]',
        };
      case Decision.SANITIZE:
      case 'sanitize':
        return {
          label: 'SANITIZE',
          icon: Sliders,
          className: 'bg-[rgba(233,180,76,0.12)] text-[#E9B44C] border-[rgba(233,180,76,0.3)]',
        };
      case Decision.QUARANTINE:
      case 'quarantine':
        return {
          label: 'QUARANTINE',
          icon: ShieldAlert,
          className: 'bg-[rgba(155,114,207,0.12)] text-[#9B72CF] border-[rgba(155,114,207,0.3)]',
        };
      case Decision.REQUIRE_REVIEW:
      case 'require_review':
        return {
          label: 'REVIEW',
          icon: Eye,
          className: 'bg-[rgba(88,166,232,0.12)] text-[#58A6E8] border-[rgba(88,166,232,0.3)]',
        };
      default:
        return {
          label: norm.toUpperCase() || 'UNKNOWN',
          icon: CheckCircle2,
          className: 'bg-[#172033] text-[#C0C8D6] border-[#263247]',
        };
    }
  };

  const { label, icon: Icon, className } = getBadgeConfig();

  const sizeClasses = {
    sm: 'px-2 py-0.5 text-[11px] gap-1 font-semibold tracking-wide',
    md: 'px-2.5 py-1 text-xs gap-1.5 font-bold tracking-wide',
    lg: 'px-3 py-1.5 text-sm gap-2 font-bold tracking-wider',
  };

  const iconSizes = {
    sm: 12,
    md: 14,
    lg: 16,
  };

  return (
    <span
      className={clsx(
        'inline-flex items-center rounded border uppercase font-mono select-none',
        className,
        sizeClasses[size]
      )}
      role="status"
      aria-label={`Decision: ${label}`}
    >
      {showIcon && <Icon size={iconSizes[size]} aria-hidden="true" className="shrink-0" />}
      <span>{label}</span>
    </span>
  );
}
