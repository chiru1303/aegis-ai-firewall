import React from 'react';
import clsx from 'clsx';
import { RiskLevel } from '../types';

interface RiskGaugeProps {
  score: number; // 0-100 or 0-1.0
  level?: RiskLevel | string;
  size?: number;
  showDetails?: boolean;
}

export default function RiskGauge({ score, level, size = 180, showDetails = true }: RiskGaugeProps) {
  // Normalize score to 0 - 100
  const normalizedScore = score > 1 ? Math.min(Math.max(score, 0), 100) : Math.min(Math.max(score * 100, 0), 100);

  const strokeWidth = size * 0.09;
  const radius = (size - strokeWidth) / 2;
  const circumference = radius * Math.PI; // Semicircle
  const strokeDashoffset = circumference - (normalizedScore / 100) * circumference;

  const getColor = () => {
    if (normalizedScore >= 80) return '#EF626F'; // Critical
    if (normalizedScore >= 50) return '#F97316'; // High
    if (normalizedScore >= 20) return '#E9B44C'; // Medium
    return '#35C98A'; // Low
  };

  const getLevelLabel = () => {
    if (level) return (level as string).toUpperCase();
    if (normalizedScore >= 80) return 'CRITICAL';
    if (normalizedScore >= 50) return 'HIGH';
    if (normalizedScore >= 20) return 'MEDIUM';
    return 'LOW';
  };

  const color = getColor();
  const levelText = getLevelLabel();

  return (
    <div
      className="flex flex-col items-center justify-center select-none"
      role="meter"
      aria-valuenow={Math.round(normalizedScore)}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label={`Risk score: ${normalizedScore.toFixed(1)} out of 100, ${levelText} risk`}
    >
      <div className="relative" style={{ width: size, height: size / 2 + 10 }}>
        <svg
          width={size}
          height={size / 2 + 10}
          viewBox={`0 0 ${size} ${size / 2 + 10}`}
          className="overflow-visible"
        >
          {/* Background track */}
          <path
            d={`M ${strokeWidth / 2} ${size / 2} A ${radius} ${radius} 0 0 1 ${size - strokeWidth / 2} ${size / 2}`}
            fill="none"
            stroke="#1D2738"
            strokeWidth={strokeWidth}
            strokeLinecap="round"
          />
          {/* Progress arc */}
          <path
            d={`M ${strokeWidth / 2} ${size / 2} A ${radius} ${radius} 0 0 1 ${size - strokeWidth / 2} ${size / 2}`}
            fill="none"
            stroke={color}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            className="transition-all duration-500 ease-out"
          />
        </svg>

        {/* Center Readout */}
        <div className="absolute inset-x-0 bottom-0 flex flex-col items-center justify-end text-center">
          <span className="text-3xl font-bold font-mono tracking-tight text-[#F4F7FB]">
            {normalizedScore.toFixed(1)}
          </span>
          <span className="text-[10px] font-mono text-[#8F9BAD] uppercase tracking-wider">
            / 100
          </span>
        </div>
      </div>

      {showDetails && (
        <div className="mt-2 flex items-center gap-1.5 font-mono text-xs font-semibold uppercase tracking-wider" style={{ color }}>
          <span className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
          <span>{levelText} RISK</span>
        </div>
      )}
    </div>
  );
}
