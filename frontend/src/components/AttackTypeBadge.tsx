import React from 'react';
import clsx from 'clsx';
import { AttackType } from '../types';
import {
  AlertTriangle, UserX, KeyRound, Terminal, Lock,
  FileWarning, ShieldBan, Binary, Code2, CheckCircle2
} from 'lucide-react';

interface AttackTypeBadgeProps {
  type: AttackType | string;
  size?: 'sm' | 'md';
}

export default function AttackTypeBadge({ type, size = 'sm' }: AttackTypeBadgeProps) {
  const getConfig = () => {
    const rawStr = typeof type === 'string' ? type.toLowerCase().replace(/[\s-]/g, '_') : String(type || '');
    switch (rawStr) {
      case 'instruction_override':
      case AttackType.INSTRUCTION_OVERRIDE:
        return { label: 'Instruction Override', icon: AlertTriangle, color: 'text-[#E9B44C] bg-[rgba(233,180,76,0.12)] border-[rgba(233,180,76,0.25)]' };
      case 'role_change':
      case 'role_manipulation':
      case AttackType.ROLE_CHANGE:
        return { label: 'Role Manipulation', icon: UserX, color: 'text-[#9B72CF] bg-[rgba(155,114,207,0.12)] border-[rgba(155,114,207,0.25)]' };
      case 'secret_extraction':
      case AttackType.SECRET_EXTRACTION:
        return { label: 'Secret Extraction', icon: KeyRound, color: 'text-[#EF626F] bg-[rgba(239,98,111,0.12)] border-[rgba(239,98,111,0.25)]' };
      case 'tool_abuse':
      case AttackType.TOOL_ABUSE:
        return { label: 'Tool Abuse', icon: Terminal, color: 'text-[#F97316] bg-[rgba(249,115,22,0.12)] border-[rgba(249,115,22,0.25)]' };
      case 'credential_theft':
      case AttackType.CREDENTIAL_THEFT:
        return { label: 'Credential Theft', icon: Lock, color: 'text-[#EF626F] bg-[rgba(239,98,111,0.15)] border-[rgba(239,98,111,0.3)]' };
      case 'context_poisoning':
      case AttackType.CONTEXT_POISONING:
        return { label: 'RAG Poisoning', icon: FileWarning, color: 'text-[#E9B44C] bg-[rgba(233,180,76,0.12)] border-[rgba(233,180,76,0.25)]' };
      case 'multi_step_jailbreak':
      case AttackType.MULTI_STEP_JAILBREAK:
        return { label: 'Multi-Step Jailbreak', icon: ShieldBan, color: 'text-[#EF626F] bg-[rgba(239,98,111,0.15)] border-[rgba(239,98,111,0.3)]' };
      case 'encoded_instruction':
      case 'obfuscation':
      case AttackType.ENCODED_INSTRUCTION:
        return { label: 'Encoded / Obfuscated', icon: Binary, color: 'text-[#58A6E8] bg-[rgba(88,166,232,0.12)] border-[rgba(88,166,232,0.25)]' };
      case 'indirect_prompt_injection':
      case 'indirect_injection':
      case AttackType.INDIRECT_PROMPT_INJECTION:
        return { label: 'Indirect Injection', icon: Code2, color: 'text-[#58A6E8] bg-[rgba(88,166,232,0.12)] border-[rgba(88,166,232,0.25)]' };
      case 'clean':
      case 'none':
      case AttackType.NONE:
      default:
        if (rawStr && rawStr !== 'none' && rawStr !== 'clean') {
          return { label: rawStr.replace(/_/g, ' ').toUpperCase(), icon: AlertTriangle, color: 'text-[#EF626F] bg-[rgba(239,98,111,0.12)] border-[rgba(239,98,111,0.25)]' };
        }
        return { label: 'Clean / None', icon: CheckCircle2, color: 'text-[#35C98A] bg-[rgba(53,201,138,0.12)] border-[rgba(53,201,138,0.25)]' };
    }
  };

  const { label, icon: Icon, color } = getConfig();

  return (
    <span
      className={clsx(
        'inline-flex items-center rounded border font-medium select-none',
        color,
        size === 'sm' ? 'px-2 py-0.5 text-[11px] gap-1.5' : 'px-2.5 py-1 text-xs gap-2'
      )}
      role="status"
      aria-label={`Attack Type: ${label}`}
    >
      <Icon size={size === 'sm' ? 12 : 14} aria-hidden="true" className="shrink-0" />
      <span>{label}</span>
    </span>
  );
}
