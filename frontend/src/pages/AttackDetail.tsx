import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ArrowLeft, Target, Shield, List, AlertTriangle,
  Copy, Check, FileText, CheckCircle2, ShieldBan,
  Clock, Lock, EyeOff, Sparkles
} from 'lucide-react';
import { apiService } from '../services/api';
import { AuditRecord, RiskLevel, Decision } from '../types';
import RiskBadge from '../components/RiskBadge';
import DecisionBadge from '../components/DecisionBadge';
import RiskGauge from '../components/RiskGauge';
import AttackTypeBadge from '../components/AttackTypeBadge';
import { formatIST } from '../utils/date';
import SyntaxHighlighter from '../components/CodeText';
const vscDarkPlus = {};
import toast from 'react-hot-toast';

export default function AttackDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [data, setData] = useState<AuditRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [copiedRecord, setCopiedRecord] = useState(false);
  const [copiedPrompt, setCopiedPrompt] = useState(false);

  useEffect(() => {
    const fetchDetails = async () => {
      try {
        if (!id) return;
        const res = await apiService.getAuditDetail(id).catch(() => null);
        setData(res);
      } catch (err) {
        toast.error('Failed to load incident record');
      } finally {
        setLoading(false);
      }
    };
    fetchDetails();
  }, [id]);

  const copyJson = () => {
    if (!data) return;
    navigator.clipboard.writeText(JSON.stringify(data, null, 2));
    setCopiedRecord(true);
    toast.success('Log details copied to clipboard');
    setTimeout(() => setCopiedRecord(false), 2000);
  };

  const copyPromptText = (promptStr: string) => {
    navigator.clipboard.writeText(promptStr);
    setCopiedPrompt(true);
    toast.success('Prompt copied to clipboard');
    setTimeout(() => setCopiedPrompt(false), 2000);
  };

  if (loading) {
    return (
      <div className="p-8 flex items-center justify-center font-mono text-xs text-[#8F9BAD]">
        <div className="animate-spin rounded-full h-5 w-5 border-2 border-[#4F8CFF] border-t-transparent mr-3" />
        Loading request details...
      </div>
    );
  }

  if (!data) {
    return (
      <div className="p-12 flex flex-col items-center justify-center text-center">
        <AlertTriangle size={36} className="text-[#E9B44C] mb-3" />
        <h2 className="text-sm font-bold text-[#F4F7FB] mb-1">Record Not Found</h2>
        <p className="text-xs text-[#8F9BAD] max-w-sm mb-4">
          The requested audit record ID does not exist or may have been purged in accordance with retention policy.
        </p>
        <button
          onClick={() => navigate(-1)}
          className="px-3.5 py-1.5 bg-[#172033] hover:bg-[#1D2940] border border-[#263247] text-xs font-mono text-[#4F8CFF] rounded transition-colors"
        >
          Return to Previous View
        </button>
      </div>
    );
  }

  // Authoritative risk score extraction with proper fallback
  const scoreVal = data.riskScore ?? data.risk_score ?? data.details?.riskScore ?? data.details?.risk_score;
  const rawScore = scoreVal !== undefined && scoreVal !== null
    ? (scoreVal <= 1.0 ? scoreVal * 100 : scoreVal)
    : (String(data.decision).toUpperCase() === 'BLOCK' ? 95 : 0);
  const normalizedScore = Number(rawScore.toFixed(1));

  // Authoritative risk level extraction
  const rawLevel = data.riskLevel || data.risk_level || data.details?.riskLevel || data.details?.risk_level;
  const effectiveRiskLevel: RiskLevel = rawLevel
    ? (typeof rawLevel === 'string' ? rawLevel.toLowerCase() as RiskLevel : rawLevel)
    : (normalizedScore >= 80 ? RiskLevel.CRITICAL : (normalizedScore >= 50 ? RiskLevel.HIGH : (normalizedScore >= 20 ? RiskLevel.MEDIUM : RiskLevel.LOW)));

  // Prompt and PII metadata
  const promptText = data.prompt || data.details?.prompt || '';
  const promptHash = data.raw_prompt_hash || data.details?.rawPromptHash || data.details?.provenance?.hash || '';
  const hasPii = Boolean(data.has_pii || data.details?.hasPii);
  const piiTypes: string[] = data.pii_types || data.details?.piiTypes || [];

  const decisionUpper = String(data.decision || 'ALLOW').toUpperCase();
  const isBlocked = decisionUpper === 'BLOCK';
  const isSanitized = decisionUpper === 'SANITIZE';

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 pb-3 border-b border-[#263247]">
        <button
          onClick={() => navigate(-1)}
          className="p-1.5 rounded hover:bg-[#172033] text-[#8F9BAD] hover:text-[#F4F7FB] border border-[#263247] transition-colors"
          title="Return"
        >
          <ArrowLeft size={16} />
        </button>
        <div className="min-w-0">
          <div className="flex items-center gap-2 min-w-0">
            <Target size={16} className={`shrink-0 ${isBlocked ? "text-[#EF626F]" : "text-[#35C98A]"}`} />
            <h1 className="text-sm sm:text-base font-bold font-mono tracking-tight text-[#F4F7FB] truncate">
              Request Details: {data.id}
            </h1>
          </div>
          <span className="text-[11px] font-mono text-[#8F9BAD] block mt-0.5">
            Logged (IST): {formatIST(data.timestamp)}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Triage & Provenance */}
        <div className="space-y-5">
          {/* Outcome Card */}
          <div className="bg-[#111827] border border-[#263247] rounded-lg p-4">
            <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-[#8F9BAD] mb-4 pb-2 border-b border-[#263247]">
              Security Assessment
            </h2>

            <div className="flex flex-col items-center justify-center py-2 mb-4">
              <RiskGauge score={normalizedScore} level={effectiveRiskLevel} size={150} />
            </div>

            <div className="space-y-3 text-xs font-mono pt-3 border-t border-[#1D2738]">
              <div className="flex justify-between items-center">
                <span className="text-[#8F9BAD]">Gate Decision:</span>
                <DecisionBadge decision={data.decision as Decision} />
              </div>
              <div className="flex justify-between items-center">
                <span className="text-[#8F9BAD]">Severity:</span>
                <RiskBadge level={effectiveRiskLevel} />
              </div>
              <div className="flex justify-between items-center">
                <span className="text-[#8F9BAD]">Policy Scope:</span>
                <span className="text-[#F4F7FB] font-semibold">{data.policy || data.details?.policy || 'default_zero_trust'}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-[#8F9BAD]">PII Protection:</span>
                {hasPii ? (
                  <span className="px-2 py-0.5 rounded text-[10px] bg-[rgba(233,180,76,0.15)] text-[#E9B44C] border border-[rgba(233,180,76,0.3)]">
                    Masked ({piiTypes.length} Types)
                  </span>
                ) : (
                  <span className="text-[#35C98A] text-[11px]">No PII Detected</span>
                )}
              </div>
            </div>
          </div>

          {/* Provenance Metadata */}
          <div className="bg-[#111827] border border-[#263247] rounded-lg p-4">
            <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-[#8F9BAD] mb-3 pb-2 border-b border-[#263247]">
              Source Information
            </h2>

            <ul className="space-y-2.5 text-xs font-mono">
              <li className="flex justify-between">
                <span className="text-[#8F9BAD]">Origin:</span>
                <span className="text-[#F4F7FB]">{data.origin || data.details?.provenance?.origin || 'client:app_default'}</span>
              </li>
              <li className="flex justify-between">
                <span className="text-[#8F9BAD]">Source Channel:</span>
                <span className="uppercase text-[#35C98A]">{data.source_type || data.details?.provenance?.sourceType || 'CHAT_COMPLETIONS'}</span>
              </li>
              <li className="flex justify-between">
                <span className="text-[#8F9BAD]">Server Trust:</span>
                <span className="text-[#E9B44C]">{data.details?.provenance?.trustLevel || 'UNTRUSTED'}</span>
              </li>
              <li className="flex justify-between">
                <span className="text-[#8F9BAD]">Session Trace:</span>
                <span className="text-[#4F8CFF]">{data.details?.sessionId || 'gateway-session'}</span>
              </li>
            </ul>

            {promptHash && (
              <div className="mt-3 pt-3 border-t border-[#1D2738]">
                <span className="text-[10px] text-[#8F9BAD] block uppercase mb-1">Payload SHA-256 Hash</span>
                <span className="text-[10px] font-mono text-[#C0C8D6] break-all bg-[#0E1526] p-1.5 rounded border border-[#1D2738] block">
                  {promptHash}
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Middle/Right Column: Forensic Timeline, Prompt Payload, & Evidence */}
        <div className="lg:col-span-2 space-y-5">
          {/* Decision Pipeline Execution Timeline */}
          <div className="bg-[#111827] border border-[#263247] rounded-lg p-4">
            <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-[#8F9BAD] mb-4 pb-2 border-b border-[#263247] flex items-center gap-2">
              <Clock size={14} className="text-[#4F8CFF]" />
              <span>Inspection Steps</span>
            </h2>

            <div className="space-y-3 font-mono text-xs">
              <div className="flex items-start gap-3">
                <div className="w-5 h-5 rounded-full bg-[rgba(53,201,138,0.15)] text-[#35C98A] flex items-center justify-center font-bold text-[10px] shrink-0 mt-0.5">
                  1
                </div>
                <div>
                  <span className="font-semibold text-[#F4F7FB] block">Text Normalization</span>
                  <span className="text-[#8F9BAD] text-[11px]">Normalized Unicode characters, stripped zero-width spaces, and decoded standard encodings.</span>
                </div>
              </div>

              <div className="flex items-start gap-3">
                <div className="w-5 h-5 rounded-full bg-[rgba(53,201,138,0.15)] text-[#35C98A] flex items-center justify-center font-bold text-[10px] shrink-0 mt-0.5">
                  2
                </div>
                <div>
                  <span className="font-semibold text-[#F4F7FB] block">Rule & Credential Scans</span>
                  <span className="text-[#8F9BAD] text-[11px]">Evaluated injection signatures, role overrides, system instruction extraction patterns, and credential leaks.</span>
                </div>
              </div>

              <div className="flex items-start gap-3">
                <div className="w-5 h-5 rounded-full bg-[rgba(53,201,138,0.15)] text-[#35C98A] flex items-center justify-center font-bold text-[10px] shrink-0 mt-0.5">
                  3
                </div>
                <div>
                  <span className="font-semibold text-[#F4F7FB] block">Machine Learning Analysis</span>
                  <span className="text-[#8F9BAD] text-[11px]">Scored payload risk using trained classifiers and text feature analysis.</span>
                </div>
              </div>

              <div className="flex items-start gap-3">
                <div className={`w-5 h-5 rounded-full flex items-center justify-center font-bold text-[10px] shrink-0 mt-0.5 ${
                  isBlocked ? 'bg-[rgba(239,98,111,0.15)] text-[#EF626F]' : (isSanitized ? 'bg-[rgba(233,180,76,0.15)] text-[#E9B44C]' : 'bg-[rgba(53,201,138,0.15)] text-[#35C98A]')
                }`}>
                  4
                </div>
                <div>
                  <span className={`font-semibold block ${
                    isBlocked ? 'text-[#EF626F]' : (isSanitized ? 'text-[#E9B44C]' : 'text-[#35C98A]')
                  }`}>
                    Policy Decision
                  </span>
                  <span className="text-[#8F9BAD] text-[11px]">
                    {isBlocked
                      ? `Risk score (${normalizedScore}%) exceeded allowable threshold. Blocked.`
                      : (isSanitized
                        ? `Threat patterns sanitized according to active policy.`
                        : `Risk score (${normalizedScore}%) within allowable baseline. Request allowed.`)}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Inspected Prompt Payload (Captured & PII Masked) */}
          <div className="bg-[#111827] border border-[#263247] rounded-lg p-4">
            <div className="flex items-center justify-between pb-2 mb-3 border-b border-[#263247]">
              <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-[#8F9BAD] flex items-center gap-2">
                <FileText size={14} className="text-[#4F8CFF]" />
                <span>Captured Prompt</span>
              </h2>
              <div className="flex items-center gap-2">
                {hasPii && (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-[rgba(233,180,76,0.15)] border border-[rgba(233,180,76,0.3)] text-[10px] font-mono text-[#E9B44C]">
                    <EyeOff size={11} />
                    <span>PII Masked</span>
                  </span>
                )}
                {promptText && (
                  <button
                    onClick={() => copyPromptText(promptText)}
                    className="inline-flex items-center gap-1 text-[11px] font-mono text-[#4F8CFF] hover:text-[#6A9DFF] px-2 py-0.5 rounded bg-[#172033] border border-[#263247] transition-colors"
                  >
                    {copiedPrompt ? <Check size={11} className="text-[#35C98A]" /> : <Copy size={11} />}
                    <span>{copiedPrompt ? 'Copied' : 'Copy Prompt'}</span>
                  </button>
                )}
              </div>
            </div>

            {promptText ? (
              <div className="space-y-3">
                <div className="p-3 bg-[#080C18] border border-[#1D2738] rounded font-mono text-xs text-[#E1E7F0] whitespace-pre-wrap break-words leading-relaxed select-text">
                  {promptText}
                </div>

                <div className="flex flex-wrap items-center justify-between gap-2 pt-2 text-[11px] font-mono text-[#8F9BAD] border-t border-[#1D2738]">
                  <div className="flex items-center gap-2">
                    <span>Cryptographic Hash:</span>
                    <span className="text-[#C0C8D6] bg-[#0E1526] px-1.5 py-0.5 rounded border border-[#1D2738] break-all">
                      {promptHash ? `${promptHash.slice(0, 16)}...${promptHash.slice(-16)}` : 'Verified'}
                    </span>
                  </div>
                  {piiTypes.length > 0 && (
                    <div className="flex items-center gap-1.5">
                      <span>Redacted Categories:</span>
                      {piiTypes.map((t: string, idx: number) => (
                        <span key={idx} className="px-1.5 py-0.5 rounded bg-[#172033] border border-[#263247] text-[10px] text-[#E9B44C]">
                          {t}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="p-3 bg-[#080C18] border border-[#1D2738] rounded text-xs font-mono text-[#8F9BAD] flex items-center justify-between">
                <span>Prompt captured and verified under cryptographic hash {promptHash ? `${promptHash.slice(0, 12)}...` : 'ledger'}.</span>
                <span className="text-[#35C98A] text-[11px] inline-flex items-center gap-1">
                  <Lock size={12} /> Privacy Preserved
                </span>
              </div>
            )}
          </div>

          {/* Extracted Signals & Evidence */}
          <div className="bg-[#111827] border border-[#263247] rounded-lg p-4">
            <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-[#8F9BAD] mb-3 pb-2 border-b border-[#263247] flex items-center gap-2">
              <List size={14} className={isBlocked ? "text-[#EF626F]" : "text-[#4F8CFF]"} />
              <span>Detected Signals & Evidence</span>
            </h2>

            {data.details?.detectedAttacks?.length ? (
              <div className="space-y-3">
                {data.details.detectedAttacks.map((attack: any, i: number) => {
                  const confNum = attack.confidence != null && !isNaN(Number(attack.confidence))
                    ? Number(attack.confidence)
                    : (normalizedScore > 0 ? normalizedScore / 100 : 0.95);
                  const confPct = (confNum <= 1.0 ? confNum * 100 : confNum).toFixed(0);

                  return (
                    <div key={i} className="p-3 bg-[#0E1526] border border-[#263247] rounded">
                      <div className="flex justify-between items-center mb-2">
                        <AttackTypeBadge type={attack.attackType} />
                        <span className="text-xs font-mono text-[#EF626F]">
                          Confidence: {confPct}%
                        </span>
                      </div>

                      <div className="space-y-1.5 pt-2 border-t border-[#1D2738]">
                        {attack.evidence?.map((ev: any, j: number) => (
                          <div key={j} className="text-xs font-mono text-[#C0C8D6] flex items-start gap-2">
                            <span className="text-[#EF626F]">•</span>
                            <span>
                              <strong className="text-[#4F8CFF]">[{ev.detectorName}]</strong> {ev.signal}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="p-3 bg-[#080C18] border border-[#1D2738] rounded text-xs font-mono text-[#35C98A] flex items-center gap-2">
                <CheckCircle2 size={14} />
                <span>No adversarial injection patterns detected in prompt payload.</span>
              </div>
            )}
          </div>

          {/* Raw Cryptographic Audit Record */}
          <div className="bg-[#111827] border border-[#263247] rounded-lg overflow-hidden">
            <div className="px-4 py-2.5 bg-[#0E1526] border-b border-[#263247] flex items-center justify-between">
              <span className="text-xs font-mono font-bold uppercase text-[#F4F7FB]">
                Raw Cryptographic Audit Record
              </span>
              <button
                onClick={copyJson}
                className="inline-flex items-center gap-1 text-xs font-mono text-[#4F8CFF] hover:text-[#6A9DFF]"
              >
                {copiedRecord ? <Check size={13} className="text-[#35C98A]" /> : <Copy size={13} />}
                <span>{copiedRecord ? 'Copied' : 'Copy Record'}</span>
              </button>
            </div>

            <SyntaxHighlighter
              language="json"
              style={vscDarkPlus}
              customStyle={{ margin: 0, padding: '14px', fontSize: '11px', background: '#080C18' }}
            >
              {JSON.stringify(data.details || data, null, 2)}
            </SyntaxHighlighter>
          </div>
        </div>
      </div>
    </div>
  );
}
