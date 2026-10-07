import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Target, AlertTriangle, Copy, Check } from 'lucide-react';
import { apiService } from '../services/api';
import { AuditRecord, RiskLevel, Decision } from '../types';
import DecisionBadge from '../components/DecisionBadge';
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
  const decisionRationale = data.decision_rationale || data.details?.decisionRationale || data.details?.decision_rationale || {};
  const detectedAttacks = data.details?.detectedAttacks || [];
  const attackDescriptions: Record<string, string> = {
    INSTRUCTION_OVERRIDE: 'the text tells the AI to ignore its original instructions',
    ROLE_CHANGE: 'the text tries to change the AI\'s role or authority',
    SECRET_EXTRACTION: 'the text asks the AI to reveal protected information',
    TOOL_ABUSE: 'the text asks the AI to use a tool for an unauthorized action',
    CREDENTIAL_THEFT: 'the text tries to obtain passwords, API keys, or other login details',
    CONTEXT_POISONING: 'the text places misleading instructions in supplied content',
    MULTI_STEP_JAILBREAK: 'the text uses a sequence of requests to bypass safety rules',
    ENCODED_INSTRUCTION: 'the text contains instructions hidden in encoded text',
    INDIRECT_PROMPT_INJECTION: 'the text hides instructions in external or retrieved content',
  };
  const attackTypes = [...new Set([
    ...detectedAttacks.map((attack: any) => String(attack.attackType || '').toUpperCase()),
    ...(decisionRationale.attack_types || []).map((attack: any) => String(typeof attack === 'string' ? attack : attack.type || attack.attack_type || '').toUpperCase()),
  ].filter(Boolean))];
  const findingExplanation = attackTypes.map((type) => attackDescriptions[type] || `the text contains ${type.toLowerCase().replace(/_/g, ' ')}`).join('; ');
  const riskImpact = attackTypes.some((type) => ['SECRET_EXTRACTION', 'CREDENTIAL_THEFT'].includes(type))
    ? 'This could expose private information or login details.'
    : (attackTypes.includes('TOOL_ABUSE')
      ? 'This could trigger an action you did not approve.'
      : 'This could make the AI follow these instructions instead of yours.');
  const decisionReason = attackTypes.length > 0
    ? (isBlocked
      ? `Blocked because ${findingExplanation}. ${riskImpact}`
      : (isSanitized
        ? `Aegis sanitized the content because ${findingExplanation}.`
        : `The scan found that ${findingExplanation}, but the safety settings allowed it.`))
    : (isBlocked
      ? (decisionRationale.gate_outcome === 'DEGRADED_FAILSAFE_BLOCK'
        ? 'Blocked because a required security check could not finish. The content was held back until it can be checked safely.'
        : (decisionRationale.mandatory_block_reason
          ? 'Blocked because the content matched a required safety rule.'
          : `Blocked because the safety scan rated this content ${normalizedScore}/100 risk.`))
      : (decisionUpper === 'REQUIRE_REVIEW'
        ? 'Held for review because the content could not be cleared safely.'
        : 'No specific unsafe instruction was found, so the request was allowed.'));

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

      <section className="space-y-5">
        <div className={`rounded-xl border p-5 sm:p-6 ${isBlocked ? 'border-[rgba(239,98,111,0.45)] bg-[rgba(239,98,111,0.06)]' : 'border-[rgba(53,201,138,0.35)] bg-[rgba(53,201,138,0.05)]'}`}>
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-[#8F9BAD]">{isBlocked ? 'Request blocked' : (isSanitized ? 'Request sanitized' : 'Request allowed')}</p>
              <h2 className={`mt-1 text-xl font-bold ${isBlocked ? 'text-[#EF626F]' : (isSanitized ? 'text-[#E9B44C]' : 'text-[#35C98A]')}`}>
                {isBlocked ? 'Why Aegis stopped this' : (isSanitized ? 'What Aegis changed' : 'Why Aegis allowed this')}
              </h2>
            </div>
            <div className="flex items-center gap-2">
              <DecisionBadge decision={data.decision as Decision} />
            </div>
          </div>

          <p className="mt-4 max-w-4xl text-sm leading-6 text-[#E1E7F0]">{decisionReason}</p>

          <div className="mt-5 border-t border-[#263247] pt-4">
            <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
              <span className="text-lg font-bold text-[#F4F7FB]">{normalizedScore}/100</span>
              <span className="text-sm text-[#C0C8D6]">{String(effectiveRiskLevel).toLowerCase()} risk</span>
              <span className="text-xs text-[#8F9BAD]">Risk level: {String(effectiveRiskLevel).toLowerCase()}. Score based on:</span>
            </div>
            {attackTypes.length > 0 ? (
              <ul className="mt-2 flex flex-wrap gap-2">
                {attackTypes.map((type) => {
                  return (
                    <li key={type} className="rounded-md border border-[#344258] bg-[#0E1526] px-3 py-2 text-sm text-[#E1E7F0]">
                      {attackDescriptions[type] || type.toLowerCase().replace(/_/g, ' ')}
                    </li>
                  );
                })}
              </ul>
            ) : (
              <p className="mt-2 text-sm text-[#C0C8D6]">No specific attack type was saved for this scan. The score reflects the overall detector assessment.</p>
            )}
          </div>

          {hasPii && (
            <p className="mt-4 rounded-md border border-[rgba(233,180,76,0.25)] bg-[rgba(233,180,76,0.06)] px-3 py-2 text-xs leading-5 text-[#D6B974]">
              Personal data ({piiTypes.join(', ') || 'sensitive information'}) was masked in this audit record. It is separate from the reason for this decision.
            </p>
          )}
        </div>

        <details className="rounded-xl border border-[#263247] bg-[#111827]">
          <summary className="cursor-pointer px-4 py-3 text-sm font-semibold text-[#E1E7F0]">View the content that was scanned</summary>
          <div className="border-t border-[#263247] p-4">
            {promptText ? (
              <>
                <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-[#1D2738] bg-[#080C18] p-4 font-mono text-xs leading-relaxed text-[#E1E7F0]">{promptText}</pre>
                {hasPii && <p className="mt-2 text-xs text-[#D6B974]">Sensitive values are masked in this saved copy.</p>}
              </>
            ) : (
              <p className="text-sm text-[#8F9BAD]">The content itself was not retained. This record contains its audit metadata only.</p>
            )}
          </div>
        </details>

        <details className="rounded-xl border border-[#263247] bg-[#111827]">
          <summary className="cursor-pointer px-4 py-3 text-sm font-semibold text-[#8F9BAD]">Technical audit details</summary>
          <div className="border-t border-[#263247]">
            <div className="flex flex-wrap items-center gap-x-5 gap-y-2 px-4 py-3 text-xs text-[#8F9BAD]">
              <span>Source: <strong className="font-medium text-[#C0C8D6]">{data.source_type || 'unknown'}</strong></span>
              <span>Policy: <strong className="font-medium text-[#C0C8D6]">{data.policy || data.details?.policy || 'default'}</strong></span>
              {promptHash && <span className="break-all">Audit hash: <strong className="font-mono font-normal text-[#C0C8D6]">{promptHash.slice(0, 16)}…</strong></span>}
            </div>
            <div className="flex justify-end border-t border-[#263247] px-4 py-2">
              <button onClick={copyJson} className="inline-flex items-center gap-1.5 text-xs text-[#8F9BAD] hover:text-[#E1E7F0]">
                {copiedRecord ? <Check size={13} /> : <Copy size={13} />}{copiedRecord ? 'Copied' : 'Copy audit record'}
              </button>
            </div>
            <div className="max-h-80 overflow-auto">
              <SyntaxHighlighter language="json" style={vscDarkPlus} customStyle={{ margin: 0, padding: '14px', fontSize: '11px', background: '#080C18' }}>
                {JSON.stringify(data.details || data, null, 2)}
              </SyntaxHighlighter>
            </div>
          </div>
        </details>
      </section>
    </div>
  );
}
