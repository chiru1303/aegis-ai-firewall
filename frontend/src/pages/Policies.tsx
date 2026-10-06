import React, { useState, useEffect } from 'react';
import {
  SlidersHorizontal, Lock, CheckCircle2,
  Plus, ToggleLeft, ToggleRight, X, Shield, Sliders
} from 'lucide-react';
import PageHeader from '../components/PageHeader';
import { apiService } from '../services/api';
import toast from 'react-hot-toast';

interface PolicyRule {
  id: string;
  name: string;
  scope: 'GLOBAL' | 'TENANT' | 'APPLICATION' | 'ENVIRONMENT';
  isMandatory: boolean;
  active: boolean;
  description: string;
  riskThreshold: number;
  action: 'BLOCK' | 'SANITIZE' | 'REQUIRE_REVIEW';
  rules: string[];
}

const MANDATORY_GUARDRAILS: PolicyRule[] = [
  {
    id: 'mg-01',
    name: 'Mandatory Credential & Secret Exfiltration Guard',
    scope: 'GLOBAL',
    isMandatory: true,
    active: true,
    description: 'Non-overridable platform invariant: Immediately blocks any payload attempting AWS key, JWT, SSH key, or environment variable extraction.',
    riskThreshold: 0,
    action: 'BLOCK',
    rules: ['Block AWS / GCP / GitHub tokens', 'Block /etc/shadow & /etc/passwd references', 'Block process.env and os.environ dumps'],
  },
  {
    id: 'mg-02',
    name: 'Mandatory Cloud Metadata & Private SSRF Defense',
    scope: 'GLOBAL',
    isMandatory: true,
    active: true,
    description: 'Enforces strict rejection of 169.254.169.254, computeMetadata, and private RFC-1918 subnets across all agent tool destinations.',
    riskThreshold: 0,
    action: 'BLOCK',
    rules: ['Block 169.254.169.254', 'Block 127.0.0.1 and localhost', 'Block private subnets 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16'],
  },
  {
    id: 'mg-03',
    name: 'Mandatory Command Injection & Shell Neutralizer',
    scope: 'GLOBAL',
    isMandatory: true,
    active: true,
    description: 'Blocks tool arguments containing shell metacharacters (; | && ` $( )) unless explicitly permitted in sandboxed environment.',
    riskThreshold: 0,
    action: 'BLOCK',
    rules: ['Detect metacharacters in CLI arguments', 'Enforce structured JSON parameters only'],
  },
];

const INITIAL_CONFIGURABLE_POLICIES: PolicyRule[] = [
  {
    id: 'pol-zero-trust',
    name: 'Zero-Trust Default Baseline',
    scope: 'GLOBAL',
    isMandatory: false,
    active: true,
    description: 'Blocks threats with risk score > 0.80; sanitizes untrusted prompt directives between 0.40 and 0.79.',
    riskThreshold: 0.80,
    action: 'BLOCK',
    rules: ['High-confidence prompt injection -> BLOCK', 'Ambiguous indirect injection -> SANITIZE'],
  },
  {
    id: 'pol-financial-strict',
    name: 'Banking & Financial Services High-Assurance',
    scope: 'TENANT',
    isMandatory: false,
    active: true,
    description: 'Extra strict thresholds for payment processors and financial agents. Zero tolerance for unverified tool invocations.',
    riskThreshold: 0.50,
    action: 'BLOCK',
    rules: ['Any role manipulation attempt -> BLOCK', 'Sanitize all external PDF documents before ingestion'],
  },
  {
    id: 'pol-rag-boundary',
    name: 'RAG Context Poisoning Quarantine',
    scope: 'APPLICATION',
    isMandatory: false,
    active: true,
    description: 'Neutralizes hidden HTML spans, markdown comments, and system-prompt tokens embedded in retrieval vectors.',
    riskThreshold: 0.60,
    action: 'SANITIZE',
    rules: ['Strip CSS-hidden text & zero-font-size', 'Neutralize markdown [system] directive tokens'],
  },
  {
    id: 'pol-research-permissive',
    name: 'Adversarial Research Permissive (Audit-Only)',
    scope: 'ENVIRONMENT',
    isMandatory: false,
    active: false,
    description: 'Enables prompt injection bypass for dedicated red-team evaluations while recording complete cryptographic audit trails.',
    riskThreshold: 0.95,
    action: 'REQUIRE_REVIEW',
    rules: ['Permit test variants for designated red-team API keys', 'Record full SHA-256 outbox events for compliance'],
  },
];

export default function Policies() {
  const [policies, setPolicies] = useState<PolicyRule[]>(INITIAL_CONFIGURABLE_POLICIES);
  const [loading, setLoading] = useState<boolean>(true);
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);
  const [submitting, setSubmitting] = useState<boolean>(false);

  // Form state
  const [formName, setFormName] = useState('');
  const [formDescription, setFormDescription] = useState('');
  const [formScope, setFormScope] = useState<'GLOBAL' | 'TENANT' | 'APPLICATION' | 'ENVIRONMENT'>('GLOBAL');
  const [formAction, setFormAction] = useState<'BLOCK' | 'SANITIZE' | 'REQUIRE_REVIEW'>('BLOCK');
  const [formThreshold, setFormThreshold] = useState<number>(0.70);
  const [formRules, setFormRules] = useState('');
  const [formActive, setFormActive] = useState<boolean>(true);
  const thresholdLabel = formThreshold < 0.4 ? 'Strict' : formThreshold < 0.72 ? 'Balanced' : 'Permissive';

  // Load policies from API
  const fetchPolicies = async () => {
    try {
      setLoading(true);
      const data = await apiService.getPolicies();
      if (Array.isArray(data) && data.length > 0) {
        const configurable = data.filter((p: any) => !p.is_mandatory && !p.isMandatory);
        if (configurable.length > 0) {
          const mapped: PolicyRule[] = configurable.map((p: any) => ({
            id: String(p.id),
            name: p.name || 'Unnamed Policy',
            scope: (p.scope?.toUpperCase() as any) || 'GLOBAL',
            isMandatory: false,
            active: p.active !== undefined ? Boolean(p.active) : Boolean(p.is_active),
            description: p.description || '',
            riskThreshold: Number(p.riskThreshold ?? p.risk_threshold ?? 0.70),
            action: (p.action as any) || 'BLOCK',
            rules: Array.isArray(p.rules) ? p.rules : [String(p.rules || 'Enforce security standard')],
          }));
          setPolicies(mapped);
        }
      }
    } catch (err) {
      console.warn('Could not load remote policies, fallback to defaults:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPolicies();
  }, []);

  const togglePolicy = async (id: string) => {
    // Optimistic UI update
    setPolicies(prev =>
      prev.map(p => {
        if (p.id === id) {
          const nextState = !p.active;
          return { ...p, active: nextState };
        }
        return p;
      })
    );

    try {
      const res = await apiService.togglePolicy(id);
      const isNowActive = res.is_active ?? res.active;
      toast.success(`Policy "${res.name || id}" is now ${isNowActive ? 'enabled' : 'disabled'}`);
    } catch (err: any) {
      // Revert if error
      setPolicies(prev =>
        prev.map(p => (p.id === id ? { ...p, active: !p.active } : p))
      );
      toast.error('Failed to update policy status');
    }
  };

  const handleCreatePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formName.trim()) {
      toast.error('Please enter a policy name');
      return;
    }

    try {
      setSubmitting(true);
      const rulesArray = formRules
        .split('\n')
        .map(r => r.trim())
        .filter(r => r.length > 0);

      const payload = {
        name: formName.trim(),
        description: formDescription.trim(),
        scope: formScope,
        action: formAction,
        risk_threshold: Number(formThreshold),
        rules: rulesArray.length > 0 ? rulesArray : [`Enforce ${formAction} action above risk threshold ${formThreshold}`],
        is_active: formActive,
      };

      const res = await apiService.createPolicy(payload);
      toast.success(res.message || 'Policy created and active in firewall');

      // Add to list
      const newPolicy: PolicyRule = {
        id: String(res.id),
        name: res.name,
        scope: res.scope as any,
        isMandatory: false,
        active: res.active ?? res.is_active ?? true,
        description: res.description || '',
        riskThreshold: Number(res.risk_threshold ?? formThreshold),
        action: (res.action as any) || formAction,
        rules: res.rules || rulesArray,
      };

      setPolicies(prev => [newPolicy, ...prev]);

      // Reset and close
      setFormName('');
      setFormDescription('');
      setFormRules('');
      setFormThreshold(0.70);
      setFormActive(true);
      setIsModalOpen(false);
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to create policy');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl policies-page">
      <PageHeader
        title="Security Policies"
        description="Manage security rules, risk thresholds, and baseline guardrails."
        badge={
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-[rgba(53,201,138,0.12)] border border-[rgba(53,201,138,0.3)] text-xs font-mono font-semibold text-[#35C98A]">
            <CheckCircle2 size={13} />
            3 BASELINE GUARDRAILS ACTIVE
          </span>
        }
        actions={
          <button
            onClick={() => setIsModalOpen(true)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#4F8CFF] hover:bg-[#6A9DFF] text-xs font-semibold text-white font-mono transition-colors shadow-md shadow-[#4F8CFF]/15"
          >
            <Plus size={14} />
            <span>Create Policy</span>
          </button>
        }
      />

      {/* Mandatory Platform Guardrails Section */}
      <div className="space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-[#263247]">
          <div className="flex items-center gap-2">
            <Lock size={15} className="text-[#EF626F]" />
            <h2 className="text-xs uppercase font-mono font-bold tracking-wider text-[#F4F7FB]">
              Baseline Guardrails
            </h2>
          </div>
          <span className="baseline-note">Always on · cannot be disabled</span>
        </div>

        <div className="space-y-3">
          {MANDATORY_GUARDRAILS.map((g) => (
            <div
              key={g.id}
              className="bg-[#111827] border border-[rgba(239,98,111,0.25)] rounded-lg p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4"
            >
              <div className="space-y-1.5">
                <div className="flex items-center gap-2">
                  <span className="font-mono font-bold text-xs text-[#F4F7FB]">{g.name}</span>
                </div>
                <p className="text-xs text-[#8F9BAD] max-w-2xl">{g.description}</p>
                <div className="flex flex-wrap gap-2 pt-1">
                  {g.rules.map((r, i) => (
                    <span key={i} className="text-[11px] font-mono text-[#C0C8D6] bg-[#0E1526] px-2 py-0.5 rounded border border-[#1D2738]">
                      • {r}
                    </span>
                  ))}
                </div>
              </div>

              <div className="self-end sm:self-center shrink-0">
                <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-[rgba(53,201,138,0.1)] border border-[rgba(53,201,138,0.25)] text-xs font-mono text-[#35C98A]">
                  <CheckCircle2 size={13} /> Active Always
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Configurable Tenant & Application Policies */}
      <div className="space-y-3 pt-4">
        <div className="flex items-center justify-between pb-2 border-b border-[#263247]">
          <div className="flex items-center gap-2">
            <SlidersHorizontal size={15} className="text-[#4F8CFF]" />
            <h2 className="text-xs uppercase font-mono font-bold tracking-wider text-[#F4F7FB]">
              Configurable Policies
            </h2>
          </div>
          <span className="text-[11px] font-mono text-[#8F9BAD]">
            {policies.filter(p => p.active).length} Active Policies
          </span>
        </div>

        <div className="space-y-3">
          {policies.map((p) => (
            <div
              key={p.id}
              className={`bg-[#111827] border rounded-lg p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-colors ${
                p.active ? 'border-[#263247]' : 'border-[#1D2738] opacity-70'
              }`}
            >
              <div className="space-y-1.5">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono font-bold text-xs text-[#F4F7FB]">{p.name}</span>
                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#172033] text-[#4F8CFF] border border-[#263247] uppercase font-semibold">
                    {p.scope[0] + p.scope.slice(1).toLowerCase()}
                  </span>
                  <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded border font-semibold ${
                    p.action === 'BLOCK' ? 'bg-[rgba(239,98,111,0.1)] text-[#EF626F] border-[rgba(239,98,111,0.3)]' :
                    p.action === 'SANITIZE' ? 'bg-[rgba(233,180,76,0.1)] text-[#E9B44C] border-[rgba(233,180,76,0.3)]' :
                    'bg-[rgba(79,140,255,0.1)] text-[#4F8CFF] border-[rgba(79,140,255,0.3)]'
                  }`}>
                    {p.action === 'REQUIRE_REVIEW' ? 'Review' : p.action[0] + p.action.slice(1).toLowerCase()}
                  </span>
                  <span className="text-[10px] font-mono text-[#8F9BAD]">
                    Threshold: &gt; {p.riskThreshold}
                  </span>
                </div>
                <p className="text-xs text-[#8F9BAD] max-w-2xl">{p.description}</p>
                <div className="flex flex-wrap gap-2 pt-1">
                  {p.rules.map((r, i) => (
                    <span key={i} className="text-[11px] font-mono text-[#C0C8D6] bg-[#0E1526] px-2 py-0.5 rounded border border-[#1D2738]">
                      • {r}
                    </span>
                  ))}
                </div>
              </div>

              <div className="flex items-center gap-3 self-end sm:self-center shrink-0">
                <button
                  onClick={() => togglePolicy(p.id)}
                  className={`inline-flex items-center gap-1.5 px-3 py-1 rounded text-xs font-mono font-semibold border transition-colors ${
                    p.active
                      ? 'bg-[rgba(53,201,138,0.12)] text-[#35C98A] border-[rgba(53,201,138,0.3)] hover:bg-[rgba(53,201,138,0.2)]'
                      : 'bg-[#172033] text-[#8F9BAD] border-[#263247] hover:bg-[#1D2940]'
                  }`}
                  title={p.active ? 'Click to disable policy' : 'Click to enable policy'}
                >
                  {p.active ? <ToggleRight size={16} /> : <ToggleLeft size={16} />}
                  <span>{p.active ? 'ACTIVE' : 'DISABLED'}</span>
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Create Policy Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in">
          <div className="bg-[#111827] border border-[#263247] rounded-xl w-full max-w-lg shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
            {/* Modal Header */}
            <div className="px-5 py-4 border-b border-[#263247] bg-[#0E1526] flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Shield size={16} className="text-[#4F8CFF]" />
                <h3 className="text-sm font-mono font-bold text-[#F4F7FB]">Create Security Policy</h3>
              </div>
              <button
                onClick={() => setIsModalOpen(false)}
                className="text-[#8F9BAD] hover:text-[#F4F7FB] p-1 rounded hover:bg-[#172033] transition-colors"
                aria-label="Close dialog"
              >
                <X size={16} />
              </button>
            </div>

            {/* Modal Body */}
            <form onSubmit={handleCreatePolicy} className="p-5 space-y-4 overflow-y-auto flex-1 font-mono">
              <div>
                <label className="block text-xs text-[#8F9BAD] mb-1 font-semibold uppercase tracking-wider">
                  Policy Name *
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Chatbot Strict Injection Guard"
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  className="w-full bg-[#0E1526] border border-[#263247] rounded-lg px-3 py-2 text-xs text-[#F4F7FB] focus:border-[#4F8CFF] focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs text-[#8F9BAD] mb-1 font-semibold uppercase tracking-wider">
                  Description
                </label>
                <input
                  type="text"
                  placeholder="Explain what this policy enforces"
                  value={formDescription}
                  onChange={(e) => setFormDescription(e.target.value)}
                  className="w-full bg-[#0E1526] border border-[#263247] rounded-lg px-3 py-2 text-xs text-[#F4F7FB] focus:border-[#4F8CFF] focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-[#8F9BAD] mb-1 font-semibold uppercase tracking-wider">
                    Scope
                  </label>
                  <select
                    value={formScope}
                    onChange={(e: any) => setFormScope(e.target.value)}
                    className="w-full bg-[#0E1526] border border-[#263247] rounded-lg px-3 py-2 text-xs text-[#F4F7FB] focus:border-[#4F8CFF] focus:outline-none"
                  >
                    <option value="GLOBAL">Global</option>
                    <option value="TENANT">Tenant</option>
                    <option value="APPLICATION">Application</option>
                    <option value="ENVIRONMENT">Environment</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs text-[#8F9BAD] mb-1 font-semibold uppercase tracking-wider">
                    Enforcement Action
                  </label>
                  <select
                    value={formAction}
                    onChange={(e: any) => setFormAction(e.target.value)}
                    className="w-full bg-[#0E1526] border border-[#263247] rounded-lg px-3 py-2 text-xs text-[#F4F7FB] focus:border-[#4F8CFF] focus:outline-none"
                  >
                    <option value="BLOCK">Block</option>
                    <option value="SANITIZE">Sanitize</option>
                    <option value="REQUIRE_REVIEW">Require Review</option>
                  </select>
                </div>
              </div>

              <div>
                <div className="flex justify-between items-center mb-1">
                  <label className="text-xs text-[#8F9BAD] font-semibold uppercase tracking-wider">
                    Risk threshold: &gt; {formThreshold.toFixed(2)}
                  </label>
                  <span className="text-[11px] text-[#4F8CFF]">
                    {thresholdLabel}
                  </span>
                </div>
                <input
                  type="range"
                  min="0.10"
                  max="0.95"
                  step="0.05"
                  value={formThreshold}
                  onChange={(e) => setFormThreshold(parseFloat(e.target.value))}
                  className="w-full h-1.5 bg-[#0E1526] rounded-lg appearance-none cursor-pointer accent-[#4F8CFF]"
                />
                <div className="threshold-scale"><span>Strict</span><span>Balanced</span><span>Permissive</span></div>
              </div>

              <div>
                <label className="block text-xs text-[#8F9BAD] mb-1 font-semibold uppercase tracking-wider">
                  Rules (one per line)
                </label>
                <textarea
                  rows={3}
                  placeholder="Block unauthorized role manipulation&#10;Sanitize embedded system instructions&#10;Disallow code execution tools"
                  value={formRules}
                  onChange={(e) => setFormRules(e.target.value)}
                  className="w-full bg-[#0E1526] border border-[#263247] rounded-lg px-3 py-2 text-xs text-[#F4F7FB] focus:border-[#4F8CFF] focus:outline-none font-mono"
                />
              </div>

              {/* Status Toggle */}
              <div className="pt-2 flex items-center justify-between border-t border-[#1D2738]">
                <div className="flex flex-col">
                  <span className="text-xs text-[#F4F7FB] font-semibold">Enable Policy</span>
                  <span className="text-[11px] text-[#8F9BAD]">Activate immediately upon creation</span>
                </div>
                <button
                  type="button"
                  onClick={() => setFormActive(!formActive)}
                  className={`inline-flex items-center gap-1.5 px-3 py-1 rounded text-xs font-semibold border transition-colors ${
                    formActive
                      ? 'bg-[rgba(53,201,138,0.12)] text-[#35C98A] border-[rgba(53,201,138,0.3)]'
                      : 'bg-[#172033] text-[#8F9BAD] border-[#263247]'
                  }`}
                >
                  {formActive ? <ToggleRight size={16} /> : <ToggleLeft size={16} />}
                  <span>{formActive ? 'ENABLED' : 'DISABLED'}</span>
                </button>
              </div>

              {/* Modal Actions */}
              <div className="pt-4 flex items-center justify-end gap-2 border-t border-[#263247]">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-3 py-1.5 rounded bg-[#172033] text-[#8F9BAD] hover:text-[#F4F7FB] text-xs font-semibold hover:bg-[#1D2940] transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-4 py-1.5 rounded bg-[#4F8CFF] hover:bg-[#6A9DFF] text-white text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50 shadow-md shadow-[#4F8CFF]/15"
                >
                  {submitting ? 'Creating...' : 'Create Policy'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
