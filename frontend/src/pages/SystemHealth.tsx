import { useCallback, useEffect, useState } from 'react';
import { Activity, AlertCircle, CheckCircle, HelpCircle, Database, RefreshCw, Server, ShieldCheck, Sparkles } from 'lucide-react';
import { apiService } from '../services/api';
import { getAuthSession } from '../utils/auth';
import { formatIST } from '../utils/date';

type HealthData = {
  status?: string;
  healthy?: boolean;
  database?: string;
  redis?: string;
  models?: Record<string, string>;
  tier_0_detectors?: number;
  upstream_llm?: string;
  timestamp?: string;
};

function readable(value?: string) {
  if (!value) return 'Status unavailable';
  return value.replace(/_/g, ' ').replace(/\s*·\s*/g, ' — ').replace(/\b\w/g, letter => letter.toUpperCase());
}

function stateFor(value?: string): 'ready' | 'notice' | 'unknown' {
  const normalized = (value || '').toLowerCase().replace(/_/g, ' ');
  if (normalized.includes('unavailable') || normalized.includes('error') || normalized.includes('failed') || normalized.includes('degraded')) return 'notice';
  if (normalized.includes('not loaded') || normalized.includes('fallback') || normalized.includes('not connected') || normalized.includes('not configured') || normalized.includes('unverified') || normalized.includes('in memory')) return 'notice';
  if (normalized.includes('loaded') || normalized.includes('connected') || normalized === 'ok' || normalized === 'healthy' || normalized.includes('heuristic') || normalized.includes('every scan') || normalized.includes('in use')) return 'ready';
  return 'unknown';
}

function StateIcon({ state }: { state: ReturnType<typeof stateFor> }) {
  if (state === 'ready') return <CheckCircle size={18} aria-hidden="true" />;
  if (state === 'notice') return <AlertCircle size={18} aria-hidden="true" />;
  return <HelpCircle size={18} aria-hidden="true" />;
}

const detectorLabels: Record<string, string> = {
  wolf_defender: 'Wolf Defender', deberta: 'DeBERTa', laya: 'LAYA', open_jev: 'Open-Jev',
  lightgbm: 'LightGBM', tier_0_detectors: 'Always-on rule detectors',
};

function detectorStatus(value: string) {
  const normalized = value.toLowerCase();
  if (normalized.includes('every scan') || normalized.includes('always')) return 'Active on every scan';
  if (normalized.includes('on-demand') || normalized.includes('escalat')) return 'Used when needed';
  if (normalized.includes('loaded')) return 'Available';
  if (normalized.includes('fallback')) return 'Fallback active';
  if (normalized.includes('not loaded')) return 'Not installed';
  return readable(value);
}

export default function SystemHealth() {
  const [health, setHealth] = useState<HealthData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [lastChecked, setLastChecked] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const result = await apiService.getHealth();
      setHealth(result);
      setLastChecked(new Date().toISOString());
    } catch {
      setError('Could not reach the health endpoint. Check that the Aegis gateway is running.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => {
    if (!autoRefresh) return;
    const timer = window.setInterval(() => { if (document.visibilityState === 'visible') void refresh(); }, 30000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, refresh]);

  const services = [
    { label: 'Gateway', value: health?.status ? readable(health.status) : 'Checking…', state: health?.status ? stateFor(health.status) : 'unknown' as const, icon: Server },
    { label: 'Database', value: health?.database ? readable(health.database) : 'Checking…', state: health?.database ? stateFor(health.database) : 'unknown' as const, icon: Database },
    { label: 'Session store', value: health?.redis ? readable(health.redis) : 'Checking…', state: health?.redis ? stateFor(health.redis) : 'unknown' as const, icon: Activity },
    { label: 'Model provider', value: health?.upstream_llm ? readable(health.upstream_llm) : 'Checking…', state: health?.upstream_llm ? stateFor(health.upstream_llm) : 'unknown' as const, icon: Sparkles },
  ];
  const detectors = Object.entries(health?.models || {});
  const loadedCount = detectors.filter(([, value]) => stateFor(value) === 'ready').length;
  const showDetectorDetails = ['superadmin', 'admin', 'tenant_admin'].includes(getAuthSession()?.role || '');

  return <div className="page-stack system-health-page">
    <div className="page-intro system-health-intro">
      <span className="eyebrow">SERVICE HEALTH</span>
      <div className="system-health-title-row">
        <div><h1>System status</h1><p className="muted">Live status for the gateway, storage, model provider, and detection stack.</p>{lastChecked && <span className="health-last-checked">Last checked {formatIST(lastChecked)}</span>}</div>
        <div className="health-controls"><label className="health-auto-refresh"><input type="checkbox" checked={autoRefresh} onChange={event => setAutoRefresh(event.target.checked)} /> Auto-refresh</label><button className="secondary-button" onClick={() => void refresh()} disabled={loading} aria-label="Refresh system status"><RefreshCw size={16} className={loading ? 'spin' : ''} />{loading ? 'Checking' : 'Refresh'}</button></div>
      </div>
    </div>

    {error && <div role="alert" className="notice error system-health-error">{error}<button onClick={() => void refresh()}>Retry</button></div>}

    <section className="health-service-grid" aria-label="Service dependencies">
      {services.map(({ label, value, state, icon: Icon }) => <article className={`health-service-card health-${state}`} key={label}>
        <div className="health-service-heading"><span className="health-service-icon"><Icon size={18} /></span><span>{label}</span></div>
        <div className="health-service-value"><StateIcon state={state} /><strong>{value}</strong></div>
      </article>)}
    </section>

    <section className="surface health-detectors">
      <div className="health-section-heading"><div><span className="eyebrow">DETECTION STACK</span><h2>Detectors and models</h2><p className="muted">Aegis keeps rule-based inspection available when optional models are offline.</p></div>
        <div className="health-count"><ShieldCheck size={18} /><strong>{health?.tier_0_detectors ?? 0}</strong><span>always-on rules</span></div>
      </div>
      {!showDetectorDetails ? <div className="health-summary"><span className={`health-dot ${loadedCount > 0 ? 'is-ready' : 'is-unknown'}`} /><strong>{health?.tier_0_detectors ?? 0} always-on rules</strong><span>Model-level diagnostics are available to workspace administrators.</span></div> : detectors.length ? <div className="health-detector-list">{detectors.map(([name, value]) => {
        const state = stateFor(value);
        return <div className={`health-detector-row health-${state}`} key={name}>
          <span className={`health-dot ${state === 'ready' ? 'is-ready' : state === 'notice' ? 'is-notice' : 'is-unknown'}`} aria-label={state} />
          <span className="health-detector-name">{detectorLabels[name] || name.replace(/_/g, ' ')}</span>
          <span className="health-detector-status">{detectorStatus(value)}</span>
        </div>;
      })}</div> : <div className="health-loading-state">{loading ? 'Loading detector status…' : 'Detector status is not available.'}</div>}
    </section>
  </div>;
}
