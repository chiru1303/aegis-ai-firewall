import { Link } from 'react-router-dom';
import { Activity, ArrowRight, Ban, RefreshCw, ScanLine, ShieldCheck } from 'lucide-react';
import { useMetrics, useThreatFeed } from '../hooks/useApi';
import { AttackType } from '../types';
import { formatIST } from '../utils/date';

const attackLabels: Record<string, string> = {
  instruction_override: 'Instruction override', role_change: 'Role change', secret_extraction: 'Secret extraction',
  tool_abuse: 'Tool abuse', credential_theft: 'Credential theft', context_poisoning: 'Context poisoning',
  multi_step_jailbreak: 'Multi-step jailbreak', encoded_instruction: 'Encoded instruction',
  indirect_prompt_injection: 'Indirect injection',
};

function TrendChart({ data }: { data: { timestamp: string; count: number; allowed?: number; blocked?: number }[] }) {
  const width = 680, height = 190, pad = 12;
  const max = Math.max(1, ...data.map(point => Math.max(point.allowed || 0, point.blocked || 0)));
  const pathFor = (key: 'allowed' | 'blocked') => data.map((point, i) => {
    const x = pad + i * (width - pad * 2) / Math.max(1, data.length - 1);
    const y = height - pad - ((point[key] || 0) / max) * (height - pad * 2);
    return `${i ? 'L' : 'M'}${x},${y}`;
  }).join(' ');
  return <div className="trend-chart-wrap">
    <div className="chart-legend"><span><i className="legend-dot allowed" />Allowed</span><span><i className="legend-dot blocked" />Blocked</span><small>Latest 50 inspections by hour</small></div>
    <svg className="trend-chart" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Hourly allowed and blocked inspection counts">
      {[0, .5, 1].map(f => <line key={f} x1={pad} x2={width - pad} y1={pad + (height - pad * 2) * f} y2={pad + (height - pad * 2) * f} className="chart-gridline" />)}
      <path d={pathFor('allowed')} className="chart-line allowed-line" />
      <path d={pathFor('blocked')} className="chart-line blocked-line" />
    </svg>
    <div className="chart-axis"><span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>Now</span></div>
  </div>;
}

export default function Dashboard() {
  const { data: metrics, loading, error, refetch } = useMetrics();
  const { data: feed, loading: feedLoading } = useThreatFeed();
  const m: any = metrics || {};
  const requests = Number(m.requests_last_24h ?? 0);
  const blocked = Number(m.blocks_last_24h ?? 0);
  const blockRate = Number(m.block_rate_last_24h ?? 0) * 100;
  const delta = Number(m.requests_last_24h ?? 0) - Number(m.requests_previous_24h ?? 0);
  const p50 = Number(m.gateway_p50_ms ?? m.avg_gateway_overhead_ms ?? m.avgLatencyMs ?? 0);
  const p95 = Number(m.gateway_p95_ms ?? 0);
  const attackTypes = Object.entries((metrics?.attackTypeDistribution || {}) as Record<string, number>)
    .filter(([name, count]) => name !== AttackType.NONE && Number(count) > 0)
    .sort((a, b) => b[1] - a[1]).slice(0, 5);

  return <div className="page-stack dashboard-page">
    <section className="overview-hero">
      <div className="hero-copy"><span className="eyebrow">AEGIS SECURITY WORKSPACE</span><h1>Your AI security workspace</h1><p>Inspect content, enforce policies, and keep model traffic behind a clear security boundary.</p></div>
      <div className="hero-actions"><Link className="primary-button" to="/analyzer"><ScanLine size={17} />New inspection<ArrowRight size={16} /></Link><Link className="secondary-button" to="/universal-integration">Connect an app<ArrowRight size={15} /></Link></div>
    </section>

    <section className="metric-grid dashboard-metrics" aria-label="Last 24 hours">
      <article className="metric-tile"><span className="metric-icon"><Activity size={18} /></span><span>Inspections</span><strong>{loading ? '—' : requests.toLocaleString()}</strong><small>{delta > 0 ? `↑ ${delta} vs previous 24h` : delta < 0 ? `↓ ${Math.abs(delta)} vs previous 24h` : 'Compared with previous 24h'}</small></article>
      <article className="metric-tile"><span className="metric-icon warning"><Ban size={18} /></span><span>Blocked</span><strong>{loading ? '—' : blocked.toLocaleString()}</strong><small>Requests held by policy</small></article>
      <article className="metric-tile"><span className="metric-icon"><ShieldCheck size={18} /></span><span>Block rate</span><strong>{loading ? '—' : `${blockRate.toFixed(1)}%`}</strong><small>Of inspections in last 24h</small></article>
      <article className="metric-tile"><span className="metric-icon"><Activity size={18} /></span><span>Gateway latency · 24h</span><strong>{loading || p50 <= 0 ? '—' : <>{p50.toFixed(0)}<small> ms p50</small></>}</strong><small>{p95 > 0 ? `${p95.toFixed(0)} ms p95` : 'No latency samples in this period'}</small></article>
    </section>

    {error && <div className="notice error" role="alert">Metrics are temporarily unavailable. <button className="text-link" onClick={() => void refetch()}>Retry</button></div>}
    <section className="overview-bottom">
      <article className="surface overview-chart-card"><div className="section-heading"><div><span className="eyebrow">TRAFFIC</span><h2>Inspection activity</h2><p className="muted">Allowed and blocked requests grouped by hour.</p></div><button className="icon-button" onClick={() => void refetch()} aria-label="Refresh overview"><RefreshCw size={16} /></button></div>
        <TrendChart data={metrics?.requestsOverTime || []} />
      </article>
      <article className="surface overview-attack-card"><div className="section-heading"><div><span className="eyebrow">DETECTION</span><h2>Common signals</h2><p className="muted">Most frequent attack categories in recent inspections.</p></div></div>
        {attackTypes.length ? <div className="attack-bars">{attackTypes.map(([name, count]) => <div key={name} className="attack-bar-row"><div><span>{attackLabels[name.toLowerCase()] || name.replace(/_/g, ' ').toLowerCase()}</span><strong>{count}</strong></div><span className="attack-bar-track"><i style={{ width: `${Math.max(4, Number(count) / Number(attackTypes[0][1]) * 100)}%` }} /></span></div>)}</div> : <div className="empty-inline">No attack signals recorded yet.</div>}
      </article>
    </section>

    <section className="surface recent-activity"><div className="section-heading"><div><span className="eyebrow">RECENT ACTIVITY</span><h2>Latest inspections</h2><p className="muted">Prompt content is hidden here to protect sensitive data.</p></div><Link className="text-link" to="/audit">View activity<ArrowRight size={15} /></Link></div>
      {feedLoading && !feed ? <div className="empty-inline">Loading activity…</div> : feed?.length ? <div className="dashboard-feed">{feed.slice(0, 5).map(item => <Link className="dashboard-feed-row" key={item.id} to={`/attack/${item.id}`}><span className={`feed-decision decision-${String(item.decision).toLowerCase()}`} /><span className="feed-main"><strong>{String(item.decision).replace(/_/g, ' ')}</strong><small>{item.attackTypes?.length ? item.attackTypes.map(type => attackLabels[String(type).toLowerCase()] || String(type).replace(/_/g, ' ').toLowerCase()).join(' · ') : `${String(item.sourceType || 'content').toUpperCase()} inspection`}</small></span><time>{formatIST(item.timestamp)}</time><ArrowRight size={15} /></Link>)}</div> : <div className="empty-inline">No inspections recorded yet. <Link to="/analyzer">Inspect content</Link></div>}
    </section>
  </div>;
}
