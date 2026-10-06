import { useEffect, useState } from 'react';
import { CheckCircle2, Loader2, ServerCog } from 'lucide-react';
import { getAuthSession } from '../utils/auth';

type Provider = 'openai' | 'ollama' | 'vllm' | 'custom';

const providerDefaults: Record<Provider, { baseUrl: string; modelHint: string }> = {
  openai: { baseUrl: 'https://api.openai.com/v1', modelHint: 'gpt-4o-mini' },
  // Ollama's native model-list endpoint is /api/tags, so keep this base URL without /v1.
  ollama: { baseUrl: 'http://localhost:11434', modelHint: 'llama3.2' },
  vllm: { baseUrl: 'http://localhost:8000/v1', modelHint: 'Qwen/Qwen2.5-7B-Instruct' },
  custom: { baseUrl: '', modelHint: 'Enter the model name exposed by your provider' },
};

export default function ProviderConfiguration() {
  const [provider, setProvider] = useState<Provider>('openai');
  const [url, setUrl] = useState('');
  const [model, setModel] = useState('');
  const [key, setKey] = useState('');
  const [hasKey, setHasKey] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [messageType, setMessageType] = useState<'success' | 'error' | 'info'>('info');
  const isAdmin = getAuthSession()?.role === 'superadmin';

  useEffect(() => {
    if (!isAdmin) return;
    let active = true;
    fetch('/api/v1/config/upstream', { credentials: 'same-origin', cache: 'no-store' })
      .then(async response => {
        if (!response.ok) throw new Error('Provider configuration is unavailable.');
        return response.json();
      })
      .then(data => {
        if (!active) return;
        setProvider(data.provider || 'openai');
        setUrl(data.base_url || '');
        setModel(data.model || '');
        setHasKey(Boolean(data.has_api_key));
      })
      .catch(error => {
        if (active) {
          setMessage(error.message || 'Provider configuration is unavailable.');
          setMessageType('error');
        }
      })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [isAdmin]);

  if (!isAdmin) return null;

  function selectProvider(nextProvider: Provider) {
    setProvider(nextProvider);
    setUrl(providerDefaults[nextProvider].baseUrl);
    setKey('');
    setHasKey(false);
    setMessage('Provider defaults loaded. Confirm the URL and model for your deployment.');
    setMessageType('info');
  }

  const payload = () => ({ provider, base_url: url, model, ...(key ? { api_key: key } : {}) });

  async function save(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setMessage('');
    try {
      const response = await fetch('/api/v1/config/upstream', {
        method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload()),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'Configuration could not be saved.');
      setKey('');
      setHasKey(Boolean(data.has_api_key));
      setMessage('Runtime settings saved. Use deployment settings to persist them across restarts.');
      setMessageType('success');
    } catch (error) {
      setMessage((error as Error).message);
      setMessageType('error');
    } finally {
      setBusy(false);
    }
  }

  async function testConnection() {
    setBusy(true);
    setMessage('Testing provider connection…');
    setMessageType('info');
    try {
      const response = await fetch('/api/v1/providers/test', {
        method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload()),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'Provider test could not be completed.');
      setMessage(data.message || (data.status === 'connected' ? 'Provider connected.' : 'Provider could not be reached.'));
      setMessageType(data.status === 'connected' ? 'success' : 'error');
    } catch (error) {
      setMessage((error as Error).message);
      setMessageType('error');
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="provider-config-panel surface" aria-labelledby="provider-config-title">
      <div className="provider-config-heading">
        <span className="integration-icon"><ServerCog size={18} /></span>
        <div><span className="eyebrow">MODEL ROUTING</span><h2 id="provider-config-title">Provider configuration</h2></div>
        {hasKey && <span className="provider-key-status"><CheckCircle2 size={14} /> Key saved</span>}
      </div>
      <form className="provider-config-form" onSubmit={save}>
        <label>Provider<select value={provider} onChange={event => selectProvider(event.target.value as Provider)} disabled={loading || busy}>{['openai', 'ollama', 'vllm', 'custom'].map(value => <option key={value} value={value}>{value === 'vllm' ? 'vLLM' : value[0].toUpperCase() + value.slice(1)}</option>)}</select></label>
        <label>Base URL<input type="url" value={url} onChange={event => setUrl(event.target.value)} required disabled={loading || busy} placeholder={providerDefaults[provider].baseUrl || 'https://api.example.com'} /></label>
        <label>Model<input value={model} onChange={event => setModel(event.target.value)} required disabled={loading || busy} placeholder={providerDefaults[provider].modelHint} /></label>
        <label>Provider key<input type="password" autoComplete="new-password" value={key} onChange={event => setKey(event.target.value)} disabled={loading || busy} placeholder={hasKey ? 'Saved · leave blank to keep' : 'Paste provider key'} /></label>
        <div className="provider-config-actions">
          <button className="secondary-button" type="button" onClick={testConnection} disabled={loading || busy || !url || !model}>{busy ? <Loader2 className="spin" size={14} /> : null}Test</button>
          <button className="primary-button" type="submit" disabled={loading || busy || !url || !model}>{busy ? <Loader2 className="spin" size={14} /> : null}Save</button>
        </div>
      </form>
      {message && <p role="status" className={`provider-config-message ${messageType}`}>{message}</p>}
      <p className="provider-config-footnote">Only server-approved destinations can be saved. For Docker deployments, use the provider's service name instead of localhost. Runtime changes reset on restart unless saved in deployment settings.</p>
    </section>
  );
}
