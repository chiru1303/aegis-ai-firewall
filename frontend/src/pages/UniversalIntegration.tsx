import { useState } from 'react';
import { Link } from 'react-router-dom';
import ProviderConfiguration from '../components/ProviderConfiguration';
import {
  ArrowRight, Check, Copy, Eye, EyeOff, FileCode2, KeyRound, Layers3, Network,
  Plug, Shield, ShieldCheck, Terminal,
} from 'lucide-react';

type Mode = 'gateway' | 'api' | 'sdk' | 'sidecar';
type Snippet = 'python' | 'curl' | 'typescript' | 'yaml';

const modes: { id: Mode; label: string; summary: string }[] = [
  { id: 'gateway', label: 'OpenAI-Compatible Gateway', summary: 'Route live model traffic through Aegis' },
  { id: 'api', label: 'Security API', summary: 'Inspect content before your model call' },
  { id: 'sdk', label: 'SDK', summary: 'Use the Python or Node client' },
  { id: 'sidecar', label: 'Sidecar / Reverse Proxy', summary: 'Add Aegis to a service network path' },
];

function CodeBlock({ code, language }: { code: string; language: string }) {
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(code);
      setCopyError(false);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false); setCopyError(true);
    }
  }
  return (
    <div className="code-sample integration-code">
      <button className="text-link" type="button" onClick={copy} aria-label="Copy code example">
        {copied ? <Check size={14} /> : <Copy size={14} />}{copied ? 'Copied' : copyError ? 'Copy unavailable' : 'Copy'}
      </button>
      <pre aria-label={`${language} example`}><code>{code}</code></pre>
    </div>
  );
}

export default function UniversalIntegration() {
  const [mode, setMode] = useState<Mode>('gateway');
  const [snippet, setSnippet] = useState<Snippet>('python');
  const [apiKey, setApiKey] = useState<string | null>(null);
  const [keyVisible, setKeyVisible] = useState(false);
  const [keyLoading, setKeyLoading] = useState(false);
  const [keyCopied, setKeyCopied] = useState(false);
  const [keyError, setKeyError] = useState('');
  const [endpointCopied, setEndpointCopied] = useState('');
  const gatewayUrl = `${window.location.origin}/v1`;
  const scanUrl = `${window.location.origin}/v1/security/scan`;

  async function toggleApiKey() {
    if (keyVisible) {
      setKeyVisible(false);
      setApiKey(null);
      setKeyError('');
      return;
    }
    if (apiKey) {
      setKeyVisible(true);
      return;
    }
    setKeyLoading(true);
    setKeyError('');
    try {
      const response = await fetch('/api/v1/auth/api-key', { credentials: 'same-origin', cache: 'no-store' });
      if (!response.ok) throw new Error(response.status === 403 ? 'Only a workspace administrator can view this key.' : 'Could not load the API key. Sign in again and retry.');
      const data = await response.json();
      setApiKey(data.api_key);
      setKeyVisible(true);
    } catch (error) {
      setKeyError((error as Error).message || 'Could not load the API key.');
    } finally {
      setKeyLoading(false);
    }
  }

  async function copyApiKey() {
    if (!apiKey) return;
    try {
      await navigator.clipboard.writeText(apiKey);
      setKeyCopied(true);
      window.setTimeout(() => setKeyCopied(false), 1800);
    } catch {
      setKeyError('Clipboard access failed. Select and copy the key manually.');
    }
  }

  async function copyEndpoint(value: string, id: string) {
    try { await navigator.clipboard.writeText(value); setEndpointCopied(id); window.setTimeout(() => setEndpointCopied(''), 1800); }
    catch { setEndpointCopied(`${id}-error`); }
  }

  const endpoint = (label: string, value: string, id: string) => <div className="connection-endpoint"><span>{label}</span><code>{value}</code><button className="text-link endpoint-copy" type="button" onClick={() => void copyEndpoint(value, id)}>{endpointCopied === id ? <Check size={14} /> : <Copy size={14} />}{endpointCopied === id ? 'Copied' : endpointCopied === `${id}-error` ? 'Select to copy' : 'Copy'}</button></div>;

  const gatewayExamples: Record<'python' | 'curl', string> = {
    python: `import os\nfrom openai import OpenAI\n\nclient = OpenAI(\n    base_url="${gatewayUrl}",\n    api_key=os.environ["AEGIS_API_KEY"],\n)\n\nresponse = client.chat.completions.create(\n    model=os.environ["LLM_MODEL"],\n    messages=[{"role": "user", "content": "Summarize this report."}],\n)\nprint(response.choices[0].message.content)`,
    curl: `curl "${gatewayUrl}/chat/completions" \\\n  -H "Authorization: Bearer $AEGIS_API_KEY" \\\n  -H "Content-Type: application/json" \\\n  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Summarize this report."}]}'`,
  };

  const apiExamples: Record<'python' | 'curl', string> = {
    python: `import os\nimport requests\n\nresponse = requests.post(\n    "${scanUrl}",\n    headers={"Authorization": f"Bearer {os.environ['AEGIS_API_KEY']}"},\n    json={"content": user_content, "sourceType": "user"},\n    timeout=10,\n)\nresponse.raise_for_status()\nresult = response.json()\n\nif result["decision"] not in ("ALLOW", "SANITIZE"):\n    raise PermissionError("Aegis blocked or held this request")\nif result["decision"] == "SANITIZE":\n    user_content = result.get("sanitized_content") or user_content\n# Send only the approved content to your model.`,
    curl: `curl "${scanUrl}" \\\n  -H "Authorization: Bearer $AEGIS_API_KEY" \\\n  -H "Content-Type: application/json" \\\n  -d '{"content":"Summarize this report.","sourceType":"user"}'`,
  };

  const sdkExamples: Record<'python' | 'typescript', string> = {
    python: `# From the repository root, install the SDK dependency:\n# pip install httpx\n# PowerShell: $env:PYTHONPATH = "sdk/python"\n\nimport os\nfrom aegis import AegisFirewall\n\nfirewall = AegisFirewall(\n    base_url="${window.location.origin}",\n    api_key=os.environ["AEGIS_API_KEY"],\n)\nresult = firewall.scan(user_content, source_type="user")\nif result.decision not in ("ALLOW", "SANITIZE"):\n    raise PermissionError("Aegis blocked or held this request")\nif result.is_sanitized:\n    user_content = result.sanitized_content or user_content\n# Continue to the model with the approved content.`,
    typescript: `import { AegisFirewall } from "./sdk/node/index.js";\n\nconst firewall = new AegisFirewall({\n  baseUrl: "${window.location.origin}",\n  apiKey: process.env.AEGIS_API_KEY!,\n});\nconst result = await firewall.scan({ content: userContent, sourceType: "user" });\nif (result.decision !== "ALLOW" && result.decision !== "SANITIZE") {\n  throw new Error("Aegis blocked or held this request");\n}\nif (result.decision === "SANITIZE") {\n  userContent = result.sanitizedContent ?? userContent;\n}\n// Continue to the model with the approved content.`,
  };

  const sidecarExample = `services:\n  app:\n    environment:\n      # Route OpenAI-compatible requests through Aegis\n      OPENAI_BASE_URL: http://backend:8000/v1\n      OPENAI_API_KEY: \${AEGIS_API_KEY}\n    networks: [aegis-net]\n\n  # Add these values to the existing Aegis backend service:\n  # UPSTREAM_PROVIDER: openai | ollama | vllm | custom\n  # LLM_BASE_URL: your provider's API base URL\n  # LLM_API_KEY: your provider credential (server-side secret)\n  # LLM_MODEL: your allowed model\n\nnetworks:\n  aegis-net:\n    driver: bridge  # attach the Aegis backend service to this same network`;

  const currentCode = mode === 'gateway'
    ? gatewayExamples[snippet as 'python' | 'curl']
    : mode === 'api'
      ? apiExamples[snippet as 'python' | 'curl']
      : mode === 'sdk'
        ? sdkExamples[snippet as 'python' | 'typescript']
        : sidecarExample;

  function chooseMode(id: Mode) {
    setMode(id);
    setSnippet(id === 'sdk' ? 'python' : id === 'sidecar' ? 'yaml' : 'python');
  }

  return (
    <div className="page-stack integration-page">
      <div className="page-intro">
        <span className="eyebrow">BEFORE YOUR MODEL SEES IT</span>
        <h1>Connect an app</h1>
        <p className="muted">Choose how Aegis fits your application. Every option helps inspect content; the gateway and proxy modes also put Aegis directly in the model request path.</p>
      </div>

      <div className="integration-step-heading"><span>1</span><div><strong>Set up provider routing</strong><small>Configure where approved model requests are sent and manage the Aegis key.</small></div></div>
      <ProviderConfiguration />

      <div className="api-key-card page-api-key-card">
        <div className="api-key-title"><KeyRound size={17} /><div><strong>Aegis API key</strong><span>Use this key from your server-side application.</span></div></div>
        <div className="api-key-value">
          <code>{keyVisible && apiKey ? apiKey : '••••••••••••••••••••••••'}</code>
          <button className="icon-button" type="button" onClick={toggleApiKey} disabled={keyLoading} aria-label={keyVisible ? 'Hide API key' : 'Reveal API key'}>
            {keyLoading ? 'Loading…' : keyVisible ? <><EyeOff size={16} /> Hide</> : <><Eye size={16} /> Reveal</>}
          </button>
          {keyVisible && apiKey && <button className="text-link" type="button" onClick={copyApiKey}>{keyCopied ? <Check size={14} /> : <Copy size={14} />}{keyCopied ? 'Copied' : 'Copy key'}</button>}
        </div>
        {keyError && <p className="api-key-error" role="alert">{keyError}</p>}
        <p className="api-key-warning">Keep this key on your server. Never expose it in browser code or commit it to source control.</p>
      </div>

      <div className="integration-step-heading"><span>2</span><div><strong>Choose a connection mode</strong><small>Pick the option that matches how your application sends model requests.</small></div></div>
      <section className="integration-mode-panel" aria-label="Integration modes">
        <div className="integration-tabs" role="tablist" aria-label="Choose an integration mode">
          {modes.map((item, index) => (
            <button
              key={item.id}
              id={`integration-tab-${item.id}`}
              className={`integration-tab${mode === item.id ? ' is-active' : ''}`}
              role="tab"
              aria-selected={mode === item.id}
              aria-controls={`integration-panel-${item.id}`}
              tabIndex={mode === item.id ? 0 : -1}
              onClick={() => chooseMode(item.id)}
              onKeyDown={(event) => {
                if (event.key === 'ArrowRight' || event.key === 'ArrowLeft') {
                  event.preventDefault();
                  const direction = event.key === 'ArrowRight' ? 1 : -1;
                  const next = (index + direction + modes.length) % modes.length;
                  chooseMode(modes[next].id);
                  document.getElementById(`integration-tab-${modes[next].id}`)?.focus();
                }
              }}
            >
              <span>{item.label}</span><small>{item.summary}</small>
            </button>
          ))}
        </div>

        <section
          className="integration-panel surface"
          id={`integration-panel-${mode}`}
          role="tabpanel"
          aria-labelledby={`integration-tab-${mode}`}
          tabIndex={0}
        >
          {mode === 'gateway' && <>
            <div className="integration-panel-heading"><span className="integration-icon"><Plug size={19} /></span><div><span className="eyebrow">MODE 01 · LIVE GATEWAY</span><h2>OpenAI-compatible gateway</h2><p className="muted">Keep your existing OpenAI client and point its base URL at Aegis. Incoming model requests are inspected before forwarding.</p></div></div>
            <div className="integration-flow"><span>Your app</span><ArrowRight size={16} /><strong><ShieldCheck size={15} /> Aegis</strong><ArrowRight size={16} /><span>Configured model provider</span></div>
            {endpoint('Base URL', gatewayUrl, 'gateway')}
            <p className="muted small integration-hint">Keep the application key and provider credentials in server-side environment variables. Set the allowed upstream provider and model in the configuration panel above.</p>
          </>}

          {mode === 'api' && <>
            <div className="integration-panel-heading"><span className="integration-icon"><Shield size={19} /></span><div><span className="eyebrow">MODE 02 · PRE-FLIGHT CHECK</span><h2>Security API</h2><p className="muted">Call the scan endpoint before sending text to your own model. Your application must enforce the returned decision.</p></div></div>
            {endpoint('POST endpoint', scanUrl, 'scan')}
            <div className="integration-notice"><ShieldCheck size={17} /><p><strong>Enforce every decision.</strong> Stop on <code>BLOCK</code> or <code>REQUIRE_REVIEW</code>; use <code>sanitized_content</code> on <code>SANITIZE</code>. This mode relies on your application to gate the model call.</p></div>
          </>}

          {mode === 'sdk' && <>
            <div className="integration-panel-heading"><span className="integration-icon"><FileCode2 size={19} /></span><div><span className="eyebrow">MODE 03 · CLIENT LIBRARIES</span><h2>SDK</h2><p className="muted">Use the lightweight clients in this repository to call Aegis scans and tool checks without building HTTP requests yourself.</p></div></div>
            <div className="connection-endpoint"><span>SDK source</span><code>sdk/python/aegis · sdk/node/index.ts</code></div>
            <p className="muted small integration-hint">Python requires <code>httpx</code>. The Node client uses built-in <code>fetch</code>. Keep the key on the server; the SDK does not move model traffic unless your application gates its model call on the result.</p>
          </>}

          {mode === 'sidecar' && <>
            <div className="integration-panel-heading"><span className="integration-icon"><Network size={19} /></span><div><span className="eyebrow">MODE 04 · NETWORK ROUTING</span><h2>Sidecar / reverse proxy</h2><p className="muted">Place the Aegis service on your application’s network path, then route compatible model requests to its gateway.</p></div></div>
            <div className="integration-flow"><span>Application container</span><ArrowRight size={16} /><strong><Layers3 size={15} /> Aegis service</strong><ArrowRight size={16} /><span>Model provider</span></div>
            <div className="integration-notice"><Terminal size={17} /><p>This is a deployment pattern, not an extra firewall process created by the dashboard. Join the app and Aegis backend to the same private network, and configure Aegis with the upstream provider and model.</p></div>
          </>}

          <div className="integration-step-heading integration-code-step"><span>3</span><div><strong>Use the integration example</strong><small>Copy the starter code and configure secrets on your application server.</small></div></div>
          <div className="integration-code-header">
            <div><span className="eyebrow">IMPLEMENTATION EXAMPLE</span><h3>{mode === 'sidecar' ? 'Docker Compose settings' : mode === 'api' ? 'Inspect before calling your model' : mode === 'sdk' ? 'Use the client library' : 'Route a chat completion'}</h3></div>
            {mode === 'sidecar' ? <span className="code-language">YAML</span> : (
              <div className="segmented-control" aria-label="Code language">
                {(mode === 'sdk' ? ['python', 'typescript'] : ['python', 'curl']).map((lang) => (
                  <button key={lang} type="button" aria-pressed={snippet === lang} onClick={() => setSnippet(lang as Snippet)}>{lang === 'typescript' ? 'TypeScript' : lang === 'curl' ? 'cURL' : 'Python'}</button>
                ))}
              </div>
            )}
          </div>
          <CodeBlock code={currentCode} language={snippet} />

          <div className="integration-bottom-links">
            <Link className="text-link" to="/health">System status <ArrowRight size={14} /></Link>
            <Link className="text-link" to="/analyzer">Try a content scan <ArrowRight size={14} /></Link>
          </div>
        </section>
      </section>

      <section className="integration-note surface">
        <ShieldCheck size={18} /><p><strong>Need enforced protection?</strong> The gateway and proxy route model traffic through Aegis. With the Security API or SDK, your app needs to honor the scan result before it calls a model.</p>
      </section>
    </div>
  );
}
