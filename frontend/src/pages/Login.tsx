import { useState } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { ArrowRight, Eye, EyeOff, LockKeyhole } from 'lucide-react';
import { login, isAuthenticated } from '../utils/auth';

export default function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [visible, setVisible] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as any)?.from?.pathname || '/';

  if (isAuthenticated()) return <Navigate to={from} replace />;

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      await login(username.trim(), password);
      setPassword('');
      navigate(from, { replace: true });
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return <main className="login-screen">
    <div className="login-story">
      <div className="brand"><span className="brand-icon"><img className="brand-logo" src="/aegis-shield.png" alt="" /></span><span>Aegis<span className="brand-caption">AI Firewall</span></span></div>
      <div><span className="eyebrow">A boundary for your AI</span><h1>Good ideas in.<br /><span>Threats out.</span></h1><p>Inspect prompts, protect sensitive data, and give your agents room to work safely.</p></div>
    </div>
    <section className="login-form-panel">
      <form className="login-form" onSubmit={submit}>
        <span className="eyebrow">Your security workspace</span>
        <h2>Welcome to Aegis</h2>
        <p className="muted">Sign in with your workspace account.</p>
        <label htmlFor="username">Username</label>
        <input id="username" name="username" type="text" value={username} onChange={event => setUsername(event.target.value)} required autoComplete="username" placeholder="Username" />
        <label htmlFor="password">Password</label>
        <div className="password-field">
          <input id="password" name="password" type={visible ? 'text' : 'password'} value={password} onChange={event => setPassword(event.target.value)} required autoComplete="current-password" placeholder="Password" />
          <button type="button" aria-label={visible ? 'Hide password' : 'Show password'} onClick={() => setVisible(!visible)}>{visible ? <EyeOff size={18} /> : <Eye size={18} />}</button>
        </div>
        {error && <p role="alert" className="notice error">{error}</p>}
        <button className="primary-button" disabled={busy || !username.trim() || !password}>
          {busy ? 'Signing in…' : 'Sign in'}<ArrowRight size={18} />
        </button>
      </form>
    </section>
  </main>;
}
