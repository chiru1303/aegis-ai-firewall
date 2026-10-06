import { useEffect, useRef, useState } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { Activity, ArrowUpRight, FileClock, LayoutDashboard, LogOut, Menu, Moon, ScanLine, Settings2, ShieldCheck, Sun, X } from 'lucide-react';
import { getAuthSession, logout } from '../utils/auth';

const primary = [
  { name: 'Overview', path: '/', icon: LayoutDashboard },
  { name: 'Scan content', path: '/analyzer', icon: ScanLine },
  { name: 'Activity', path: '/audit', icon: FileClock },
  { name: 'Connect an app', path: '/universal-integration', icon: Settings2 },
  { name: 'Policies', path: '/policies', icon: ShieldCheck },
  { name: 'System status', path: '/health', icon: Activity },
];

export default function Layout() {
  const [open, setOpen] = useState(false);
  const [mobile, setMobile] = useState(() => window.matchMedia('(max-width: 767px)').matches);
  const [light, setLight] = useState(() => {
    try { return localStorage.getItem('aegis_theme') === 'light'; } catch { return false; }
  });
  const sidebarRef = useRef<HTMLElement>(null);
  const menuRef = useRef<HTMLButtonElement>(null);
  const location = useLocation();
  const navigate = useNavigate();
  const session = getAuthSession();
  const operator = ['superadmin', 'admin', 'tenant_admin', 'soc_analyst', 'auditor'].includes(session?.role || '');
  const primaryItems = primary.filter(item => operator || !['/', '/audit', '/policies', '/health'].includes(item.path));
  const title = primary.find(item => item.path === location.pathname)?.name || 'Request details';

  useEffect(() => {
    const media = window.matchMedia('(max-width: 767px)');
    const update = () => setMobile(media.matches);
    media.addEventListener('change', update);
    return () => media.removeEventListener('change', update);
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = light ? 'light' : 'dark';
    try { localStorage.setItem('aegis_theme', light ? 'light' : 'dark'); } catch { /* Theme still applies for this session. */ }
  }, [light]);

  useEffect(() => {
    if (sidebarRef.current) sidebarRef.current.inert = mobile && !open;
    if (mobile && open) sidebarRef.current?.querySelector<HTMLButtonElement>('.mobile-close')?.focus();
  }, [mobile, open]);

  useEffect(() => { setOpen(false); }, [location.pathname]);

  function closeMenu() {
    setOpen(false);
    menuRef.current?.focus();
  }

  function trapFocus(event: React.KeyboardEvent) {
    if (!mobile || !open || event.key !== 'Tab') return;
    const elements = Array.from(sidebarRef.current?.querySelectorAll<HTMLElement>('a, button') || []).filter(element => element.offsetParent !== null);
    const last = elements[elements.length - 1];
    if (event.shiftKey && document.activeElement === elements[0]) { event.preventDefault(); last?.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); elements[0]?.focus(); }
  }

  return <div className="workspace">
    <a className="skip-link" href="#main-content">Skip to content</a>
    {open && <button className="sidebar-backdrop" aria-label="Close navigation" onClick={closeMenu} />}
    <aside ref={sidebarRef} onKeyDown={trapFocus} role={mobile && open ? 'dialog' : undefined} aria-modal={mobile && open ? true : undefined} aria-hidden={mobile && !open} className={`workspace-sidebar ${open ? 'is-open' : ''}`} aria-label="Workspace navigation">
      <NavLink to="/" className="brand" aria-label="Aegis home"><span className="brand-icon"><img className="brand-logo" src="/aegis-shield.png" alt="" /></span><span>Aegis<span className="brand-caption">AI Firewall</span></span></NavLink>
      <button className="mobile-close icon-button" onClick={closeMenu} aria-label="Close menu"><X size={20} /></button>
      <span className="nav-label">Workspace</span>
      <nav aria-label="Main navigation">{primaryItems.map(({ name, path, icon: Icon }) => <NavLink key={path} to={path} end={path === '/'} title={name} aria-label={name} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><Icon size={19} aria-hidden="true" /><span>{name}</span></NavLink>)}</nav>
      <div className="sidebar-bottom">
        <div className="workspace-identity">
          <span className="avatar">A</span>
          <div>
            <strong title="admin">admin</strong>
          </div>
        </div>
        <button className="nav-item" title="Sign out" onClick={async () => { try { await logout(); } finally { navigate('/login'); } }}><LogOut size={18} aria-hidden="true" /><span>Sign out</span></button>
      </div>
    </aside>

    <div className="workspace-body">
      <header className="workspace-header">
        <div><button ref={menuRef} className="mobile-menu icon-button" onClick={() => setOpen(true)} aria-label="Open navigation"><Menu size={22} /></button><span className="muted">Workspace</span><span className="breadcrumb-divider">/</span><strong>{title}</strong></div>
        <div className="workspace-header-actions">
          <button className="theme-toggle icon-button" type="button" onClick={() => setLight(value => !value)} aria-label={`Switch to ${light ? 'dark' : 'light'} theme`} aria-pressed={light} title={`Switch to ${light ? 'dark' : 'light'} theme`}>{light ? <Moon size={18} /> : <Sun size={18} />}</button>
          {location.pathname !== '/analyzer' && <NavLink className="header-action" to="/analyzer">New scan<ArrowUpRight size={16} /></NavLink>}
        </div>
      </header>
      <main id="main-content" tabIndex={-1} className="workspace-content"><Outlet /></main>
      <footer className="workspace-footer">Aegis AI Firewall<span>v1.0.0</span></footer>
    </div>
  </div>;
}
