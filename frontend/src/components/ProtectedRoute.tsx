import { useEffect, useState } from 'react';
import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { isAuthenticated } from '../utils/auth';

export default function ProtectedRoute() {
  const location = useLocation();
  const [verified, setVerified] = useState<boolean | null>(null);
  useEffect(() => {
    let mounted = true;
    fetch('/api/v1/auth/session', { credentials: 'same-origin' }).then(res => { if (mounted) setVerified(res.ok); })
      .catch(() => { if (mounted) setVerified(false); });
    return () => { mounted = false; };
  }, []);

  if (verified === null && isAuthenticated()) return <div className="loading-state">Verifying access…</div>;

  if (!isAuthenticated() || verified === false) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  return <Outlet />;
}
