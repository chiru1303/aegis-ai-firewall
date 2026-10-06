import React, { Suspense, lazy } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';

import Layout from './components/Layout';
import ErrorBoundary from './components/ErrorBoundary';
import ProtectedRoute from './components/ProtectedRoute';

const Login = lazy(() => import('./pages/Login'));
const Dashboard = lazy(() => import('./pages/Dashboard'));

const RequestAnalyzer = lazy(() => import('./pages/RequestAnalyzer'));
const AttackDetail = lazy(() => import('./pages/AttackDetail'));
const Policies = lazy(() => import('./pages/Policies'));
const UniversalIntegration = lazy(() => import('./pages/UniversalIntegration'));
const AuditLog = lazy(() => import('./pages/AuditLog'));
const SystemHealth = lazy(() => import('./pages/SystemHealth'));

function PageLoader() {
  return (
    <div className="flex h-64 items-center justify-center">
      <div className="flex items-center gap-3 text-xs font-mono text-[#8F9BAD]">
        <div className="w-4 h-4 rounded-full border-2 border-[#4F8CFF] border-t-transparent animate-spin" />
        <span>Loading workspace…</span>
      </div>
    </div>
  );
}

function App() {
  return (
    <div className="min-h-screen bg-[#0B1020] text-[#F4F7FB] font-sans selection:bg-[#4F8CFF] selection:text-white">
      <Toaster
        position="top-right"
        toastOptions={{
          className: '!bg-[#111827] !text-[#F4F7FB] !border !border-[#263247] !font-mono !text-xs !shadow-lg',
          style: { background: '#111827', color: '#F4F7FB', border: '1px solid #263247' }
        }}
      />
      <ErrorBoundary>
        <Suspense fallback={<PageLoader />}>
          <Routes>
            {/* Public route */}
            <Route path="/login" element={<Login />} />

            {/* Protected routes */}
            <Route element={<ProtectedRoute />}>
              <Route path="/" element={<Layout />}>
                <Route index element={<Dashboard />} />
                <Route path="feed" element={<Navigate to="/audit" replace />} />
                <Route path="incidents" element={<Navigate to="/audit" replace />} />
                <Route path="logs" element={<Navigate to="/audit" replace />} />
                <Route path="analyzer" element={<RequestAnalyzer />} />
                <Route path="attack/:id" element={<AttackDetail />} />
                <Route path="policies" element={<Policies />} />
                <Route path="playground" element={<Navigate to="/universal-integration" replace />} />
                <Route path="universal-integration" element={<UniversalIntegration />} />
                <Route path="integration" element={<Navigate to="/universal-integration" replace />} />
                <Route path="audit" element={<AuditLog />} />
                <Route path="health" element={<SystemHealth />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Route>
            </Route>
          </Routes>
        </Suspense>
      </ErrorBoundary>
    </div>
  );
}

export default App;
