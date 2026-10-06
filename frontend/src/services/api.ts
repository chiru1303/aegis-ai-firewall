import axios from 'axios';
import {
  ScanRequest, ScanResponse, ToolCheckRequest, ToolCheckResponse,
  DashboardMetrics, ThreatFeedItem, AuditRecord, SessionState
} from '../types';

const api = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
});

api.defaults.withCredentials = true;
api.interceptors.response.use(response => response, error => {
  if (error.response?.status === 401) {
    sessionStorage.removeItem('aegis_auth_session');
    if (window.location.pathname !== '/login') window.location.assign('/login');
  }
  return Promise.reject(error);
});

function normalizeScan(d: any): ScanResponse {
  return { ...d, id: d.id || d.request_id, riskScore: d.riskScore ?? d.risk_score ?? 0,
    riskLevel: d.riskLevel ?? d.risk_level ?? 'LOW', sanitizedContent: d.sanitizedContent || d.sanitized_content,
    latencyMs: d.latencyMs ?? d.latency_ms ?? 0,
    detectedAttacks: d.detectedAttacks || (d.attack_types || []).map((at: any) => ({ attackType: at.type || at.attack_type,
      confidence: at.confidence ?? d.risk_score, evidence: d.evidence || [] })),
    policyIdApplied: d.policyIdApplied || d.policy || 'default_zero_trust' };
}

export const apiService = {
  // Scanners
  scanText: (data: ScanRequest): Promise<ScanResponse> => api.post('/scan', data).then(res => normalizeScan(res.data)),

  scanDocument: (file: File, config: Omit<ScanRequest, 'content'>): Promise<ScanResponse> => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('session_id', config.sessionId || crypto.randomUUID());
    const extension = file.name.split('.').pop()?.toLowerCase() || '';
    const sourceByExtension: Record<string, string> = {
      pdf: 'pdf', docx: 'docx', doc: 'docx', html: 'web', htm: 'web', md: 'code',
      json: 'api', xml: 'api', txt: 'user', eml: 'email', py: 'code', js: 'code', ts: 'code',
      java: 'code', c: 'code', cpp: 'code', go: 'code', rb: 'code', png: 'image', jpg: 'image',
      jpeg: 'image', webp: 'image',
    };
    formData.append('source_type', sourceByExtension[extension] || 'unknown');
    return api.post('/scan/document', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    }).then(res => normalizeScan(res.data));
  },

  // Tool Firewall
  checkTool: (data: ToolCheckRequest): Promise<ToolCheckResponse> => api.post('/tool/check', data).then(res => res.data),

  // Analytics & Metrics
  getMetrics: (): Promise<DashboardMetrics> => api.get('/metrics').then(res => res.data),

  getThreatFeed: (limit = 20): Promise<ThreatFeedItem[]> => api.get('/feed', { params: { limit } }).then(res => res.data),

  // Audit
  getAuditLogs: (params?: any): Promise<AuditRecord[]> => api.get('/audit', { params }).then(res => res.data),
  getAuditDetail: (id: string): Promise<AuditRecord> => api.get(`/audit/${id}`).then(res => res.data),

  // Session
  getSessions: (): Promise<SessionState[]> => api.get('/sessions').then(res => res.data),
  getSession: (sessionId: string): Promise<SessionState> => api.get(`/session/${sessionId}`).then(res => res.data),
  quarantineSession: (sessionId: string): Promise<any> => api.post(`/session/${sessionId}/quarantine`).then(res => res.data),

  // System & Policies
  getHealth: (): Promise<any> => api.get('/health').then(res => res.data),
  getPolicies: (): Promise<any[]> => api.get('/policies').then(res => res.data),
  createPolicy: (policyData: any): Promise<any> => api.post('/policies', policyData).then(res => res.data),
  togglePolicy: (id: string): Promise<any> => api.post(`/policies/${id}/toggle`).then(res => res.data),
};
