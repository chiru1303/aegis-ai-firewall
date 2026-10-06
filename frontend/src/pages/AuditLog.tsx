import React, { useEffect, useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FileText, Download, ShieldCheck, Search, Filter,
  Copy, Check, ArrowUpRight, RefreshCw, Lock
} from 'lucide-react';
import PageHeader from '../components/PageHeader';
import DataTable, { Column } from '../components/DataTable';
import { apiService } from '../services/api';
import { AuditRecord, Decision, RiskLevel } from '../types';
import RiskBadge from '../components/RiskBadge';
import DecisionBadge from '../components/DecisionBadge';
import { formatIST } from '../utils/date';
import toast from 'react-hot-toast';

export default function AuditLog() {
  const navigate = useNavigate();
  const [logs, setLogs] = useState<AuditRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterDecision, setFilterDecision] = useState<string>('all');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const data = await apiService.getAuditLogs().catch(() => null);
      setLogs(data || []);
    } catch (e) {
      console.error(e);
      toast.error('Failed to load audit records');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  const handleCopyId = (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    navigator.clipboard.writeText(id);
    setCopiedId(id);
    toast.success('Audit ID copied');
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      if (filterDecision !== 'all' && log.decision?.toLowerCase() !== filterDecision.toLowerCase()) {
        return false;
      }
      if (filterSeverity !== 'all' && log.riskLevel?.toLowerCase() !== filterSeverity.toLowerCase()) {
        return false;
      }
      return true;
    });
  }, [logs, filterDecision, filterSeverity]);

  const exportCsv = () => {
    const headers = ['id', 'timestamp_ist', 'action', 'decision', 'riskLevel', 'prompt', 'has_pii'];
    const rows = filteredLogs.map(l => [
      l.id,
      `"${formatIST(l.timestamp)}"`,
      l.action,
      l.decision,
      l.riskLevel,
      `"${(l.prompt || '').replace(/"/g, '""')}"`,
      l.has_pii ? 'YES' : 'NO'
    ].join(','));
    const csv = [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegis-audit-ledger-${Date.now()}.csv`;
    a.click();
    toast.success('Audit ledger CSV exported');
  };

  const columns: Column<AuditRecord>[] = [
    {
      key: 'timestamp',
      header: 'Timestamp (IST)',
      width: '180px',
      render: (item) => (
        <span className="font-mono text-xs text-[#C0C8D6] whitespace-nowrap">
          {formatIST(item.timestamp)}
        </span>
      ),
    },
    {
      key: 'id',
      header: 'Request ID',
      width: '170px',
      render: (item) => (
        <div className="flex items-center gap-1.5 font-mono text-xs text-[#4F8CFF]">
          <span className="truncate max-w-[110px]">{item.id}</span>
          <button
            onClick={(e) => handleCopyId(e, item.id)}
            className="p-0.5 rounded hover:bg-[#172033] text-[#8F9BAD] hover:text-[#F4F7FB]"
            title="Copy ID"
          >
            {copiedId === item.id ? <Check size={12} className="text-[#35C98A]" /> : <Copy size={12} />}
          </button>
        </div>
      ),
    },
    {
      key: 'prompt',
      header: 'Prompt Content',
      render: (item) => (
        <div className="flex items-center gap-1.5 max-w-[320px]">
          {item.has_pii && (
            <span className="px-1.5 py-0.5 rounded bg-[rgba(233,180,76,0.15)] border border-[rgba(233,180,76,0.3)] text-[#E9B44C] text-[9px] font-mono shrink-0">
              PII MASKED
            </span>
          )}
          <span className="font-mono text-xs text-[#E1E7F0] truncate block" title={item.prompt || ''}>
            {item.prompt ? (item.prompt.length > 55 ? item.prompt.slice(0, 55) + '...' : item.prompt) : <span className="text-[#8F9BAD] italic">Protected payload</span>}
          </span>
        </div>
      ),
    },
    {
      key: 'action',
      header: 'Action',
      width: '110px',
      render: (item) => (
        <span className="font-mono text-xs text-[#F4F7FB] px-2 py-0.5 rounded bg-[#172033] border border-[#263247]">
          {item.action}
        </span>
      ),
    },
    {
      key: 'decision',
      header: 'Decision',
      width: '110px',
      render: (item) => <DecisionBadge decision={item.decision as Decision} />,
    },
    {
      key: 'riskLevel',
      header: 'Risk Level',
      width: '110px',
      render: (item) => {
        const score = item.riskScore ?? item.risk_score;
        const normScore = score !== undefined && score !== null ? (score <= 1.0 ? score * 100 : score) : undefined;
        const lvl = item.riskLevel || item.risk_level || (normScore !== undefined ? (normScore >= 80 ? RiskLevel.CRITICAL : (normScore >= 50 ? RiskLevel.HIGH : (normScore >= 20 ? RiskLevel.MEDIUM : RiskLevel.LOW))) : RiskLevel.LOW);
        return <RiskBadge level={typeof lvl === 'string' ? lvl.toLowerCase() as RiskLevel : lvl} />;
      },
    },
    {
      key: 'actionLink',
      header: '',
      align: 'right',
      width: '80px',
      render: (item) => (
        <span className="inline-flex items-center text-xs font-mono text-[#4F8CFF] hover:text-[#6A9DFF]">
          Inspect <ArrowUpRight size={12} className="ml-0.5" />
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-5">
      <PageHeader
        title="Security Logs"
        description="Search and inspect all prompt evaluations, policy decisions, and sanitized payloads."
        badge={
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-[rgba(53,201,138,0.12)] border border-[rgba(53,201,138,0.3)] text-xs font-mono font-medium text-[#35C98A]">
            <span className="w-1.5 h-1.5 rounded-full bg-[#35C98A]" />
            Live
          </span>
        }
        actions={
          <div className="flex items-center gap-2">
            <button
              onClick={fetchLogs}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#111827] border border-[#263247] hover:bg-[#172033] text-xs font-medium text-[#F4F7FB] transition-colors"
            >
              <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
              <span>Refresh</span>
            </button>
            <button
              onClick={exportCsv}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#172033] border border-[#263247] hover:bg-[#1D2940] text-xs font-mono text-[#4F8CFF] transition-colors"
            >
              <Download size={13} />
              <span>Export CSV</span>
            </button>
          </div>
        }
      />

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center justify-between p-3 bg-[#111827] border border-[#263247] rounded-lg gap-3">
        <div className="flex items-center gap-2 text-xs font-mono text-[#8F9BAD]">
          <Filter size={14} className="text-[#4F8CFF]" />
          <span>Filters:</span>

          <select
            value={filterDecision}
            onChange={(e) => setFilterDecision(e.target.value)}
            className="bg-[#172033] border border-[#263247] text-[#F4F7FB] rounded px-2.5 py-1 text-xs focus:outline-none focus:border-[#4F8CFF]"
          >
            <option value="all">All Decisions</option>
            <option value="allow">Allow</option>
            <option value="block">Block</option>
            <option value="sanitize">Sanitize</option>
          </select>

          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="bg-[#172033] border border-[#263247] text-[#F4F7FB] rounded px-2.5 py-1 text-xs focus:outline-none focus:border-[#4F8CFF]"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <span className="text-xs font-mono text-[#8F9BAD]">
          Showing {filteredLogs.length} of {logs.length} events
        </span>
      </div>

      {/* Ledger Table */}
      <DataTable
        columns={columns}
        data={filteredLogs}
        loading={loading}
        rowKey={(item) => item.id}
        onRowClick={(item) => navigate(`/attack/${item.id}`)}
        searchPlaceholder="Search logs by prompt, ID, or action..."
        emptyTitle="No log entries found"
        emptyDescription="No events match your current filter parameters."
      />
    </div>
  );
}
