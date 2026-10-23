import React, { useEffect, useState } from 'react';
import {
  Clock,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  UserCheck,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  Play,
  Loader2,
  Terminal,
  Info,
  TimerOff,
  Filter,
} from 'lucide-react';
import {
  fetchApprovals,
  approveAction,
  rejectAction,
  executeApproval,
  ApprovalRequest,
  ApprovalExecutionResult,
} from '../api/client';

type TabFilter = 'all' | 'pending' | 'approved' | 'expired' | 'rejected';

export const ApprovalQueue: React.FC = () => {
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [activeFilter, setActiveFilter] = useState<TabFilter>('all');
  const [operatorId, setOperatorId] = useState<string>('lead_security_officer');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [executingId, setExecutingId] = useState<string | null>(null);
  const [executionResults, setExecutionResults] = useState<Record<string, ApprovalExecutionResult>>({});

  const loadApprovals = async () => {
    try {
      // Fetch all records so we can calculate live tab counts and display history
      const data = await fetchApprovals('all');
      setApprovals(data);
    } catch (err) {
      console.error('Failed fetching approvals:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadApprovals();
    const interval = setInterval(loadApprovals, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleAuthorizeAndRun = async (id: string) => {
    setErrorMsg(null);
    setSuccessMsg(null);
    setExecutingId(id);
    try {
      const res = await executeApproval(id, operatorId);
      setExecutionResults((prev) => ({ ...prev, [id]: res }));
      setSuccessMsg(`Action authorized and executed (${res.duration_ms}ms) with exit code ${res.exit_code}`);
      loadApprovals();
    } catch (err: any) {
      setErrorMsg(err.message || 'Execution failed');
    } finally {
      setExecutingId(null);
    }
  };

  const handleApprove = async (id: string) => {
    setErrorMsg(null);
    setSuccessMsg(null);
    try {
      await approveAction(id, operatorId);
      setSuccessMsg(`Action approved under operator verification: ${operatorId}`);
      loadApprovals();
    } catch (err: any) {
      setErrorMsg(err.message || 'Approval failed');
    }
  };

  const handleReject = async (id: string) => {
    setErrorMsg(null);
    setSuccessMsg(null);
    try {
      await rejectAction(id, operatorId);
      setSuccessMsg(`Action rejected by operator: ${operatorId}`);
      loadApprovals();
    } catch (err: any) {
      setErrorMsg(err.message || 'Rejection failed');
    }
  };

  // Status counts
  const pendingCount = approvals.filter((a) => (a.status || '').toLowerCase() === 'pending').length;
  const approvedCount = approvals.filter((a) => (a.status || '').toLowerCase() === 'approved').length;
  const expiredCount = approvals.filter((a) => (a.status || '').toLowerCase() === 'expired').length;
  const rejectedCount = approvals.filter((a) => (a.status || '').toLowerCase() === 'rejected').length;

  const filteredApprovals = approvals.filter((item) => {
    const s = (item.status || '').toLowerCase();
    if (activeFilter === 'pending') return s === 'pending';
    if (activeFilter === 'approved') return s === 'approved';
    if (activeFilter === 'expired') return s === 'expired';
    if (activeFilter === 'rejected') return s === 'rejected';
    return true; // 'all'
  });

  return (
    <div className="space-y-6">
      {/* Header Deck */}
      <div className="pb-4 border-b border-zinc-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
            <Clock className="w-5 h-5 text-amber-400" />
            HUMAN REVIEW QUEUE & EXPLICIT SIGN-OFF
          </h2>
          <p className="text-xs text-zinc-400 font-mono mt-0.5">
            Gated operations awaiting manual cryptographic authorization and historical sign-off records
          </p>
        </div>
        <button
          onClick={loadApprovals}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-zinc-900 border border-zinc-800 text-xs font-mono text-zinc-300 hover:text-white transition hover:scale-105"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Queue</span>
        </button>
      </div>

      {/* Operator Identity Banner */}
      <div className="bg-[#11131a] border border-zinc-800/80 rounded-2xl p-4 font-mono text-xs flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-2.5">
          <UserCheck className="w-4 h-4 text-emerald-400 shrink-0" />
          <div>
            <span className="text-zinc-200 font-bold block">
              Active Authorized Reviewer Identity
            </span>
            <span className="text-zinc-500 text-[11px]">
              AI self-approvals (e.g. &apos;ai_agent&apos;, &apos;copilot&apos;, &apos;bot&apos;) are strictly forbidden by protocol
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto">
          <span className="text-zinc-400 text-[11px]">Operator ID:</span>
          <input
            type="text"
            value={operatorId}
            onChange={(e) => setOperatorId(e.target.value)}
            className="bg-zinc-950 border border-zinc-700 px-2.5 py-1.5 rounded-lg text-zinc-200 text-xs focus:outline-none focus:border-emerald-500 w-full md:w-56"
          />
        </div>
      </div>

      {/* Explanatory Context Card for Expiration TTL */}
      <div className="bg-amber-500/5 border border-amber-500/20 rounded-2xl p-4 font-mono text-xs text-zinc-300 flex items-start gap-3">
        <Info className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <span className="font-semibold text-amber-300 block">
            Cryptographic Approval Window & Lifecycle (5-Minute TTL)
          </span>
          <p className="text-[11px] text-zinc-400 leading-relaxed">
            Pending operations enforce a strict <strong>5-minute expiration timer</strong> (<code>AGENTGUARD_APPROVAL_TIMEOUT = 300s</code>) to prevent replay attacks and stale authorizations. 
            When a request expires, its status becomes <code>EXPIRED</code> to ensure untrusted code is never executed retroactively. Historical inspection evaluations are always permanently retained in the <strong>Audit Trail</strong>.
          </p>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center gap-2 border-b border-zinc-800 pb-2 overflow-x-auto font-mono text-xs">
        <span className="text-zinc-500 text-[11px] flex items-center gap-1 mr-1">
          <Filter className="w-3.5 h-3.5" /> Filter:
        </span>
        <button
          onClick={() => setActiveFilter('all')}
          className={`px-3 py-1.5 rounded-lg transition-all flex items-center gap-1.5 ${
            activeFilter === 'all'
              ? 'bg-zinc-800 text-white font-bold border border-zinc-700'
              : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900'
          }`}
        >
          <span>All Records</span>
          <span className="px-1.5 py-0.2 rounded text-[10px] bg-zinc-700/60 text-zinc-300">
            {approvals.length}
          </span>
        </button>

        <button
          onClick={() => setActiveFilter('pending')}
          className={`px-3 py-1.5 rounded-lg transition-all flex items-center gap-1.5 ${
            activeFilter === 'pending'
              ? 'bg-amber-500/20 text-amber-300 font-bold border border-amber-500/40'
              : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900'
          }`}
        >
          <Clock className="w-3 h-3 text-amber-400" />
          <span>Pending (Active)</span>
          {pendingCount > 0 && (
            <span className="px-1.5 py-0.2 rounded text-[10px] bg-amber-500 text-black font-bold animate-pulse">
              {pendingCount}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveFilter('approved')}
          className={`px-3 py-1.5 rounded-lg transition-all flex items-center gap-1.5 ${
            activeFilter === 'approved'
              ? 'bg-emerald-500/20 text-emerald-300 font-bold border border-emerald-500/40'
              : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900'
          }`}
        >
          <CheckCircle2 className="w-3 h-3 text-emerald-400" />
          <span>Approved / Executed</span>
          <span className="px-1.5 py-0.2 rounded text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-800">
            {approvedCount}
          </span>
        </button>

        <button
          onClick={() => setActiveFilter('expired')}
          className={`px-3 py-1.5 rounded-lg transition-all flex items-center gap-1.5 ${
            activeFilter === 'expired'
              ? 'bg-zinc-800 text-zinc-200 font-bold border border-zinc-600'
              : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900'
          }`}
        >
          <TimerOff className="w-3 h-3 text-zinc-400" />
          <span>Expired</span>
          <span className="px-1.5 py-0.2 rounded text-[10px] bg-zinc-800 text-zinc-400 border border-zinc-700">
            {expiredCount}
          </span>
        </button>

        <button
          onClick={() => setActiveFilter('rejected')}
          className={`px-3 py-1.5 rounded-lg transition-all flex items-center gap-1.5 ${
            activeFilter === 'rejected'
              ? 'bg-rose-500/20 text-rose-300 font-bold border border-rose-500/40'
              : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900'
          }`}
        >
          <XCircle className="w-3 h-3 text-rose-400" />
          <span>Denied</span>
          <span className="px-1.5 py-0.2 rounded text-[10px] bg-rose-950 text-rose-400 border border-rose-800">
            {rejectedCount}
          </span>
        </button>
      </div>

      {errorMsg && (
        <div className="bg-rose-500/10 border border-rose-500/40 text-rose-300 px-4 py-2.5 rounded-xl font-mono text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {successMsg && (
        <div className="bg-emerald-500/10 border border-emerald-500/40 text-emerald-300 px-4 py-2.5 rounded-xl font-mono text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}

      {/* Queue List Table */}
      <div className="bg-[#11131a] border border-zinc-800/80 rounded-2xl overflow-hidden">
        {filteredApprovals.length === 0 ? (
          <div className="p-12 text-center text-zinc-500 font-mono text-xs space-y-2">
            <CheckCircle2 className="w-8 h-8 text-emerald-500/40 mx-auto" />
            <p className="text-zinc-300 font-bold">
              {activeFilter === 'pending'
                ? 'No Active Approvals Pending'
                : `No requests found matching filter "${activeFilter}"`}
            </p>
            <p className="text-zinc-500 text-[11px]">
              {activeFilter === 'pending'
                ? 'All proposed agent actions have been evaluated, expired, or approved.'
                : 'Select "All Records" tab to review historical authorizations.'}
            </p>
          </div>
        ) : (
          <div className="divide-y divide-zinc-800/60 font-mono text-xs">
            {filteredApprovals.map((req) => {
              const isExpanded = expandedId === req.approval_id;
              const expiresDate = new Date(req.expires_at);
              const requestedDate = new Date(req.requested_at);
              const statusLower = (req.status || '').toLowerCase();
              const isPending = statusLower === 'pending';
              const isExpired = statusLower === 'expired';
              const isApproved = statusLower === 'approved';
              const isRejected = statusLower === 'rejected';

              return (
                <div
                  key={req.approval_id}
                  className={`p-4 space-y-3 transition-colors ${
                    isPending
                      ? 'bg-amber-500/[0.02] border-l-2 border-l-amber-500'
                      : isExpired
                      ? 'opacity-80 bg-zinc-950/20'
                      : isApproved
                      ? 'bg-emerald-500/[0.02] border-l-2 border-l-emerald-500'
                      : 'bg-rose-500/[0.02] border-l-2 border-l-rose-500'
                  }`}
                >
                  <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
                    <div className="space-y-1 min-w-0 flex-1">
                      <div className="flex items-center flex-wrap gap-2">
                        {/* Status Badge */}
                        {isPending && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase bg-amber-500/15 text-amber-300 border border-amber-500/40 animate-pulse">
                            PENDING SIGN-OFF
                          </span>
                        )}
                        {isExpired && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase bg-zinc-800/80 text-zinc-400 border border-zinc-700 flex items-center gap-1">
                            <TimerOff className="w-3 h-3 text-zinc-400" />
                            EXPIRED (5m TTL)
                          </span>
                        )}
                        {isApproved && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase bg-emerald-500/15 text-emerald-300 border border-emerald-500/40 flex items-center gap-1">
                            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                            APPROVED / EXECUTED
                          </span>
                        )}
                        {isRejected && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase bg-rose-500/15 text-rose-300 border border-rose-500/40 flex items-center gap-1">
                            <XCircle className="w-3 h-3 text-rose-400" />
                            DENIED
                          </span>
                        )}

                        <span className="text-zinc-500 text-[11px]">
                          Requested: {requestedDate.toLocaleTimeString()}
                        </span>
                        <span className="text-zinc-700">|</span>
                        <span
                          className={`text-[11px] ${
                            isExpired ? 'text-zinc-500 line-through' : 'text-zinc-400'
                          }`}
                        >
                          Expired: {expiresDate.toLocaleTimeString()}
                        </span>

                        {req.decided_by && (
                          <>
                            <span className="text-zinc-700">|</span>
                            <span className="text-zinc-400 text-[11px]">
                              Signer: <span className="text-zinc-200 font-semibold">{req.decided_by}</span>
                            </span>
                          </>
                        )}
                      </div>

                      <div className="text-sm font-semibold text-zinc-100 truncate pt-0.5">
                        {req.action_summary}
                      </div>

                      {isExpired && (
                        <p className="text-[11px] text-zinc-500 italic">
                          Authorization timed out after 5 minutes to prevent replay attacks.
                        </p>
                      )}
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      {isPending ? (
                        <>
                          <button
                            disabled={executingId === req.approval_id}
                            onClick={() => handleAuthorizeAndRun(req.approval_id)}
                            className="px-3 py-1.5 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-black font-bold text-xs uppercase tracking-wider flex items-center gap-1.5 transition glow-emerald disabled:opacity-50 hover:scale-105"
                            title="Authorize and immediately execute in controlled workspace"
                          >
                            {executingId === req.approval_id ? (
                              <>
                                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                <span>Running...</span>
                              </>
                            ) : (
                              <>
                                <Play className="w-3.5 h-3.5 fill-black" />
                                <span>Authorize & Run</span>
                              </>
                            )}
                          </button>
                          <button
                            onClick={() => handleApprove(req.approval_id)}
                            className="px-2.5 py-1.5 rounded-xl bg-zinc-900 border border-zinc-700 hover:border-emerald-500 text-zinc-300 hover:text-white font-mono text-xs uppercase tracking-wider flex items-center gap-1.5 transition hover:scale-105"
                            title="Authorize only (no execution)"
                          >
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                            <span>Sign-off</span>
                          </button>
                          <button
                            onClick={() => handleReject(req.approval_id)}
                            className="px-2.5 py-1.5 rounded-xl bg-rose-950/60 border border-rose-800/80 hover:bg-rose-900 text-rose-300 font-mono text-xs uppercase tracking-wider flex items-center gap-1.5 transition hover:scale-105"
                          >
                            <XCircle className="w-3.5 h-3.5" />
                            <span>Deny</span>
                          </button>
                        </>
                      ) : (
                        <div className="px-2.5 py-1 rounded bg-zinc-900/80 border border-zinc-800 text-zinc-500 text-[11px] uppercase tracking-wider">
                          {isExpired ? 'Execution Locked (Expired)' : 'Action Completed'}
                        </div>
                      )}

                      <button
                        onClick={() => setExpandedId(isExpanded ? null : req.approval_id)}
                        className="p-1.5 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-400 hover:text-white transition"
                        title="Toggle payload details"
                      >
                        {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  {/* Hash and Identifier Details */}
                  <div className="flex items-center justify-between text-[11px] text-zinc-500 pt-1">
                    <span className="truncate max-w-md font-mono">
                      BOUND_HASH: {req.action_hash}
                    </span>
                    <span className="font-mono">ID: {req.approval_id}</span>
                  </div>

                  {/* Inline Execution Output Terminal */}
                  {executionResults[req.approval_id] && (
                    <div className="mt-2 bg-[#090a0f] border border-emerald-900/60 rounded-xl p-3 font-mono text-xs">
                      <div className="flex items-center justify-between pb-1.5 border-b border-zinc-800/80 mb-2">
                        <span className="text-emerald-400 font-bold flex items-center gap-1.5">
                          <Terminal className="w-3.5 h-3.5" />
                          <span>Execution Result [EXIT {executionResults[req.approval_id].exit_code ?? 0}]</span>
                        </span>
                        <span className="text-[10px] text-zinc-500">
                          Latency: {executionResults[req.approval_id].duration_ms}ms
                        </span>
                      </div>
                      <div className="text-zinc-400 text-[11px] mb-1">
                        $ {executionResults[req.approval_id].command}
                      </div>
                      <pre className="text-zinc-200 text-xs overflow-x-auto whitespace-pre-wrap bg-black/60 p-2.5 rounded-lg">
                        {executionResults[req.approval_id].stdout ||
                          executionResults[req.approval_id].stderr ||
                          '(Execution returned empty stdout)'}
                      </pre>
                    </div>
                  )}

                  {/* Expanded JSON Inspector */}
                  {isExpanded && (
                    <div className="p-3 bg-zinc-950 rounded-xl border border-zinc-800 space-y-1.5 text-[11px]">
                      <span className="text-zinc-400 font-bold block uppercase text-[10px]">
                        Exact Action Specification (Cryptographically Bound)
                      </span>
                      <pre className="text-zinc-300 overflow-x-auto max-h-40">
                        {JSON.stringify(req.action_details, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};

export default ApprovalQueue;
