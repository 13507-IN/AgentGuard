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
} from 'lucide-react';
import { fetchApprovals, approveAction, rejectAction, ApprovalRequest } from '../api/client';

export const ApprovalQueue: React.FC = () => {
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [operatorId, setOperatorId] = useState<string>('lead_security_officer');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const loadApprovals = async () => {
    try {
      const data = await fetchApprovals();
      setApprovals(data);
    } catch (err) {
      console.error('Failed fetching pending approvals:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadApprovals();
    const interval = setInterval(loadApprovals, 4000);
    return () => clearInterval(interval);
  }, []);

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

  return (
    <div className="space-y-6">
      <div className="pb-4 border-b border-zinc-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
            <Clock className="w-5 h-5 text-amber-400" />
            HUMAN REVIEW QUEUE & EXPLICIT SIGN-OFF
          </h2>
          <p className="text-xs text-zinc-400 font-mono mt-0.5">
            Gated operations awaiting manual cryptographic authorization
          </p>
        </div>
        <button
          onClick={loadApprovals}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-zinc-900 border border-zinc-800 text-xs font-mono text-zinc-300 hover:text-white transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Queue</span>
        </button>
      </div>

      {/* Operator Identity Banner */}
      <div className="bg-[#11131a] border border-zinc-800/80 rounded p-4 font-mono text-xs flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
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
            className="bg-zinc-950 border border-zinc-700 px-2.5 py-1 rounded text-zinc-200 text-xs focus:outline-none focus:border-emerald-500 w-full md:w-56"
          />
        </div>
      </div>

      {errorMsg && (
        <div className="bg-rose-500/10 border border-rose-500/40 text-rose-300 px-4 py-2.5 rounded font-mono text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {successMsg && (
        <div className="bg-emerald-500/10 border border-emerald-500/40 text-emerald-300 px-4 py-2.5 rounded font-mono text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}

      {/* Queue Table */}
      <div className="bg-[#11131a] border border-zinc-800/80 rounded overflow-hidden">
        {approvals.length === 0 ? (
          <div className="p-12 text-center text-zinc-500 font-mono text-xs space-y-2">
            <CheckCircle2 className="w-8 h-8 text-emerald-500/40 mx-auto" />
            <p className="text-zinc-400 font-bold">Review Queue is Clear</p>
            <p>No agent actions currently require human approval</p>
          </div>
        ) : (
          <div className="divide-y divide-zinc-800/60 font-mono text-xs">
            {approvals.map((req) => {
              const isExpanded = expandedId === req.approval_id;
              const expiresDate = new Date(req.expires_at);
              const requestedDate = new Date(req.requested_at);

              return (
                <div key={req.approval_id} className="p-4 space-y-3">
                  <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
                    <div className="space-y-1 min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase bg-amber-500/10 text-amber-300 border border-amber-500/30">
                          {req.status}
                        </span>
                        <span className="text-zinc-500 text-[11px]">
                          Requested: {requestedDate.toLocaleTimeString()}
                        </span>
                        <span className="text-zinc-700">|</span>
                        <span className="text-zinc-400 text-[11px]">
                          Expires: {expiresDate.toLocaleTimeString()}
                        </span>
                      </div>
                      <div className="text-sm font-semibold text-zinc-100 truncate">
                        {req.action_summary}
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        onClick={() => handleApprove(req.approval_id)}
                        className="px-3.5 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs uppercase tracking-wider flex items-center gap-1.5 transition glow-emerald"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>Authorize</span>
                      </button>
                      <button
                        onClick={() => handleReject(req.approval_id)}
                        className="px-3.5 py-1.5 rounded bg-rose-600/80 hover:bg-rose-500 text-white font-bold text-xs uppercase tracking-wider flex items-center gap-1.5 transition glow-rose"
                      >
                        <XCircle className="w-3.5 h-3.5" />
                        <span>Deny</span>
                      </button>
                      <button
                        onClick={() => setExpandedId(isExpanded ? null : req.approval_id)}
                        className="p-1.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-400 hover:text-white"
                        title="Toggle payload details"
                      >
                        {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  {/* Hash and Details */}
                  <div className="flex items-center justify-between text-[11px] text-zinc-500 pt-1">
                    <span className="truncate max-w-md">
                      BOUND_HASH: {req.action_hash}
                    </span>
                    <span>ID: {req.approval_id}</span>
                  </div>

                  {/* Expanded JSON Inspector */}
                  {isExpanded && (
                    <div className="p-3 bg-zinc-950 rounded border border-zinc-800 space-y-1.5 text-[11px]">
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
