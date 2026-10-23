import React, { useEffect, useState } from 'react';
import {
  FileCode2,
  Filter,
  Search,
  RefreshCw,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { fetchAuditLog, AuditEntry } from '../api/client';

export const AuditLog: React.FC = () => {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [decisionFilter, setDecisionFilter] = useState<string>('');
  const [actionTypeFilter, setActionTypeFilter] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [limit, setLimit] = useState<number>(50);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const loadEntries = async () => {
    setLoading(true);
    try {
      const data = await fetchAuditLog({
        decision: decisionFilter || undefined,
        action_type: actionTypeFilter || undefined,
        limit,
      });
      setEntries(data);
    } catch (err) {
      console.error('Failed fetching audit log:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadEntries();
  }, [decisionFilter, actionTypeFilter, limit]);

  const filtered = entries.filter((e) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      e.action_summary.toLowerCase().includes(q) ||
      e.action_type.toLowerCase().includes(q) ||
      e.decision.toLowerCase().includes(q) ||
      e.action_hash.toLowerCase().includes(q) ||
      e.matched_policies.some((p) => p.toLowerCase().includes(q))
    );
  });

  const getDecisionBadge = (decision: string) => {
    switch (decision) {
      case 'ALLOW':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            ALLOW
          </span>
        );
      case 'BLOCK':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider uppercase bg-rose-500/10 text-rose-400 border border-rose-500/30">
            BLOCK
          </span>
        );
      case 'REQUIRE_APPROVAL':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider uppercase bg-amber-500/10 text-amber-300 border border-amber-500/30">
            APPROVAL REQUIRED
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono text-zinc-400 border border-zinc-700">
            {decision}
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      <div className="pb-4 border-b border-zinc-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
            <FileCode2 className="w-5 h-5 text-cyan-400" />
            IMMUTABLE AUDIT TRAIL & FORENSIC EVENT LEDGER
          </h2>
          <p className="text-xs text-zinc-400 font-mono mt-0.5">
            Cryptographically timestamped action logs with automated secret redaction
          </p>
        </div>
        <button
          onClick={loadEntries}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-zinc-900 border border-zinc-800 text-xs font-mono text-zinc-300 hover:text-white transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Ledger</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#11131a] border border-zinc-800/80 rounded p-4 font-mono text-xs flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3">
        <div className="flex-1 relative">
          <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search action summary, command, policy ID, or SHA-256 hash..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-zinc-950 border border-zinc-800 rounded pl-9 pr-3 py-2 text-zinc-200 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <Filter className="w-4 h-4 text-zinc-500" />
          <select
            value={decisionFilter}
            onChange={(e) => setDecisionFilter(e.target.value)}
            className="bg-zinc-950 border border-zinc-800 rounded px-2.5 py-2 text-zinc-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Decisions</option>
            <option value="ALLOW">ALLOW</option>
            <option value="BLOCK">BLOCK</option>
            <option value="REQUIRE_APPROVAL">REQUIRE_APPROVAL</option>
          </select>

          <select
            value={actionTypeFilter}
            onChange={(e) => setActionTypeFilter(e.target.value)}
            className="bg-zinc-950 border border-zinc-800 rounded px-2.5 py-2 text-zinc-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Action Types</option>
            <option value="shell_command">shell_command</option>
            <option value="file_read">file_read</option>
            <option value="file_write">file_write</option>
            <option value="file_delete">file_delete</option>
            <option value="directory_list">directory_list</option>
          </select>

          <select
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
            className="bg-zinc-950 border border-zinc-800 rounded px-2.5 py-2 text-zinc-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="25">Limit: 25</option>
            <option value="50">Limit: 50</option>
            <option value="100">Limit: 100</option>
          </select>
        </div>
      </div>

      {/* Ledger Table */}
      <div className="bg-[#11131a] border border-zinc-800/80 rounded overflow-hidden">
        {filtered.length === 0 ? (
          <div className="p-12 text-center text-zinc-500 font-mono text-xs">
            No audit records match the current filters.
          </div>
        ) : (
          <div className="divide-y divide-zinc-800/60 font-mono text-xs">
            {filtered.map((entry) => {
              const isExpanded = expandedId === entry.entry_id;
              return (
                <div key={entry.entry_id} className="hover:bg-zinc-900/30 transition">
                  <div
                    onClick={() => setExpandedId(isExpanded ? null : entry.entry_id)}
                    className="p-3.5 flex flex-col md:flex-row md:items-center justify-between gap-3 cursor-pointer"
                  >
                    <div className="flex items-start md:items-center gap-3 min-w-0 flex-1">
                      {getDecisionBadge(entry.decision)}
                      <span className="px-1.5 py-0.5 rounded bg-zinc-800/80 text-zinc-400 text-[10px] uppercase font-bold border border-zinc-700/60 shrink-0">
                        {entry.action_type}
                      </span>
                      <span className="text-zinc-200 truncate font-semibold" title={entry.action_summary}>
                        {entry.action_summary}
                      </span>
                    </div>

                    <div className="flex items-center gap-4 text-zinc-500 text-[11px] shrink-0">
                      {entry.duration_ms !== null && <span>{entry.duration_ms}ms</span>}
                      <span>{new Date(entry.timestamp).toLocaleString()}</span>
                      {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </div>
                  </div>

                  {/* Expanded Detail View */}
                  {isExpanded && (
                    <div className="p-4 bg-zinc-950/70 border-t border-zinc-800/60 space-y-3 text-xs">
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-[11px]">
                        <div>
                          <span className="text-zinc-500 font-bold block uppercase mb-1">
                            Decision Rationale
                          </span>
                          <p className="text-zinc-300 bg-zinc-900 p-2.5 rounded border border-zinc-800">
                            {entry.explanation || 'Evaluated against policy rules'}
                          </p>
                        </div>
                        <div>
                          <span className="text-zinc-500 font-bold block uppercase mb-1">
                            Matched Policies
                          </span>
                          <div className="flex flex-wrap gap-1">
                            {entry.matched_policies.length > 0 ? (
                              entry.matched_policies.map((p) => (
                                <span
                                  key={p}
                                  className="px-2 py-0.5 rounded bg-zinc-800 text-zinc-300 border border-zinc-700 text-[10px]"
                                >
                                  {p}
                                </span>
                              ))
                            ) : (
                              <span className="text-zinc-500 italic">None</span>
                            )}
                          </div>
                        </div>
                        <div>
                          <span className="text-zinc-500 font-bold block uppercase mb-1">
                            Execution & Approval Status
                          </span>
                          <div className="space-y-1 text-zinc-300">
                            <div>Exec Status: <span className="text-zinc-100">{entry.execution_status || 'Pre-execution inspection'}</span></div>
                            {entry.approval_status && (
                              <div>Approval: <span className="text-amber-400">{entry.approval_status}</span></div>
                            )}
                          </div>
                        </div>
                      </div>

                      {entry.execution_output && (
                        <div>
                          <span className="text-zinc-500 font-bold block uppercase mb-1 text-[11px]">
                            Output Capture (Redacted)
                          </span>
                          <pre className="bg-zinc-950 p-2.5 rounded border border-zinc-800 text-[11px] text-zinc-300 overflow-x-auto max-h-36">
                            {entry.execution_output}
                          </pre>
                        </div>
                      )}

                      <div className="pt-2 border-t border-zinc-800/40 text-[10px] text-zinc-600 flex items-center justify-between">
                        <span>ACTION_HASH: {entry.action_hash}</span>
                        <span>ENTRY_ID: {entry.entry_id}</span>
                      </div>
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

export default AuditLog;
