import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Clock,
  Terminal,
  Activity,
  RefreshCw,
  ChevronRight,
} from 'lucide-react';
import { fetchOverview, fetchAuditLog, OverviewStats, AuditEntry } from '../api/client';

export const Overview: React.FC = () => {
  const [stats, setStats] = useState<OverviewStats>({
    total: 0,
    allowed: 0,
    blocked: 0,
    require_approval: 0,
    pending_approvals: 0,
  });
  const [recentEvents, setRecentEvents] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [lastRefreshed, setLastRefreshed] = useState<Date>(new Date());
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const loadData = async () => {
    try {
      const [statsData, auditData] = await Promise.all([
        fetchOverview(),
        fetchAuditLog({ limit: 12 }),
      ]);
      setStats(statsData);
      setRecentEvents(auditData);
      setLastRefreshed(new Date());
    } catch (err) {
      console.error('Failed loading telemetry metrics:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, []);

  const total = stats.total || 0;
  const allowRate = total > 0 ? ((stats.allowed / total) * 100).toFixed(1) : '0.0';
  const blockRate = total > 0 ? ((stats.blocked / total) * 100).toFixed(1) : '0.0';

  const getDecisionBadge = (decision: string) => {
    switch (decision) {
      case 'ALLOW':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
            ALLOW
          </span>
        );
      case 'BLOCK':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider uppercase bg-rose-500/10 text-rose-400 border border-rose-500/30 glow-rose">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-400"></span>
            BLOCK
          </span>
        );
      case 'REQUIRE_APPROVAL':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider uppercase bg-amber-500/10 text-amber-300 border border-amber-500/30 glow-amber">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
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
      {/* Telemetry Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-4 border-b border-zinc-800/80 gap-3">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
            <Activity className="w-5 h-5 text-emerald-400" />
            SECURITY TELEMETRY & GATEWAY METRICS
          </h2>
          <p className="text-xs text-zinc-400 font-mono mt-0.5">
            Real-time policy decision stream across MCP clients
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-[11px] font-mono text-zinc-500 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
            SYNC: {lastRefreshed.toLocaleTimeString()}
          </span>
          <button
            onClick={loadData}
            className="p-1.5 rounded bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-300 hover:text-white transition"
            title="Refresh metrics"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* 4 Stat Instruments Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Inspected */}
        <div className="bg-[#11131a] border border-zinc-800/80 rounded p-4 relative overflow-hidden">
          <div className="flex items-center justify-between text-zinc-400 text-xs font-mono uppercase tracking-wider">
            <span>Actions Evaluated</span>
            <Terminal className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white font-mono">{stats.total}</span>
            <span className="text-[11px] font-mono text-zinc-500">invocations</span>
          </div>
          <div className="mt-3 pt-3 border-t border-zinc-800/60 flex items-center justify-between text-[11px] font-mono text-zinc-400">
            <span>Throughput</span>
            <span className="text-cyan-400">Live Wire</span>
          </div>
        </div>

        {/* Allowed */}
        <div className="bg-[#11131a] border border-zinc-800/80 rounded p-4 relative overflow-hidden">
          <div className="flex items-center justify-between text-zinc-400 text-xs font-mono uppercase tracking-wider">
            <span>Permitted (ALLOW)</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-emerald-400 font-mono">{stats.allowed}</span>
            <span className="text-[11px] font-mono text-zinc-500">({allowRate}%)</span>
          </div>
          <div className="mt-3 pt-3 border-t border-zinc-800/60 flex items-center justify-between text-[11px] font-mono text-zinc-400">
            <span>Workspace Safe</span>
            <span className="text-emerald-400 font-bold">✓ Non-Destructive</span>
          </div>
        </div>

        {/* Blocked */}
        <div className="bg-[#11131a] border border-zinc-800/80 rounded p-4 relative overflow-hidden">
          <div className="flex items-center justify-between text-zinc-400 text-xs font-mono uppercase tracking-wider">
            <span>Neutralized (BLOCK)</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-rose-400 font-mono">{stats.blocked}</span>
            <span className="text-[11px] font-mono text-zinc-500">({blockRate}%)</span>
          </div>
          <div className="mt-3 pt-3 border-t border-zinc-800/60 flex items-center justify-between text-[11px] font-mono text-zinc-400">
            <span>Hard Interceptions</span>
            <span className="text-rose-400 font-bold">✕ Hard Denied</span>
          </div>
        </div>

        {/* Pending Approvals */}
        <div className="bg-[#11131a] border border-zinc-800/80 rounded p-4 relative overflow-hidden">
          <div className="flex items-center justify-between text-zinc-400 text-xs font-mono uppercase tracking-wider">
            <span>Human Review Queue</span>
            <Clock className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-amber-400 font-mono">
              {stats.pending_approvals}
            </span>
            <span className="text-[11px] font-mono text-zinc-500">awaiting review</span>
          </div>
          <div className="mt-3 pt-3 border-t border-zinc-800/60 flex items-center justify-between text-[11px] font-mono text-zinc-400">
            <span>Gated Actions</span>
            <span className={stats.pending_approvals > 0 ? 'text-amber-400 animate-pulse' : 'text-zinc-500'}>
              {stats.pending_approvals > 0 ? 'Action Required' : 'Queue Clear'}
            </span>
          </div>
        </div>
      </div>

      {/* Recent Activity Feed */}
      <div className="bg-[#11131a] border border-zinc-800/80 rounded">
        <div className="p-4 border-b border-zinc-800/80 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-zinc-400" />
            <h3 className="text-sm font-bold tracking-tight text-white font-mono uppercase">
              Action Evaluation Stream (Latest Invocations)
            </h3>
          </div>
          <span className="text-[11px] font-mono text-zinc-500">
            Displaying {recentEvents.length} events
          </span>
        </div>

        {recentEvents.length === 0 ? (
          <div className="p-8 text-center text-zinc-500 font-mono text-xs">
            No actions evaluated yet. Trigger tool calls in Cursor to see live security decisions here.
          </div>
        ) : (
          <div className="divide-y divide-zinc-800/60 font-mono text-xs">
            {recentEvents.map((event) => {
              const isExpanded = expandedId === event.entry_id;
              return (
                <div
                  key={event.entry_id}
                  className="hover:bg-zinc-900/40 transition cursor-pointer"
                  onClick={() => setExpandedId(isExpanded ? null : event.entry_id)}
                >
                  <div className="p-3.5 flex flex-col md:flex-row md:items-center justify-between gap-3">
                    <div className="flex items-start md:items-center gap-3 min-w-0 flex-1">
                      {getDecisionBadge(event.decision)}
                      <span className="px-1.5 py-0.5 rounded bg-zinc-800/80 text-zinc-400 text-[10px] uppercase font-bold border border-zinc-700/60 shrink-0">
                        {event.action_type}
                      </span>
                      <span className="text-zinc-200 truncate font-semibold" title={event.action_summary}>
                        {event.action_summary}
                      </span>
                    </div>

                    <div className="flex items-center gap-4 text-zinc-500 text-[11px] shrink-0">
                      {event.duration_ms !== null && (
                        <span>{event.duration_ms}ms</span>
                      )}
                      <span>
                        {new Date(event.timestamp).toLocaleTimeString()}
                      </span>
                      <ChevronRight
                        className={`w-4 h-4 text-zinc-600 transition-transform ${
                          isExpanded ? 'rotate-90 text-zinc-300' : ''
                        }`}
                      />
                    </div>
                  </div>

                  {/* Expanded Detail Drawer */}
                  {isExpanded && (
                    <div className="px-4 pb-4 pt-1 bg-zinc-950/60 border-t border-zinc-800/40 text-xs space-y-2">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px]">
                        <div>
                          <span className="text-zinc-500 block uppercase font-bold mb-1">
                            Policy Reason
                          </span>
                          <p className="text-zinc-300 bg-zinc-900/80 p-2 rounded border border-zinc-800/80">
                            {event.explanation || 'Evaluated against security rule matrix'}
                          </p>
                        </div>
                        <div>
                          <span className="text-zinc-500 block uppercase font-bold mb-1">
                            Matched Security Rules
                          </span>
                          <div className="flex flex-wrap gap-1">
                            {event.matched_policies.length > 0 ? (
                              event.matched_policies.map((p) => (
                                <span
                                  key={p}
                                  className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300 text-[10px] border border-zinc-700"
                                >
                                  {p}
                                </span>
                              ))
                            ) : (
                              <span className="text-zinc-500 italic">None</span>
                            )}
                          </div>
                        </div>
                      </div>

                      {event.execution_output && (
                        <div>
                          <span className="text-zinc-500 block uppercase font-bold mb-1">
                            Execution Output (Redacted)
                          </span>
                          <pre className="bg-zinc-950 p-2.5 rounded border border-zinc-800 text-[11px] text-zinc-300 overflow-x-auto max-h-36">
                            {event.execution_output}
                          </pre>
                        </div>
                      )}

                      <div className="text-[10px] text-zinc-600 flex items-center justify-between pt-1">
                        <span>ACTION_HASH: {event.action_hash}</span>
                        <span>ENTRY_ID: {event.entry_id}</span>
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

export default Overview;
