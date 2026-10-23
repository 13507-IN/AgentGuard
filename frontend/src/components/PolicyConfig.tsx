import React, { useEffect, useState } from 'react';
import {
  SlidersHorizontal,
  Lock,
  RefreshCw,
  Terminal,
  FolderLock,
  CheckCircle2,
} from 'lucide-react';
import { fetchPolicies, togglePolicy, PolicyInfo } from '../api/client';

export const PolicyConfig: React.FC = () => {
  const [policies, setPolicies] = useState<PolicyInfo[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  const loadPolicies = async () => {
    setLoading(true);
    try {
      const data = await fetchPolicies();
      setPolicies(data);
    } catch (err) {
      console.error('Failed fetching policies:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPolicies();
  }, []);

  const handleToggle = async (policyId: string, currentEnabled: boolean, mandatory: boolean) => {
    if (mandatory) return;

    const nextState = !currentEnabled;
    // Optimistic update
    setPolicies((prev) =>
      prev.map((p) => (p.policy_id === policyId ? { ...p, enabled: nextState } : p))
    );

    try {
      await togglePolicy(policyId, nextState);
      setStatusMsg(`Policy '${policyId}' set to ${nextState ? 'ACTIVE' : 'DISABLED'}`);
      setTimeout(() => setStatusMsg(null), 3000);
    } catch (err: any) {
      console.error('Failed toggling policy:', err);
      // Revert on failure
      loadPolicies();
    }
  };

  const shellPolicies = policies.filter((p) => p.policy_id.startsWith('shell.'));
  const fsPolicies = policies.filter((p) => p.policy_id.startsWith('fs.'));

  const renderPolicyCard = (p: PolicyInfo) => {
    const isMandatory = p.is_mandatory;

    return (
      <div
        key={p.policy_id}
        className={`bg-[#11131a] border rounded p-4 font-mono text-xs flex flex-col justify-between space-y-3 transition ${
          p.enabled
            ? 'border-zinc-800/80 hover:border-zinc-700'
            : 'border-zinc-900 opacity-60 bg-zinc-950/40'
        }`}
      >
        <div className="space-y-1.5">
          <div className="flex items-center justify-between gap-2">
            <span className="font-bold text-zinc-100 text-sm">{p.name}</span>
            {isMandatory ? (
              <span className="flex items-center gap-1 text-[10px] uppercase font-bold text-rose-400 bg-rose-950/40 border border-rose-800/60 px-2 py-0.5 rounded">
                <Lock className="w-3 h-3" />
                <span>MANDATORY</span>
              </span>
            ) : (
              <span className="text-[10px] uppercase font-bold text-zinc-400 bg-zinc-900 border border-zinc-800 px-2 py-0.5 rounded">
                CONFIGURABLE
              </span>
            )}
          </div>
          <div className="text-[11px] text-zinc-500">{p.policy_id}</div>
          <p className="text-zinc-400 text-xs leading-relaxed pt-1">{p.description}</p>
        </div>

        <div className="pt-3 border-t border-zinc-800/60 flex items-center justify-between">
          <span className="text-[11px] text-zinc-500 uppercase">
            Severity: <span className="text-zinc-300 font-bold">{p.severity}</span>
          </span>

          <div className="flex items-center gap-2">
            <span
              className={`text-[11px] font-bold ${
                p.enabled ? 'text-emerald-400' : 'text-zinc-600'
              }`}
            >
              {p.enabled ? 'ACTIVE' : 'DISABLED'}
            </span>
            <button
              type="button"
              disabled={isMandatory}
              onClick={() => handleToggle(p.policy_id, p.enabled, isMandatory)}
              title={isMandatory ? 'Mandatory policies cannot be disabled' : 'Toggle policy'}
              className={`w-10 h-5 rounded-full p-0.5 transition-colors ${
                isMandatory
                  ? 'bg-zinc-800 cursor-not-allowed opacity-50'
                  : p.enabled
                  ? 'bg-emerald-600'
                  : 'bg-zinc-800'
              }`}
            >
              <div
                className={`w-4 h-4 rounded-full bg-white transition-transform ${
                  p.enabled ? 'translate-x-5' : 'translate-x-0'
                }`}
              />
            </button>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      <div className="pb-4 border-b border-zinc-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
            <SlidersHorizontal className="w-5 h-5 text-emerald-400" />
            DETERMINISTIC SECURITY POLICY MATRIX
          </h2>
          <p className="text-xs text-zinc-400 font-mono mt-0.5">
            Active guardrails governing shell commands, execution limits, and workspace containment
          </p>
        </div>
        <button
          onClick={loadPolicies}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-zinc-900 border border-zinc-800 text-xs font-mono text-zinc-300 hover:text-white transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Reload Policies</span>
        </button>
      </div>

      {statusMsg && (
        <div className="bg-emerald-500/10 border border-emerald-500/40 text-emerald-300 px-4 py-2 rounded font-mono text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span>{statusMsg}</span>
        </div>
      )}

      {/* Shell Policies Section */}
      <div className="space-y-3">
        <div className="flex items-center gap-2 text-sm font-mono text-zinc-200 uppercase font-bold tracking-wider">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span>Process & Shell Execution Policies</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {shellPolicies.map(renderPolicyCard)}
        </div>
      </div>

      {/* Filesystem Policies Section */}
      <div className="space-y-3 pt-4 border-t border-zinc-800/80">
        <div className="flex items-center gap-2 text-sm font-mono text-zinc-200 uppercase font-bold tracking-wider">
          <FolderLock className="w-4 h-4 text-emerald-400" />
          <span>Filesystem Boundary & Secret Containment Policies</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {fsPolicies.map(renderPolicyCard)}
        </div>
      </div>
    </div>
  );
};

export default PolicyConfig;
