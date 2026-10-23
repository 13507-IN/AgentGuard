import React, { useState } from 'react';
import {
  Terminal,
  Play,
  Copy,
  Check,
  Layers,
  Sparkles,
} from 'lucide-react';
import { inspectAction, InspectResult } from '../api/client';

export const ActionInspector: React.FC = () => {
  const [actionType, setActionType] = useState<string>('shell_command');
  const [command, setCommand] = useState<string>('rm -rf /');
  const [resource, setResource] = useState<string>('');
  const [workingDir, setWorkingDir] = useState<string>('./workspace');
  const [taskContext, setTaskContext] = useState<string>('Optimize disk space by purging root files');
  const [loading, setLoading] = useState<boolean>(false);
  const [result, setResult] = useState<InspectResult | null>(null);
  const [copiedHash, setCopiedHash] = useState<boolean>(false);

  const presets = [
    {
      label: 'Destructive Wipe (rm -rf /)',
      type: 'shell_command',
      cmd: 'rm -rf /',
      res: '',
      desc: 'Attempting to delete root filesystem',
    },
    {
      label: 'Secret Access (.env file)',
      type: 'file_read',
      cmd: '',
      res: './workspace/.env',
      desc: 'Attempting to inspect credentials',
    },
    {
      label: 'Privilege Escalation (sudo su)',
      type: 'shell_command',
      cmd: 'sudo su - root',
      res: '',
      desc: 'Attempting privilege elevation',
    },
    {
      label: 'Sensitive Deletion (rm temp.txt)',
      type: 'file_delete',
      cmd: '',
      res: './workspace/temp_build.log',
      desc: 'Mutating workspace by removing file',
    },
    {
      label: 'Harmless Read (ls workspace)',
      type: 'directory_list',
      cmd: '',
      res: './workspace',
      desc: 'Read-only directory listing',
    },
  ];

  const handleInspect = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setLoading(true);
    setResult(null);

    try {
      const data = await inspectAction({
        action_type: actionType,
        command: actionType === 'shell_command' ? command : undefined,
        resource: actionType !== 'shell_command' ? resource : undefined,
        working_directory: workingDir || undefined,
        task_context: taskContext || undefined,
      });
      setResult(data);
    } catch (err: any) {
      console.error('Inspection failed:', err);
    } finally {
      setLoading(false);
    }
  };

  const copyHash = () => {
    if (result?.action_hash) {
      navigator.clipboard.writeText(result.action_hash);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
    }
  };

  return (
    <div className="space-y-6">
      <div className="pb-4 border-b border-zinc-800/80">
        <h2 className="text-xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
          <Terminal className="w-5 h-5 text-emerald-400" />
          POLICY EVALUATION & RISK INSPECTOR
        </h2>
        <p className="text-xs text-zinc-400 font-mono mt-0.5">
          Simulate or test agent tool proposals against the active deterministic policy matrix
        </p>
      </div>

      {/* Preset Chips */}
      <div className="space-y-2">
        <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-500 font-bold block">
          Tactical Test Presets
        </span>
        <div className="flex flex-wrap gap-2">
          {presets.map((preset, idx) => (
            <button
              key={idx}
              onClick={() => {
                setActionType(preset.type);
                setCommand(preset.cmd);
                setResource(preset.res);
                setTaskContext(preset.desc);
              }}
              className="px-2.5 py-1 rounded bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 hover:border-zinc-700 text-xs font-mono text-zinc-300 transition"
            >
              {preset.label}
            </button>
          ))}
        </div>
      </div>

      {/* Split-Screen Console */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left Pane: Action Proposal Input */}
        <form
          onSubmit={handleInspect}
          className="bg-[#11131a] border border-zinc-800/80 rounded p-5 space-y-4 font-mono text-xs"
        >
          <div className="flex items-center justify-between pb-3 border-b border-zinc-800/80">
            <span className="font-bold text-zinc-200 uppercase tracking-wider text-xs">
              Proposed Action Parameters
            </span>
            <span className="text-[11px] text-zinc-500">INPUT STAGE</span>
          </div>

          <div>
            <label className="block text-zinc-400 font-bold mb-1.5 uppercase text-[11px]">
              Action Type
            </label>
            <select
              value={actionType}
              onChange={(e) => setActionType(e.target.value)}
              className="w-full bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-zinc-200 focus:outline-none focus:border-emerald-500/80"
            >
              <option value="shell_command">shell_command (Terminal Process)</option>
              <option value="file_read">file_read (Filesystem Read)</option>
              <option value="file_write">file_write (Filesystem Write)</option>
              <option value="file_delete">file_delete (Permanent Deletion)</option>
              <option value="directory_list">directory_list (Workspace Enumeration)</option>
              <option value="network_request">network_request (External HTTP Call)</option>
            </select>
          </div>

          {actionType === 'shell_command' ? (
            <div>
              <label className="block text-zinc-400 font-bold mb-1.5 uppercase text-[11px]">
                Shell Command
              </label>
              <input
                type="text"
                value={command}
                onChange={(e) => setCommand(e.target.value)}
                placeholder="e.g. rm -rf /"
                className="w-full bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-zinc-200 focus:outline-none focus:border-emerald-500/80 font-mono"
              />
            </div>
          ) : (
            <div>
              <label className="block text-zinc-400 font-bold mb-1.5 uppercase text-[11px]">
                Target Resource Path
              </label>
              <input
                type="text"
                value={resource}
                onChange={(e) => setResource(e.target.value)}
                placeholder="e.g. ./workspace/.env"
                className="w-full bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-zinc-200 focus:outline-none focus:border-emerald-500/80 font-mono"
              />
            </div>
          )}

          <div>
            <label className="block text-zinc-400 font-bold mb-1.5 uppercase text-[11px]">
              Working Directory
            </label>
            <input
              type="text"
              value={workingDir}
              onChange={(e) => setWorkingDir(e.target.value)}
              placeholder="./workspace"
              className="w-full bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-zinc-200 focus:outline-none focus:border-emerald-500/80 font-mono"
            />
          </div>

          <div>
            <label className="block text-zinc-400 font-bold mb-1.5 uppercase text-[11px]">
              Task Context / Agent Justification
            </label>
            <textarea
              rows={2}
              value={taskContext}
              onChange={(e) => setTaskContext(e.target.value)}
              placeholder="Why the agent requested this command..."
              className="w-full bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-zinc-200 focus:outline-none focus:border-emerald-500/80 font-mono"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 px-4 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs uppercase tracking-wider flex items-center justify-center gap-2 transition glow-emerald disabled:opacity-50"
          >
            {loading ? (
              <span>Evaluating Deterministic Policies...</span>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Execute Policy Evaluation</span>
              </>
            )}
          </button>
        </form>

        {/* Right Pane: Policy Decision Verdict Console */}
        <div className="bg-[#11131a] border border-zinc-800/80 rounded p-5 space-y-4 font-mono text-xs flex flex-col">
          <div className="flex items-center justify-between pb-3 border-b border-zinc-800/80">
            <span className="font-bold text-zinc-200 uppercase tracking-wider text-xs">
              Security Evaluation Verdict
            </span>
            <span className="text-[11px] text-zinc-500">POLICY ENGINE OUTPUT</span>
          </div>

          {!result ? (
            <div className="flex-1 flex flex-col items-center justify-center text-center p-8 text-zinc-500 space-y-2">
              <Layers className="w-8 h-8 text-zinc-700" />
              <p>Submit an action proposal to view real-time deterministic risk classification</p>
            </div>
          ) : (
            <div className="space-y-4 flex-1">
              {/* Main Verdict Badge */}
              <div
                className={`p-4 rounded border flex items-center justify-between ${
                  result.decision === 'BLOCK'
                    ? 'bg-rose-500/10 border-rose-500/40 text-rose-300 glow-rose'
                    : result.decision === 'ALLOW'
                    ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-300 glow-emerald'
                    : 'bg-amber-500/10 border-amber-500/40 text-amber-300 glow-amber'
                }`}
              >
                <div>
                  <span className="text-[10px] tracking-widest uppercase block font-bold">
                    DECISION OUTCOME
                  </span>
                  <span className="text-2xl font-black tracking-tight">{result.decision}</span>
                </div>
                <div className="text-right">
                  <span className="text-[10px] tracking-widest uppercase block font-bold text-zinc-400">
                    SEVERITY
                  </span>
                  <span className="text-sm font-bold uppercase">{result.risk_category}</span>
                </div>
              </div>

              {/* Matched Rules */}
              <div>
                <span className="text-zinc-500 font-bold text-[10px] uppercase block mb-1">
                  Enforced Policy Identifiers
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {result.matched_policies.length > 0 ? (
                    result.matched_policies.map((p) => (
                      <span
                        key={p}
                        className="px-2 py-0.5 rounded bg-zinc-900 border border-zinc-700/80 text-zinc-300 text-[11px]"
                      >
                        {p}
                      </span>
                    ))
                  ) : (
                    <span className="text-zinc-500 italic">No restrictive policies matched</span>
                  )}
                </div>
              </div>

              {/* Explanation */}
              <div>
                <span className="text-zinc-500 font-bold text-[10px] uppercase block mb-1">
                  Deterministic Reason
                </span>
                <div className="bg-zinc-950 p-3 rounded border border-zinc-800 text-zinc-200">
                  {result.explanation}
                </div>
              </div>

              {/* Safer Alternative */}
              {result.safer_alternative && (
                <div>
                  <span className="text-amber-400 font-bold text-[10px] uppercase block mb-1">
                    Safer Alternative Recommendation
                  </span>
                  <div className="bg-amber-950/20 border border-amber-500/30 p-2.5 rounded text-amber-200 text-[11px]">
                    {result.safer_alternative}
                  </div>
                </div>
              )}

              {/* AI Risk Reasoning */}
              {result.ai_explanation && (
                <div className="bg-zinc-900/60 p-3 rounded border border-zinc-800 space-y-1">
                  <div className="flex items-center gap-1.5 text-cyan-400 text-[11px] font-bold uppercase">
                    <Sparkles className="w-3.5 h-3.5" />
                    <span>AI Risk Explainer (Qwen 2.5-3B)</span>
                  </div>
                  <p className="text-zinc-300 text-[11px] leading-relaxed">
                    {result.ai_explanation}
                  </p>
                </div>
              )}

              {/* Action Hash Chip */}
              <div className="pt-2 border-t border-zinc-800/60 flex items-center justify-between text-[11px] text-zinc-500">
                <span className="truncate max-w-[280px]">
                  HASH: {result.action_hash}
                </span>
                <button
                  type="button"
                  onClick={copyHash}
                  className="flex items-center gap-1 text-zinc-400 hover:text-white transition px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800"
                >
                  {copiedHash ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedHash ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ActionInspector;
