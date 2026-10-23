import React, { useState, useEffect } from 'react';
import {
  Shield,
  Activity,
  Terminal,
  Clock,
  SlidersHorizontal,
  FileCode2,
  Database,
  Radio,
  Lock,
} from 'lucide-react';
import Overview from './components/Overview';
import ActionInspector from './components/ActionInspector';
import ApprovalQueue from './components/ApprovalQueue';
import AuditLog from './components/AuditLog';
import PolicyConfig from './components/PolicyConfig';
import ThreatLab from './components/ThreatLab';
import { fetchOverview } from './api/client';
import { Flame } from 'lucide-react';

type TabType = 'overview' | 'threatlab' | 'inspect' | 'approvals' | 'audit' | 'policies';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [pendingCount, setPendingCount] = useState<number>(0);
  const [isLive, setIsLive] = useState<boolean>(true);

  // Poll overview stats to update the pending approvals badge in the header tabs
  useEffect(() => {
    const checkPending = async () => {
      try {
        const stats = await fetchOverview();
        setPendingCount(stats.pending_approvals || 0);
        setIsLive(true);
      } catch {
        setIsLive(false);
      }
    };

    checkPending();
    const interval = setInterval(checkPending, 5000);
    return () => clearInterval(interval);
  }, []);

  const tabs: { id: TabType; label: string; icon: React.ReactNode; badge?: number }[] = [
    { id: 'overview', label: 'Telemetry & Overview', icon: <Activity className="w-4 h-4" /> },
    { id: 'threatlab', label: 'Threat Lab & Agent', icon: <Flame className="w-4 h-4 text-rose-400" /> },
    { id: 'inspect', label: 'Action Inspector', icon: <Terminal className="w-4 h-4" /> },
    {
      id: 'approvals',
      label: 'Human Review Queue',
      icon: <Clock className="w-4 h-4" />,
      badge: pendingCount,
    },
    { id: 'audit', label: 'Audit Trail', icon: <FileCode2 className="w-4 h-4" /> },
    { id: 'policies', label: 'Policy Matrix', icon: <SlidersHorizontal className="w-4 h-4" /> },
  ];

  return (
    <div className="min-h-screen bg-[#090a0f] bg-tactical-grid text-zinc-200 flex flex-col font-sans selection:bg-emerald-500/20 selection:text-emerald-300">
      {/* Top Header Bar */}
      <header className="sticky top-0 z-50 bg-[#090a0f]/95 backdrop-blur-md border-b border-zinc-800/80">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between py-3 gap-3">
            {/* Brand Title */}
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded bg-emerald-950/60 border border-emerald-500/40 flex items-center justify-center text-emerald-400 glow-emerald">
                <Shield className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-base font-bold tracking-tight text-white font-mono">
                    AGENT<span className="text-emerald-400">GUARD</span>
                  </span>
                  <span className="text-[10px] font-mono tracking-widest uppercase px-1.5 py-0.5 rounded bg-zinc-800/90 text-zinc-400 border border-zinc-700/60">
                    CORE v0.1.0
                  </span>
                  <span
                    className={`inline-flex items-center gap-1.5 text-[11px] font-mono px-2 py-0.5 rounded-full border ${
                      isLive
                        ? 'text-emerald-400 bg-emerald-950/40 border-emerald-500/30'
                        : 'text-rose-400 bg-rose-950/40 border-rose-500/30'
                    }`}
                  >
                    <span
                      className={`w-1.5 h-1.5 rounded-full ${
                        isLive ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'
                      }`}
                    ></span>
                    {isLive ? 'GATEWAY ARMED' : 'OFFLINE'}
                  </span>
                </div>
                <p className="text-xs text-zinc-400 font-mono">
                  Runtime Security Gateway for Autonomous Tool-Using Agents
                </p>
              </div>
            </div>

            {/* Hardware & System Telemetry Bar */}
            <div className="hidden lg:flex items-center gap-4 text-[11px] font-mono text-zinc-400 bg-zinc-900/60 border border-zinc-800/80 px-3 py-1.5 rounded">
              <div className="flex items-center gap-1.5">
                <Database className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-zinc-500">DB:</span>
                <span className="text-zinc-200">MongoDB 8.2 (27017)</span>
              </div>
              <span className="text-zinc-700">/</span>
              <div className="flex items-center gap-1.5">
                <Radio className="w-3.5 h-3.5 text-cyan-400" />
                <span className="text-zinc-500">MCP:</span>
                <span className="text-zinc-200">JSON-RPC / stdio</span>
              </div>
              <span className="text-zinc-700">/</span>
              <div className="flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-amber-400" />
                <span className="text-zinc-500">DECISION HIERARCHY:</span>
                <span className="text-emerald-400 font-semibold">BLOCK &gt; APPROVE &gt; ALLOW</span>
              </div>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="flex space-x-1 border-t border-zinc-800/60 pt-1.5 overflow-x-auto">
            {tabs.map((tab) => {
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-2 px-3 py-2 text-xs font-mono tracking-tight rounded-t transition border-b-2 whitespace-nowrap ${
                    isActive
                      ? 'border-emerald-400 text-emerald-300 bg-zinc-900/90 shadow-sm'
                      : 'border-transparent text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/40'
                  }`}
                >
                  {tab.icon}
                  <span>{tab.label}</span>
                  {tab.badge !== undefined && tab.badge > 0 && (
                    <span className="px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40 animate-pulse">
                      {tab.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>
      </header>

      {/* Main Workspace Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'overview' && <Overview />}
        {activeTab === 'threatlab' && <ThreatLab onNavigateToApprovals={() => setActiveTab('approvals')} />}
        {activeTab === 'inspect' && <ActionInspector />}
        {activeTab === 'approvals' && <ApprovalQueue />}
        {activeTab === 'audit' && <AuditLog />}
        {activeTab === 'policies' && <PolicyConfig />}
      </main>

      {/* Industrial Footer */}
      <footer className="border-t border-zinc-800/80 bg-[#090a0f] py-4 text-center text-xs font-mono text-zinc-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div>
            AgentGuard Security Protocol &bull; Deterministic Policy Enforcement Boundary
          </div>
          <div className="flex items-center gap-3 text-zinc-400">
            <span>Fail-Closed Engine</span>
            <span>&bull;</span>
            <span>Tamper-Evident SHA-256</span>
            <span>&bull;</span>
            <span className="text-emerald-400">Connected to MongoDB</span>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default App;
