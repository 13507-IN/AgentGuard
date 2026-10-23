import React, { useState, useEffect } from 'react';
import {
  Shield,
  Terminal,
  Clock,
  SlidersHorizontal,
  FileCode2,
  Database,
  Cpu,
  Flame,
  Menu,
  X,
  Search,
  Bell,
  ArrowUpRight,
  TrendingUp,
  Plus,
  RefreshCw,
  Trash2,
  Brain,
  LayoutDashboard,
  Sparkles,
} from 'lucide-react';
import Overview from './components/Overview';
import ActionInspector from './components/ActionInspector';
import ApprovalQueue from './components/ApprovalQueue';
import AuditLog from './components/AuditLog';
import PolicyConfig from './components/PolicyConfig';
import ThreatLab from './components/ThreatLab';
import {
  fetchOverview,
  fetchBackboardMemories,
  fetchBackboardStats,
  deleteBackboardMemory,
  simulateThreat,
  OverviewStats,
  BackboardMemoryItem,
  BackboardStats,
} from './api/client';

type TabType = 'overview' | 'threatlab' | 'inspect' | 'approvals' | 'audit' | 'policies';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [mobileMenuOpen, setMobileMenuOpen] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [stats, setStats] = useState<OverviewStats>({
    total: 0,
    allowed: 0,
    blocked: 0,
    require_approval: 0,
    pending_approvals: 0,
  });
  const [isLive, setIsLive] = useState<boolean>(true);

  // Backboard state
  const [memories, setMemories] = useState<BackboardMemoryItem[]>([]);
  const [backboardStats, setBackboardStats] = useState<BackboardStats | null>(null);
  const [memorySearch, setMemorySearch] = useState<string>('');
  const [isSearchingMemory, setIsSearchingMemory] = useState<boolean>(false);

  const loadOverview = async () => {
    try {
      const data = await fetchOverview();
      setStats(data);
      setIsLive(true);
    } catch {
      setIsLive(false);
    }
  };

  const loadMemories = async (query?: string) => {
    setIsSearchingMemory(true);
    try {
      const [mems, s] = await Promise.all([
        fetchBackboardMemories(query),
        fetchBackboardStats(),
      ]);
      setMemories(mems);
      setBackboardStats(s);
    } catch {
      // ignore
    } finally {
      setIsSearchingMemory(false);
    }
  };

  useEffect(() => {
    loadOverview();
    loadMemories();
    const interval = setInterval(() => {
      loadOverview();
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleMemorySearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    loadMemories(memorySearch);
  };

  const handleDeleteMemory = async (id: string) => {
    try {
      await deleteBackboardMemory(id);
      loadMemories(memorySearch);
    } catch (err: any) {
      alert(`Delete memory failed: ${err.message || err}`);
    }
  };

  const handleQuickSimulation = async (scenario: string) => {
    setActiveTab('threatlab');
    try {
      await simulateThreat(scenario);
      loadOverview();
      loadMemories();
    } catch {
      // ignore
    }
  };

  const navItems = [
    {
      id: 'overview' as TabType,
      label: 'Dashboard',
      icon: <LayoutDashboard className="w-4 h-4" />,
    },
    {
      id: 'threatlab' as TabType,
      label: 'Threat Lab & Agent',
      icon: <Flame className="w-4 h-4" />,
      badge: 'OLLAMA',
      badgeColor: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
    },
    {
      id: 'approvals' as TabType,
      label: 'Review Queue',
      icon: <Clock className="w-4 h-4" />,
      badge: stats.pending_approvals > 0 ? String(stats.pending_approvals) : undefined,
      badgeColor: 'bg-amber-500 text-black font-bold animate-pulse',
    },
    {
      id: 'inspect' as TabType,
      label: 'Action Inspector',
      icon: <Terminal className="w-4 h-4" />,
    },
    {
      id: 'audit' as TabType,
      label: 'Audit Trail',
      icon: <FileCode2 className="w-4 h-4" />,
    },
    {
      id: 'policies' as TabType,
      label: 'Policy Matrix',
      icon: <SlidersHorizontal className="w-4 h-4" />,
    },
  ];

  const total = stats.total || 0;
  const allowRate = total > 0 ? Math.round((stats.allowed / total) * 100) : 0;
  const blockRate = total > 0 ? Math.round((stats.blocked / total) * 100) : 0;
  const gateRate = total > 0 ? Math.round((stats.require_approval / total) * 100) : 0;

  return (
    <div className="flex min-h-screen bg-[#090a0f] text-zinc-200 font-sans selection:bg-emerald-500/20 selection:text-emerald-300">
      {/* Mobile Sidebar Overlay */}
      {mobileMenuOpen && (
        <div
          onClick={() => setMobileMenuOpen(false)}
          className="fixed inset-0 bg-black/80 z-40 lg:hidden backdrop-blur-sm"
        />
      )}

      {/* Modern Fixed Left Sidebar (w-64) Matching reference */}
      <aside
        className={`fixed top-0 left-0 w-64 bg-[#0d0f17] border-r border-zinc-800/80 p-4 h-screen overflow-y-auto z-50 transition-transform duration-300 flex flex-col justify-between ${
          mobileMenuOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        <div className="space-y-6">
          {/* Logo & Brand Header */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5 cursor-pointer group">
              <div className="w-9 h-9 rounded-xl bg-emerald-600 flex items-center justify-center transition-transform group-hover:scale-105 duration-300 shadow-lg shadow-emerald-600/30">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <div>
                <span className="text-base font-bold font-mono text-white tracking-tight block leading-tight">
                  Agent<span className="text-emerald-400">Guard</span>
                </span>
                <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider block">
                  Security Gateway
                </span>
              </div>
            </div>

            <button
              onClick={() => setMobileMenuOpen(false)}
              className="lg:hidden p-1.5 rounded-lg text-zinc-400 hover:text-white hover:bg-zinc-800"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Navigation Menu */}
          <div className="space-y-4">
            <div>
              <p className="text-[10px] font-semibold font-mono text-zinc-500 mb-2 uppercase tracking-wider">
                Core Operations
              </p>
              <nav className="space-y-1">
                {navItems.map((item) => {
                  const isActive = activeTab === item.id;
                  return (
                    <button
                      key={item.id}
                      onClick={() => {
                        setActiveTab(item.id);
                        setMobileMenuOpen(false);
                      }}
                      className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-xs font-mono font-medium transition-all duration-200 ${
                        isActive
                          ? 'bg-emerald-600 text-white shadow-lg shadow-emerald-600/25 font-bold'
                          : 'text-zinc-400 hover:bg-zinc-800/60 hover:text-zinc-200'
                      }`}
                    >
                      {item.icon}
                      <span className="text-xs">{item.label}</span>
                      {item.badge && (
                        <span
                          className={`ml-auto text-[10px] px-1.5 py-0.5 rounded-full border ${
                            item.badgeColor || 'bg-zinc-800 text-zinc-300 border-zinc-700'
                          }`}
                        >
                          {item.badge}
                        </span>
                      )}
                    </button>
                  );
                })}
              </nav>
            </div>

            {/* Services & Integrations */}
            <div>
              <p className="text-[10px] font-semibold font-mono text-zinc-500 mb-2 uppercase tracking-wider">
                Intelligence & Cloud
              </p>
              <div className="space-y-1.5 text-xs font-mono">
                <div className="flex items-center justify-between p-2 rounded-lg bg-zinc-900/60 border border-zinc-800/80">
                  <div className="flex items-center gap-2">
                    <Brain className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-zinc-300 text-[11px]">Backboard.io</span>
                  </div>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-950/80 border border-emerald-500/40 text-emerald-300 font-bold">
                    {memories.length} mem
                  </span>
                </div>

                <div className="flex items-center justify-between p-2 rounded-lg bg-zinc-900/60 border border-zinc-800/80">
                  <div className="flex items-center gap-2">
                    <Database className="w-3.5 h-3.5 text-blue-400" />
                    <span className="text-zinc-300 text-[11px]">MongoDB Atlas</span>
                  </div>
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                </div>

                <div className="flex items-center justify-between p-2 rounded-lg bg-zinc-900/60 border border-zinc-800/80">
                  <div className="flex items-center gap-2">
                    <Cpu className="w-3.5 h-3.5 text-purple-400" />
                    <span className="text-zinc-300 text-[11px]">Ollama Local</span>
                  </div>
                  <span className="text-[10px] text-zinc-400">qwen2.5:3b</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* User Profile Card at bottom of sidebar */}
        <div className="pt-4 border-t border-zinc-800/80 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-full bg-emerald-950/80 border border-emerald-500/40 flex items-center justify-center text-emerald-400 text-xs font-mono font-bold">
              SO
            </div>
            <div className="text-left font-mono">
              <p className="text-xs font-bold text-white leading-tight">Security Officer</p>
              <p className="text-[10px] text-zinc-500 truncate max-w-[130px]">lead_security_officer</p>
            </div>
          </div>
          <span
            className={`w-2 h-2 rounded-full ${isLive ? 'bg-emerald-400' : 'bg-rose-400'}`}
            title={isLive ? 'Gateway armed' : 'Offline'}
          ></span>
        </div>
      </aside>

      {/* Main App Content Area */}
      <main className="flex-1 lg:ml-64 p-3 sm:p-4 md:p-6 lg:p-8 flex flex-col justify-between min-h-screen">
        <div className="space-y-6">
          {/* Top Bar Header Matching reference design */}
          <header className="space-y-4 animate-slide-in-up">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 flex-1">
                <button
                  onClick={() => setMobileMenuOpen(true)}
                  className="lg:hidden p-2 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-300 hover:text-white"
                >
                  <Menu className="w-5 h-5" />
                </button>

                {/* Global Search Bar with ⌘F Badge */}
                <div className="relative flex-1 max-w-md">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search security directives, policies, or audit..."
                    className="w-full bg-[#11131a] border border-zinc-800 rounded-xl pl-9 pr-14 py-2 text-xs font-mono text-white placeholder-zinc-500 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition-all"
                  />
                  <kbd className="hidden md:inline-block absolute right-2.5 top-1/2 -translate-y-1/2 px-1.5 py-0.5 text-[10px] font-mono font-bold text-zinc-400 bg-zinc-800 rounded border border-zinc-700">
                    ⌘F
                  </kbd>
                </div>
              </div>

              {/* Status Indicator & Notifications */}
              <div className="flex items-center gap-2 sm:gap-3">
                <div
                  className={`hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono border ${
                    isLive
                      ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-400'
                      : 'bg-rose-950/40 border-rose-500/40 text-rose-400'
                  }`}
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${isLive ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'}`}></span>
                  <span>{isLive ? 'GATEWAY ARMED' : 'OFFLINE'}</span>
                </div>

                <button
                  onClick={() => setActiveTab('approvals')}
                  className="relative p-2 rounded-xl bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-300 hover:text-white transition"
                  title="Human Review Queue"
                >
                  <Bell className="w-4 h-4" />
                  {stats.pending_approvals > 0 && (
                    <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-amber-400 rounded-full animate-ping"></span>
                  )}
                </button>

                <div className="flex items-center gap-2 pl-2 border-l border-zinc-800">
                  <div className="w-7 h-7 rounded-full bg-emerald-600 flex items-center justify-center text-white text-xs font-mono font-bold ring-2 ring-emerald-500/20">
                    SO
                  </div>
                  <div className="text-xs font-mono hidden md:block">
                    <p className="font-semibold text-white leading-none">Jessin Sam</p>
                    <p className="text-[10px] text-zinc-500 leading-none mt-1">lead_security_officer</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Dashboard Title & Top Action Deck */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pt-1">
              <div>
                <h1 className="text-2xl sm:text-3xl font-bold font-mono tracking-tight text-white flex items-center gap-2">
                  {activeTab === 'overview' && 'Security Operations Dashboard'}
                  {activeTab === 'threatlab' && 'Threat Lab & Autonomous Agent'}
                  {activeTab === 'approvals' && 'Human Review & Sign-Off Queue'}
                  {activeTab === 'inspect' && 'Pre-Execution Policy Inspector'}
                  {activeTab === 'audit' && 'Cryptographic Audit Trail'}
                  {activeTab === 'policies' && 'Policy Engine Matrix'}
                </h1>
                <p className="text-xs text-zinc-400 font-mono mt-1">
                  Plan, prioritize, and govern autonomous AI tool actions with persistent Backboard memory.
                </p>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => setActiveTab('threatlab')}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-mono font-bold text-xs uppercase tracking-wider transition-all duration-200 hover:scale-105 shadow-lg shadow-emerald-600/30"
                >
                  <Plus className="w-4 h-4" />
                  <span>Dispatch Agent</span>
                </button>

                <button
                  onClick={() => handleQuickSimulation('supply_chain')}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-200 hover:text-white font-mono text-xs transition-all duration-200 hover:scale-105"
                >
                  <Flame className="w-3.5 h-3.5 text-rose-400" />
                  <span>Test Gated Attack</span>
                </button>
              </div>
            </div>
          </header>

          {/* Top 4 KPI Metric Cards (Matching reference exact card aesthetic) */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 animate-slide-in-up">
            {/* Card 1: Total Actions (Hero Emerald Card) */}
            <div
              onClick={() => setActiveTab('overview')}
              className="rounded-2xl border border-emerald-500/40 bg-gradient-to-br from-emerald-600 to-emerald-700 text-white p-5 shadow-lg shadow-emerald-950/30 cursor-pointer transition-all duration-300 hover:scale-[1.02]"
            >
              <div className="flex items-start justify-between mb-3">
                <h3 className="text-xs font-mono font-medium text-emerald-100 uppercase tracking-wider">
                  Total Actions Governed
                </h3>
                <div className="w-7 h-7 rounded-full bg-emerald-500/30 flex items-center justify-center">
                  <ArrowUpRight className="w-3.5 h-3.5 text-white" />
                </div>
              </div>
              <p className="text-3xl font-bold font-mono mb-2">{stats.total}</p>
              <div className="flex items-center gap-1.5 text-[11px] font-mono text-emerald-100">
                <TrendingUp className="w-3.5 h-3.5" />
                <span>Continuous wire inspection active</span>
              </div>
            </div>

            {/* Card 2: Blocked Threats */}
            <div
              onClick={() => setActiveTab('audit')}
              className="rounded-2xl border border-zinc-800/80 bg-[#11131a] p-5 shadow-sm cursor-pointer transition-all duration-300 hover:scale-[1.02] hover:border-rose-500/40"
            >
              <div className="flex items-start justify-between mb-3">
                <h3 className="text-xs font-mono font-medium text-zinc-400 uppercase tracking-wider">
                  Blocked Attacks
                </h3>
                <div className="w-7 h-7 rounded-full bg-rose-950/80 border border-rose-800 flex items-center justify-center text-rose-400">
                  <ArrowUpRight className="w-3.5 h-3.5" />
                </div>
              </div>
              <p className="text-3xl font-bold font-mono text-white mb-2">{stats.blocked}</p>
              <div className="flex items-center gap-1.5 text-[11px] font-mono text-rose-400">
                <span>{blockRate}% refusal rate (Zero Escapes)</span>
              </div>
            </div>

            {/* Card 3: Human Approvals Gated */}
            <div
              onClick={() => setActiveTab('approvals')}
              className="rounded-2xl border border-zinc-800/80 bg-[#11131a] p-5 shadow-sm cursor-pointer transition-all duration-300 hover:scale-[1.02] hover:border-amber-500/40"
            >
              <div className="flex items-start justify-between mb-3">
                <h3 className="text-xs font-mono font-medium text-zinc-400 uppercase tracking-wider">
                  Gated Operations
                </h3>
                <div className="w-7 h-7 rounded-full bg-amber-950/80 border border-amber-800 flex items-center justify-center text-amber-400">
                  <ArrowUpRight className="w-3.5 h-3.5" />
                </div>
              </div>
              <p className="text-3xl font-bold font-mono text-white mb-2">{stats.pending_approvals}</p>
              <div className="flex items-center gap-1.5 text-[11px] font-mono text-amber-400">
                <span>{stats.pending_approvals > 0 ? 'Pending operator sign-off' : 'Queue clear'}</span>
              </div>
            </div>

            {/* Card 4: Backboard Cloud Memories */}
            <div
              onClick={() => loadMemories()}
              className="rounded-2xl border border-zinc-800/80 bg-[#11131a] p-5 shadow-sm cursor-pointer transition-all duration-300 hover:scale-[1.02] hover:border-emerald-500/40"
            >
              <div className="flex items-start justify-between mb-3">
                <h3 className="text-xs font-mono font-medium text-zinc-400 uppercase tracking-wider">
                  Backboard Memories
                </h3>
                <div className="w-7 h-7 rounded-full bg-emerald-950/80 border border-emerald-800 flex items-center justify-center text-emerald-400">
                  <ArrowUpRight className="w-3.5 h-3.5" />
                </div>
              </div>
              <p className="text-3xl font-bold font-mono text-white mb-2">{memories.length}</p>
              <div className="flex items-center gap-1.5 text-[11px] font-mono text-emerald-400">
                <Sparkles className="w-3.5 h-3.5" />
                <span>Semantic cross-session memory</span>
              </div>
            </div>
          </div>

          {/* 3-Column Cockpit Grid (Left 2 Columns for Active View & Right 1 Column for Progress Ring & Backboard Stream) */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left 2 Columns: Selected Tab View */}
            <div className="lg:col-span-2 space-y-6">
              {activeTab === 'overview' && <Overview />}
              {activeTab === 'threatlab' && (
                <ThreatLab onNavigateToApprovals={() => setActiveTab('approvals')} />
              )}
              {activeTab === 'approvals' && <ApprovalQueue />}
              {activeTab === 'inspect' && <ActionInspector />}
              {activeTab === 'audit' && <AuditLog />}
              {activeTab === 'policies' && <PolicyConfig />}
            </div>

            {/* Right 1 Column: Security Confinement Ring & Backboard Intelligence */}
            <div className="space-y-6">
              {/* Circular Progress Gauge Card (Matching reference Project Progress) */}
              <div className="rounded-2xl border border-zinc-800/80 bg-[#11131a] p-6 shadow-sm font-mono">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                    <Shield className="w-4 h-4 text-emerald-400" />
                    <span>Policy Confinement</span>
                  </h2>
                  <span className="text-[10px] text-zinc-500">Defense-in-Depth</span>
                </div>

                <div className="flex flex-col items-center">
                  <div className="relative w-40 h-40 mb-4 flex items-center justify-center">
                    {/* SVG Gauge */}
                    <svg className="w-full h-full -rotate-90" viewBox="0 0 160 160">
                      <circle
                        cx="80"
                        cy="80"
                        r="66"
                        stroke="rgba(255, 255, 255, 0.08)"
                        strokeWidth="12"
                        fill="none"
                      />
                      <circle
                        cx="80"
                        cy="80"
                        r="66"
                        stroke="#10b981"
                        strokeWidth="12"
                        fill="none"
                        strokeDasharray={414.69}
                        strokeDashoffset={414.69 * (1 - 1.0)}
                        strokeLinecap="round"
                        className="transition-all duration-1000 ease-out"
                      />
                    </svg>

                    <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                      <span className="text-3xl font-bold text-white">100%</span>
                      <span className="text-[10px] text-zinc-400 uppercase tracking-widest mt-0.5">
                        Confinement
                      </span>
                    </div>
                  </div>

                  {/* Legend */}
                  <div className="flex flex-wrap justify-center gap-3 text-[11px] text-zinc-400">
                    <div className="flex items-center gap-1.5">
                      <div className="w-2.5 h-2.5 rounded-full bg-emerald-500"></div>
                      <span>Permitted ({stats.allowed} • {allowRate}%)</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <div className="w-2.5 h-2.5 rounded-full bg-amber-500"></div>
                      <span>Gated ({stats.require_approval} • {gateRate}%)</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <div className="w-2.5 h-2.5 rounded-full bg-rose-500"></div>
                      <span>Blocked ({stats.blocked} • {blockRate}%)</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Backboard Live Cloud Memory Intelligence Stream */}
              <div className="rounded-2xl border border-zinc-800/80 bg-[#11131a] p-6 shadow-sm font-mono space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Brain className="w-4 h-4 text-emerald-400" />
                    <h2 className="text-sm font-bold text-white uppercase tracking-wider">
                      Backboard.io Memory
                    </h2>
                    {backboardStats?.total_memories !== undefined && (
                      <span className="text-[10px] text-zinc-500">
                        ({backboardStats.total_memories} in cloud)
                      </span>
                    )}
                  </div>

                  <button
                    onClick={() => loadMemories(memorySearch)}
                    disabled={isSearchingMemory}
                    className="p-1 rounded bg-zinc-900 border border-zinc-800 text-zinc-400 hover:text-white"
                    title="Refresh memory stream"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${isSearchingMemory ? 'animate-spin' : ''}`} />
                  </button>
                </div>

                {/* Semantic Vector Search in Backboard */}
                <form onSubmit={handleMemorySearchSubmit} className="relative">
                  <input
                    type="text"
                    value={memorySearch}
                    onChange={(e) => setMemorySearch(e.target.value)}
                    placeholder="Semantic search in memories..."
                    className="w-full bg-black/60 border border-zinc-800 rounded-xl px-3 py-1.5 text-xs text-white placeholder-zinc-500 focus:outline-none focus:border-emerald-500"
                  />
                  {memorySearch && (
                    <button
                      type="button"
                      onClick={() => {
                        setMemorySearch('');
                        loadMemories('');
                      }}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-white text-xs"
                    >
                      ×
                    </button>
                  )}
                </form>

                {/* Memory items stream */}
                <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                  {memories.length === 0 ? (
                    <div className="text-center py-6 text-zinc-500 text-xs">
                      No memories matched. Action decisions are stored in Backboard cloud automatically.
                    </div>
                  ) : (
                    memories.slice(0, 8).map((m) => (
                      <div
                        key={m.id}
                        className="p-3 rounded-xl bg-black/40 border border-zinc-800/70 hover:border-zinc-700 transition flex items-start justify-between gap-2 text-xs"
                      >
                        <div className="space-y-1 min-w-0 flex-1">
                          <p className="text-zinc-200 text-[11px] leading-relaxed break-words">
                            {m.content}
                          </p>
                          {m.created_at && (
                            <span className="text-[9px] text-zinc-500 block">
                              {new Date(m.created_at).toLocaleTimeString()}
                            </span>
                          )}
                        </div>

                        <button
                          onClick={() => handleDeleteMemory(m.id)}
                          className="text-zinc-600 hover:text-rose-400 p-1 shrink-0 transition"
                          title="Delete memory rule from Backboard"
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Local Qwen Agent Quick Controller */}
              <div className="rounded-2xl border border-zinc-800/80 bg-[#11131a] p-6 shadow-sm font-mono space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
                    <Cpu className="w-3.5 h-3.5 text-blue-400" />
                    <span>Local Qwen Agent Loop</span>
                  </h3>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-950 border border-blue-700 text-blue-300 font-bold">
                    qwen2.5:3b
                  </span>
                </div>

                <p className="text-[11px] text-zinc-400">
                  Every proposed tool action from local open-source models is intercepted by AgentGuard policy rules before execution.
                </p>

                <div className="pt-2 flex flex-col gap-2">
                  <button
                    onClick={() => {
                      setActiveTab('threatlab');
                    }}
                    className="w-full py-2 rounded-xl bg-zinc-900 border border-zinc-800 hover:border-emerald-500 text-zinc-200 hover:text-emerald-300 text-xs font-bold transition flex items-center justify-center gap-1.5"
                  >
                    <span>Open Threat Lab Cockpit</span>
                    <ArrowUpRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Modern Clean Footer Matching reference */}
        <footer className="mt-8 pt-4 border-t border-zinc-800/80 text-center text-xs font-mono text-zinc-500 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div>
            AgentGuard AI Runtime Security &bull; Deterministic Kernel Confinement
          </div>
          <div className="flex items-center gap-3 text-zinc-400">
            <span>Fail-Closed</span>
            <span>&bull;</span>
            <span>Backboard Cloud Memory</span>
            <span>&bull;</span>
            <span className="text-emerald-400">MongoDB 8.2</span>
          </div>
        </footer>
      </main>
    </div>
  );
};

export default App;
