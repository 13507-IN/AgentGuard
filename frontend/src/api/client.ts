const API_BASE = '/api';

export interface AuditEntry {
  entry_id: string;
  action_type: string;
  action_summary: string;
  action_hash: string;
  decision: 'ALLOW' | 'BLOCK' | 'REQUIRE_APPROVAL';
  risk_category: string;
  matched_policies: string[];
  explanation: string;
  ai_explanation: string | null;
  approval_status: string | null;
  execution_status: string | null;
  execution_output: string | null;
  was_simulated: boolean;
  timestamp: string;
  duration_ms: number | null;
}

export interface ApprovalRequest {
  approval_id: string;
  action_hash: string;
  action_summary: string;
  action_details: Record<string, any>;
  risk_category: string;
  requested_at: string;
  expires_at: string;
  status: string;
  decided_by: string | null;
}

export interface OverviewStats {
  total: number;
  allowed: number;
  blocked: number;
  require_approval: number;
  pending_approvals: number;
  backboard_memories?: number;
}

export interface PolicyInfo {
  policy_id: string;
  name: string;
  description: string;
  enabled: boolean;
  is_mandatory: boolean;
  severity: string;
}

export interface InspectResult {
  decision: string;
  risk_category: string;
  matched_policies: string[];
  explanation: string;
  safer_alternative: string | null;
  action_hash: string;
  requires_approval: boolean;
  ai_explanation: string | null;
}

/**
 * Handle HTTP JSON response with detailed error reporting
 */
async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let errorMsg = `HTTP Error ${res.status}: ${res.statusText}`;
    try {
      const errData = await res.json();
      if (errData && (errData.detail || errData.message || errData.error)) {
        errorMsg = errData.detail || errData.message || errData.error;
      }
    } catch {
      // Non-JSON error body
      try {
        const text = await res.text();
        if (text) errorMsg = text;
      } catch {
        // ignore
      }
    }
    throw new Error(errorMsg);
  }
  return res.json() as Promise<T>;
}

/**
 * Fetch overview statistics
 */
export async function fetchOverview(): Promise<OverviewStats> {
  const res = await fetch(`${API_BASE}/overview`, {
    headers: { 'Accept': 'application/json' },
  });
  const data = await handleResponse<any>(res);

  // Normalize shape if nested under data or stats
  const source = data.stats || data.data || data;
  return {
    total: Number(source.total || 0),
    allowed: Number(source.allowed || 0),
    blocked: Number(source.blocked || 0),
    require_approval: Number(source.require_approval || 0),
    pending_approvals: Number(source.pending_approvals || 0),
    backboard_memories: Number(source.backboard_memories || 0),
  };
}

/**
 * Fetch audit log entries with optional filters
 */
export async function fetchAuditLog(params?: {
  decision?: string;
  action_type?: string;
  limit?: number;
}): Promise<AuditEntry[]> {
  const query = new URLSearchParams();
  if (params?.decision && params.decision !== 'ALL') {
    query.set('decision', params.decision);
  }
  if (params?.action_type && params.action_type !== 'ALL') {
    query.set('action_type', params.action_type);
  }
  if (params?.limit) {
    query.set('limit', params.limit.toString());
  }

  const queryString = query.toString();
  const url = `${API_BASE}/audit${queryString ? `?${queryString}` : ''}`;

  const res = await fetch(url, {
    headers: { 'Accept': 'application/json' },
  });
  const data = await handleResponse<any>(res);

  // Return array directly or extract from data/entries property
  if (Array.isArray(data)) {
    return data;
  }
  if (Array.isArray(data.entries)) {
    return data.entries;
  }
  if (Array.isArray(data.audit_log)) {
    return data.audit_log;
  }
  return [];
}

/**
 * Fetch approvals with optional status filter (all, pending, approved, rejected, expired)
 */
export async function fetchApprovals(status: string = 'all'): Promise<ApprovalRequest[]> {
  const url = status ? `${API_BASE}/approvals?status=${encodeURIComponent(status)}` : `${API_BASE}/approvals`;
  const res = await fetch(url, {
    headers: { 'Accept': 'application/json' },
  });
  const data = await handleResponse<any>(res);

  if (Array.isArray(data)) {
    return data;
  }
  if (Array.isArray(data.approvals)) {
    return data.approvals;
  }
  return [];
}

/**
 * Approve an action request
 */
export async function approveAction(approvalId: string, decidedBy: string): Promise<any> {
  const res = await fetch(`${API_BASE}/approvals/${encodeURIComponent(approvalId)}/approve`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify({ decided_by: decidedBy }),
  });
  return handleResponse<any>(res);
}

/**
 * Reject an action request
 */
export async function rejectAction(approvalId: string, decidedBy: string): Promise<any> {
  const res = await fetch(`${API_BASE}/approvals/${encodeURIComponent(approvalId)}/reject`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify({ decided_by: decidedBy }),
  });
  return handleResponse<any>(res);
}

export interface ApprovalExecutionResult {
  status: string;
  approval_id: string;
  success: boolean;
  stdout: string;
  stderr: string;
  exit_code: number | null;
  duration_ms: number;
  command: string;
}

/**
 * Approve and execute an authorized action immediately in workspace
 */
export async function executeApproval(
  approvalId: string,
  decidedBy: string = 'lead_security_officer'
): Promise<ApprovalExecutionResult> {
  const res = await fetch(`${API_BASE}/approvals/${encodeURIComponent(approvalId)}/execute`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify({ decided_by: decidedBy }),
  });
  return handleResponse<ApprovalExecutionResult>(res);
}

/**
 * Inspect a proposed action against security policies and AI analysis
 */
export async function inspectAction(data: {
  action_type: string;
  command?: string;
  resource?: string;
  working_directory?: string;
  task_context?: string;
}): Promise<InspectResult> {
  const res = await fetch(`${API_BASE}/inspect`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify(data),
  });
  return handleResponse<InspectResult>(res);
}

/**
 * Fetch all security policies
 */
export async function fetchPolicies(): Promise<PolicyInfo[]> {
  const res = await fetch(`${API_BASE}/policies`, {
    headers: { 'Accept': 'application/json' },
  });
  const data = await handleResponse<any>(res);

  if (Array.isArray(data)) {
    return data;
  }
  if (Array.isArray(data.policies)) {
    return data.policies;
  }
  return [];
}

/**
 * Toggle a security policy enabled/disabled
 */
export async function togglePolicy(policyId: string, enabled: boolean): Promise<any> {
  const res = await fetch(`${API_BASE}/policies/${encodeURIComponent(policyId)}/toggle`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify({ enabled }),
  });
  return handleResponse<any>(res);
}

export interface AgentStepResult {
  step: number;
  action?: string;
  command?: string;
  status: 'BLOCKED' | 'QUEUED_FOR_APPROVAL' | 'EXECUTED';
  decision: string;
  risk_category?: string;
  matched_policies?: string[];
  reason?: string;
  safer_alternative?: string;
  approval_id?: string;
  message?: string;
  stdout?: string;
  stderr?: string;
  exit_code?: number;
  duration_ms?: number;
}

export interface AgentRunResponse {
  goal: string;
  backboard_memory_enabled: boolean;
  recalled_memories_count: number;
  recalled_memories: string[];
  actions_planned: number;
  actions_blocked: number;
  actions_queued_for_approval: number;
  actions_executed: number;
  steps: AgentStepResult[];
}

export interface BackboardMemoryItem {
  id: string;
  content: string;
  created_at: string | null;
  score: number | null;
  metadata: Record<string, any>;
}

export async function runAutonomousAgent(prompt: string): Promise<AgentRunResponse> {
  const res = await fetch(`${API_BASE}/agent/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify({ prompt }),
  });
  return handleResponse<AgentRunResponse>(res);
}

export async function fetchBackboardMemories(query?: string): Promise<BackboardMemoryItem[]> {
  const url = query && query.trim()
    ? `${API_BASE}/agent/memories?query=${encodeURIComponent(query.trim())}`
    : `${API_BASE}/agent/memories`;
  const res = await fetch(url, {
    headers: { 'Accept': 'application/json' },
  });
  return handleResponse<BackboardMemoryItem[]>(res);
}

export interface BackboardStats {
  enabled: boolean;
  assistant_id?: string;
  total_memories: number;
  max_memories?: number;
  remaining_slots?: number;
}

export async function fetchBackboardStats(): Promise<BackboardStats> {
  const res = await fetch(`${API_BASE}/agent/memories/stats`, {
    headers: { 'Accept': 'application/json' },
  });
  return handleResponse<BackboardStats>(res);
}

export async function deleteBackboardMemory(memoryId: string): Promise<any> {
  const res = await fetch(`${API_BASE}/agent/memories/${encodeURIComponent(memoryId)}`, {
    method: 'DELETE',
    headers: { 'Accept': 'application/json' },
  });
  return handleResponse<any>(res);
}

export async function simulateThreat(scenario: string, command?: string): Promise<AgentRunResponse> {
  const res = await fetch(`${API_BASE}/simulate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify({ scenario, command }),
  });
  return handleResponse<AgentRunResponse>(res);
}

export interface LocalLoopTurn {
  turn: number;
  speaker: string;
  feedback_dispatched?: string;
  proposed_raw: string;
  steps: AgentStepResult[];
}

export interface OllamaLoopResponse {
  goal: string;
  model: string;
  backboard_memory_enabled: boolean;
  recalled_memories_count: number;
  recalled_memories: string[];
  self_correction_triggered: boolean;
  turns: LocalLoopTurn[];
}

export async function runOllamaAgentLoop(prompt: string, model: string = 'qwen2.5:3b'): Promise<OllamaLoopResponse> {
  const res = await fetch(`${API_BASE}/agent/ollama-loop`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify({ prompt, model }),
  });
  return handleResponse<OllamaLoopResponse>(res);
}


