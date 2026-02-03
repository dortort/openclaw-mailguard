/**
 * Tool Firewall Policy Module
 * Enforces provenance-aware tool access control for Gmail-origin sessions
 */

import type {
  ToolPolicyContext,
  ToolPolicyDecision,
  MailGuardConfig,
  RiskScore,
  EmailProvenance,
  ApprovalRequest,
  PlannedAction,
  SideEffectPlan,
  Logger,
} from '../types.js';
import { randomUUID } from 'crypto';

// ============================================================================
// Rate Limiter
// ============================================================================

// Rate limiter for approval operations
class ApprovalRateLimiter {
  private attempts: Map<string, { count: number; windowStart: number }> = new Map();
  private readonly maxAttempts = 10;
  private readonly windowMs = 60000; // 1 minute

  check(sessionId: string): boolean {
    const now = Date.now();
    const key = sessionId;
    const entry = this.attempts.get(key);

    if (!entry || now - entry.windowStart > this.windowMs) {
      this.attempts.set(key, { count: 1, windowStart: now });
      return true;
    }

    if (entry.count >= this.maxAttempts) {
      return false;
    }

    entry.count++;
    return true;
  }

  cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.attempts.entries()) {
      if (now - entry.windowStart > this.windowMs) {
        this.attempts.delete(key);
      }
    }
  }
}

// ============================================================================
// Tool Categories
// ============================================================================

/**
 * Tools that are always safe for Gmail-origin sessions
 */
const SAFE_TOOLS = new Set([
  // Read-only information tools
  'summarize',
  'summarize_text',
  'classify',
  'classify_email',
  'extract_entities',
  'analyze_sentiment',
  'translate',
  'search_knowledge',

  // Draft/preview tools (don't actually send)
  'draft_reply',
  'draft_email',
  'preview_action',
  'format_text',

  // Labeling proposals (require confirmation)
  'propose_label',
  'suggest_labels',
  'categorize',

  // Calendar read-only
  'check_availability',
  'list_events',

  // Contact lookup (read-only)
  'lookup_contact',
  'search_contacts',
]);

/**
 * Tools that require approval but can be allowed for Gmail-origin
 */
const APPROVAL_REQUIRED_TOOLS = new Set([
  'send_email',
  'send_reply',
  'forward_email',
  'apply_label',
  'remove_label',
  'move_to_folder',
  'archive_email',
  'mark_read',
  'mark_unread',
  'create_draft',
  'update_draft',
  'delete_draft',
  'create_calendar_event',
  'update_calendar_event',
  'create_contact',
  'update_contact',
]);

/**
 * Tools that are ALWAYS denied for Gmail-origin sessions
 * These represent "hard" denials that cannot be bypassed
 */
const HARD_DENIED_TOOLS = new Set([
  // Browser/web automation
  'browser_control',
  'browser_navigate',
  'browser_click',
  'browser_type',
  'browser_screenshot',
  'puppeteer',
  'playwright',
  'selenium',

  // Code/command execution
  'exec',
  'shell',
  'bash',
  'powershell',
  'terminal',
  'run_command',
  'execute_code',
  'eval',
  'code_execute',

  // Filesystem modification
  'filesystem_write',
  'filesystem_edit',
  'filesystem_delete',
  'write_file',
  'edit_file',
  'delete_file',
  'create_file',
  'patch',
  'patch_file',

  // Network operations (unrestricted)
  'web_fetch_unrestricted',
  'http_request',
  'make_request',

  // Email deletion (destructive)
  'delete_email',
  'permanently_delete',
  'empty_trash',

  // Account/settings modification
  'update_settings',
  'change_password',
  'create_filter',
  'delete_filter',
  'manage_forwarding',

  // OAuth/credentials
  'oauth_request',
  'store_credentials',
  'manage_tokens',
]);

// ============================================================================
// Policy Enforcement
// ============================================================================

export class ToolFirewall {
  private config: MailGuardConfig;
  private logger: Logger;
  private sessionPolicies: Map<string, SessionPolicy> = new Map();
  private approvalRateLimiter = new ApprovalRateLimiter();
  private readonly maxSessions = 10000;

  constructor(config: MailGuardConfig, logger: Logger) {
    this.config = config;
    this.logger = logger;
  }

  /**
   * Initialize session policy based on provenance
   */
  initializeSession(
    sessionId: string,
    provenance: EmailProvenance | undefined,
    riskScore: RiskScore | undefined
  ): void {
    // Evict oldest session if at capacity
    if (this.sessionPolicies.size >= this.maxSessions) {
      // Find and delete oldest session by createdAt
      let oldestId: string | undefined;
      let oldestTime = Infinity;
      for (const [id, policy] of this.sessionPolicies.entries()) {
        if (policy.createdAt.getTime() < oldestTime) {
          oldestTime = policy.createdAt.getTime();
          oldestId = id;
        }
      }
      if (oldestId) {
        this.sessionPolicies.delete(oldestId);
        this.logger.debug('Evicted oldest session due to capacity', { sessionId: oldestId });
      }
    }

    const policy: SessionPolicy = {
      sessionId,
      source: provenance?.source ?? 'direct',
      riskScore: riskScore?.score ?? 0,
      isGmailOrigin: provenance?.source === 'gmail',
      isAllowlistedSender: provenance?.isAllowlistedDomain ?? false,
      createdAt: new Date(),
      deniedTools: new Set(this.config.deniedTools),
      approvalRequiredActions: new Set(this.config.approvalRequiredActions),
      pendingApprovals: [],
      toolCallHistory: [],
    };

    // Add hard-denied tools
    for (const tool of HARD_DENIED_TOOLS) {
      policy.deniedTools.add(tool);
    }

    this.sessionPolicies.set(sessionId, policy);

    this.logger.info('Session policy initialized', {
      sessionId,
      source: policy.source,
      riskScore: policy.riskScore,
      deniedToolCount: policy.deniedTools.size,
    });
  }

  /**
   * Check if a tool request is allowed
   */
  checkToolAccess(context: ToolPolicyContext): ToolPolicyDecision {
    const policy = this.sessionPolicies.get(context.sessionId);

    // If no policy exists, this isn't a Gmail-origin session - allow with standard checks
    if (!policy) {
      return {
        allowed: true,
        reason: 'No Gmail-origin policy active for this session',
        requiresApproval: false,
      };
    }

    const tool = normalizeToolName(context.requestedTool);

    // Check hard denials first (cannot be bypassed)
    if (HARD_DENIED_TOOLS.has(tool) || policy.deniedTools.has(tool)) {
      this.logger.warn('Tool access denied (hard denial)', {
        sessionId: context.sessionId,
        tool,
        reason: 'Gmail-origin session cannot use this tool',
      });

      policy.toolCallHistory.push({
        tool,
        timestamp: new Date(),
        decision: 'denied',
        reason: 'hard_denial',
      });

      return {
        allowed: false,
        reason: `Tool "${tool}" is not available for email-triggered sessions. This is a security restriction that cannot be bypassed.`,
        requiresApproval: false,
        denialType: 'hard',
        alternatives: getSafeAlternatives(tool),
      };
    }

    // Check if tool is in the safe list
    if (SAFE_TOOLS.has(tool)) {
      policy.toolCallHistory.push({
        tool,
        timestamp: new Date(),
        decision: 'allowed',
        reason: 'safe_tool',
      });

      return {
        allowed: true,
        reason: 'Tool is approved for Gmail-origin sessions',
        requiresApproval: false,
      };
    }

    // Check if tool requires approval
    if (APPROVAL_REQUIRED_TOOLS.has(tool) || policy.approvalRequiredActions.has(tool)) {
      this.logger.info('Tool requires approval', {
        sessionId: context.sessionId,
        tool,
      });

      policy.toolCallHistory.push({
        tool,
        timestamp: new Date(),
        decision: 'pending_approval',
        reason: 'requires_approval',
      });

      // Determine approval type based on config
      const approvalType = this.config.lobsterIntegration.enabled ? 'lobster' : 'exec-approval';

      return {
        allowed: false,
        reason: `Tool "${tool}" requires operator approval before execution`,
        requiresApproval: true,
        approvalType,
        denialType: 'soft',
      };
    }

    // For Gmail-origin sessions, deny unknown tools by default (fail-secure)
    if (policy.isGmailOrigin) {
      this.logger.warn('Tool denied (not in allowlist for Gmail-origin)', {
        sessionId: context.sessionId,
        tool,
      });

      policy.toolCallHistory.push({
        tool,
        timestamp: new Date(),
        decision: 'denied',
        reason: 'not_in_allowlist',
      });

      return {
        allowed: false,
        reason: `Tool "${tool}" is not in the allowlist for email-triggered sessions. Only explicitly approved tools are permitted.`,
        requiresApproval: true,
        denialType: 'soft',
      };
    }

    // For non-Gmail sessions, allow with logging
    this.logger.info('Tool allowed (non-Gmail session)', {
      sessionId: context.sessionId,
      tool,
    });

    policy.toolCallHistory.push({
      tool,
      timestamp: new Date(),
      decision: 'allowed',
      reason: 'non_gmail_session',
    });

    return {
      allowed: true,
      reason: 'Tool allowed for non-email-triggered sessions',
      requiresApproval: false,
    };
  }

  /**
   * Create a side effect plan for actions requiring approval
   */
  createSideEffectPlan(
    sessionId: string,
    actions: PlannedAction[]
  ): SideEffectPlan {
    const plan: SideEffectPlan = {
      id: generateId(),
      sessionId,
      actions,
      status: 'pending_approval',
      approvals: [],
    };

    const policy = this.sessionPolicies.get(sessionId);
    if (policy) {
      for (const action of actions) {
        if (action.requiresApproval) {
          const approval: ApprovalRequest = {
            id: generateId(),
            type: 'side_effect',
            action: action.type,
            details: action.parameters,
            riskContext: {
              emailFrom: '',
              emailSubject: '',
              riskScore: policy.riskScore,
              signals: [],
            },
            preview: action.description,
            createdAt: new Date(),
            expiresAt: new Date(Date.now() + this.config.lobsterIntegration.timeout * 1000),
            status: 'pending',
          };
          plan.approvals.push(approval);
          policy.pendingApprovals.push(approval);
        }
      }
    }

    return plan;
  }

  /**
   * Resolve an approval request
   */
  resolveApproval(
    sessionId: string,
    approvalId: string,
    approved: boolean,
    resolvedBy: string
  ): boolean {
    const policy = this.sessionPolicies.get(sessionId);
    if (!policy) return false;

    // Rate limiting check
    if (!this.approvalRateLimiter.check(sessionId)) {
      this.logger.warn('Approval rate limit exceeded', { sessionId, approvalId });
      return false;
    }

    const approval = policy.pendingApprovals.find(a => a.id === approvalId);
    if (!approval) return false;

    approval.status = approved ? 'approved' : 'denied';
    approval.resolvedBy = resolvedBy;
    approval.resolvedAt = new Date();

    this.logger.info('Approval resolved', {
      sessionId,
      approvalId,
      approved,
      resolvedBy,
      action: approval.action,
    });

    return true;
  }

  /**
   * Get pending approvals for a session
   */
  getPendingApprovals(sessionId: string): ApprovalRequest[] {
    const policy = this.sessionPolicies.get(sessionId);
    if (!policy) return [];

    return policy.pendingApprovals.filter(a => a.status === 'pending');
  }

  /**
   * Get tool call history for a session
   */
  getToolCallHistory(sessionId: string): ToolCallRecord[] {
    const policy = this.sessionPolicies.get(sessionId);
    return policy?.toolCallHistory ?? [];
  }

  /**
   * Clean up expired sessions
   */
  cleanupExpiredSessions(maxAgeMs: number = 3600000): void {
    const now = Date.now();

    for (const [sessionId, policy] of this.sessionPolicies.entries()) {
      const lastActivity = policy.toolCallHistory.length > 0
        ? policy.toolCallHistory[policy.toolCallHistory.length - 1]?.timestamp.getTime() ?? policy.createdAt.getTime()
        : policy.createdAt.getTime();

      if (now - lastActivity > maxAgeMs) {
        this.sessionPolicies.delete(sessionId);
        this.logger.debug('Session policy expired', { sessionId });
      }
    }
  }

  /**
   * Get denied tools for a session
   */
  getDeniedTools(sessionId: string): string[] {
    const policy = this.sessionPolicies.get(sessionId);
    if (!policy) return [];
    return Array.from(policy.deniedTools);
  }
}

// ============================================================================
// Supporting Types
// ============================================================================

interface SessionPolicy {
  sessionId: string;
  source: 'gmail' | 'direct' | 'api' | 'hook';
  riskScore: number;
  isGmailOrigin: boolean;
  isAllowlistedSender: boolean;
  createdAt: Date;
  deniedTools: Set<string>;
  approvalRequiredActions: Set<string>;
  pendingApprovals: ApprovalRequest[];
  toolCallHistory: ToolCallRecord[];
}

interface ToolCallRecord {
  tool: string;
  timestamp: Date;
  decision: 'allowed' | 'denied' | 'pending_approval';
  reason: string;
}

// ============================================================================
// Helper Functions
// ============================================================================

function normalizeToolName(tool: string): string {
  return tool.toLowerCase().replace(/[^a-z0-9_]/g, '_');
}

function generateId(): string {
  return randomUUID();
}

/**
 * Suggest safe alternatives for denied tools
 */
function getSafeAlternatives(tool: string): string[] {
  const alternatives: Record<string, string[]> = {
    'exec': ['No direct alternative - describe the desired outcome instead'],
    'shell': ['No direct alternative - describe the desired outcome instead'],
    'browser_control': ['web_fetch (with restrictions)', 'describe what information is needed'],
    'browser_navigate': ['Provide the URL for manual review'],
    'filesystem_write': ['draft_reply (to share content in email)'],
    'filesystem_edit': ['draft_reply (to share edits in email)'],
    'delete_email': ['archive_email (with approval)', 'apply_label (to mark for deletion)'],
    'send_email': ['draft_email (creates draft for review)', 'draft_reply'],
    'forward_email': ['draft_email (with forwarded content for review)'],
  };

  return alternatives[normalizeToolName(tool)] ?? [];
}

// ============================================================================
// Policy Check Tool (for registration with OpenClaw)
// ============================================================================

export const policyCheckTool = {
  name: 'mailguard.policy_check',
  description: 'Check if an action is allowed under the current security policy. Required for Gmail-origin sessions before executing side effects.',
  inputSchema: {
    type: 'object',
    properties: {
      action: {
        type: 'string',
        description: 'The action or tool to check',
      },
      parameters: {
        type: 'object',
        description: 'Parameters for the action',
      },
    },
    required: ['action'],
  },
};

// ============================================================================
// Exports
// ============================================================================

export { SAFE_TOOLS, APPROVAL_REQUIRED_TOOLS, HARD_DENIED_TOOLS };
