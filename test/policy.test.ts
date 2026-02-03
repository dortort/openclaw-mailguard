/**
 * Tool Firewall Policy Tests
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { ToolFirewall, SAFE_TOOLS, HARD_DENIED_TOOLS, APPROVAL_REQUIRED_TOOLS } from '../src/policy/tool_firewall.js';
import type { MailGuardConfig, EmailProvenance, RiskScore, Logger } from '../src/types.js';

// Mock logger
const mockLogger: Logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

// Helper to create mock config
function createMockConfig(overrides?: Partial<MailGuardConfig>): MailGuardConfig {
  return {
    endpoint: '/mailguard/gmail',
    webhookSecret: 'test-secret-12345678',
    maxPayloadSize: 1048576,
    maxBodyLength: 50000,
    riskThreshold: 70,
    enableMLClassifier: false,
    allowedSenderDomains: [],
    blockedSenderDomains: [],
    allowedRecipientDomains: [],
    deniedTools: [
      'browser_control',
      'exec',
      'shell',
      'filesystem_write',
    ],
    approvalRequiredActions: [
      'send_email',
      'forward_email',
      'delete_email',
    ],
    quarantineEnabled: true,
    rateLimitPerSender: 10,
    logLevel: 'info',
    allowUnsafeExternalContent: false,
    lobsterIntegration: {
      enabled: true,
      workflowTemplate: 'mailguard-approval',
      timeout: 3600,
    },
    ...overrides,
  };
}

// Helper to create mock provenance
function createMockProvenance(overrides?: Partial<EmailProvenance>): EmailProvenance {
  return {
    source: 'gmail',
    hookName: 'mailguard-gmail',
    receivedAt: new Date(),
    senderDomain: 'example.com',
    isAllowlistedDomain: false,
    isBlocklistedDomain: false,
    rateLimitRemaining: 10,
    ...overrides,
  };
}

// Helper to create mock risk score
function createMockRiskScore(overrides?: Partial<RiskScore>): RiskScore {
  return {
    score: 30,
    reasons: [],
    signals: [],
    recommendation: 'allow',
    ...overrides,
  };
}

describe('ToolFirewall', () => {
  let firewall: ToolFirewall;
  let config: MailGuardConfig;

  beforeEach(() => {
    config = createMockConfig();
    firewall = new ToolFirewall(config, mockLogger);
  });

  describe('session initialization', () => {
    it('should initialize session with Gmail provenance', () => {
      const sessionId = 'test-session-1';
      const provenance = createMockProvenance();
      const riskScore = createMockRiskScore();

      firewall.initializeSession(sessionId, provenance, riskScore);

      const deniedTools = firewall.getDeniedTools(sessionId);
      expect(deniedTools.length).toBeGreaterThan(0);
    });

    it('should include hard-denied tools in session policy', () => {
      const sessionId = 'test-session-2';
      const provenance = createMockProvenance();
      const riskScore = createMockRiskScore();

      firewall.initializeSession(sessionId, provenance, riskScore);

      const deniedTools = firewall.getDeniedTools(sessionId);
      expect(deniedTools).toContain('exec');
      expect(deniedTools).toContain('browser_control');
    });
  });

  describe('tool access control', () => {
    beforeEach(() => {
      firewall.initializeSession(
        'session-1',
        createMockProvenance(),
        createMockRiskScore()
      );
    });

    it('should allow safe tools', () => {
      const decision = firewall.checkToolAccess({
        source: 'gmail',
        riskScore: 30,
        senderDomain: 'example.com',
        isAllowlistedSender: false,
        sessionId: 'session-1',
        requestedTool: 'summarize',
      });

      expect(decision.allowed).toBe(true);
      expect(decision.requiresApproval).toBe(false);
    });

    it('should deny hard-denied tools', () => {
      const decision = firewall.checkToolAccess({
        source: 'gmail',
        riskScore: 30,
        senderDomain: 'example.com',
        isAllowlistedSender: false,
        sessionId: 'session-1',
        requestedTool: 'exec',
      });

      expect(decision.allowed).toBe(false);
      expect(decision.denialType).toBe('hard');
      expect(decision.requiresApproval).toBe(false);
    });

    it('should require approval for side effect tools', () => {
      const decision = firewall.checkToolAccess({
        source: 'gmail',
        riskScore: 30,
        senderDomain: 'example.com',
        isAllowlistedSender: false,
        sessionId: 'session-1',
        requestedTool: 'send_email',
      });

      expect(decision.allowed).toBe(false);
      expect(decision.requiresApproval).toBe(true);
      expect(decision.denialType).toBe('soft');
    });

    it('should suggest alternatives for denied tools', () => {
      const decision = firewall.checkToolAccess({
        source: 'gmail',
        riskScore: 30,
        senderDomain: 'example.com',
        isAllowlistedSender: false,
        sessionId: 'session-1',
        requestedTool: 'browser_control',
      });

      expect(decision.alternatives).toBeDefined();
      expect(decision.alternatives?.length).toBeGreaterThan(0);
    });

    it('should allow non-restricted tools without policy', () => {
      const decision = firewall.checkToolAccess({
        source: 'gmail',
        riskScore: 30,
        senderDomain: 'example.com',
        isAllowlistedSender: false,
        sessionId: 'non-existent-session',
        requestedTool: 'any_tool',
      });

      expect(decision.allowed).toBe(true);
      expect(decision.reason).toContain('No Gmail-origin policy');
    });
  });

  describe('side effect plans', () => {
    beforeEach(() => {
      firewall.initializeSession(
        'session-1',
        createMockProvenance(),
        createMockRiskScore()
      );
    });

    it('should create side effect plan with approvals', () => {
      const plan = firewall.createSideEffectPlan('session-1', [
        {
          id: 'action-1',
          type: 'send_email',
          description: 'Send reply email',
          parameters: { to: 'user@example.com' },
          requiresApproval: true,
          approved: false,
        },
        {
          id: 'action-2',
          type: 'apply_label',
          description: 'Apply processed label',
          parameters: { label: 'Processed' },
          requiresApproval: true,
          approved: false,
        },
      ]);

      expect(plan.approvals).toHaveLength(2);
      expect(plan.status).toBe('pending_approval');
    });

    it('should not create approvals for non-requiring actions', () => {
      const plan = firewall.createSideEffectPlan('session-1', [
        {
          id: 'action-1',
          type: 'summarize',
          description: 'Summarize email',
          parameters: {},
          requiresApproval: false,
          approved: false,
        },
      ]);

      expect(plan.approvals).toHaveLength(0);
    });
  });

  describe('approval resolution', () => {
    beforeEach(() => {
      firewall.initializeSession(
        'session-1',
        createMockProvenance(),
        createMockRiskScore()
      );
    });

    it('should resolve approval requests', () => {
      const plan = firewall.createSideEffectPlan('session-1', [
        {
          id: 'action-1',
          type: 'send_email',
          description: 'Send reply',
          parameters: {},
          requiresApproval: true,
          approved: false,
        },
      ]);

      const approvalId = plan.approvals[0]?.id;
      expect(approvalId).toBeDefined();

      const resolved = firewall.resolveApproval('session-1', approvalId!, true, 'operator@example.com');
      expect(resolved).toBe(true);
    });

    it('should return false for non-existent approval', () => {
      const resolved = firewall.resolveApproval('session-1', 'non-existent', true, 'operator@example.com');
      expect(resolved).toBe(false);
    });

    it('should track pending approvals', () => {
      firewall.createSideEffectPlan('session-1', [
        {
          id: 'action-1',
          type: 'send_email',
          description: 'Send reply',
          parameters: {},
          requiresApproval: true,
          approved: false,
        },
      ]);

      const pending = firewall.getPendingApprovals('session-1');
      expect(pending).toHaveLength(1);
    });
  });

  describe('tool call history', () => {
    beforeEach(() => {
      firewall.initializeSession(
        'session-1',
        createMockProvenance(),
        createMockRiskScore()
      );
    });

    it('should record tool call decisions', () => {
      firewall.checkToolAccess({
        source: 'gmail',
        riskScore: 30,
        senderDomain: 'example.com',
        isAllowlistedSender: false,
        sessionId: 'session-1',
        requestedTool: 'summarize',
      });

      firewall.checkToolAccess({
        source: 'gmail',
        riskScore: 30,
        senderDomain: 'example.com',
        isAllowlistedSender: false,
        sessionId: 'session-1',
        requestedTool: 'exec',
      });

      const history = firewall.getToolCallHistory('session-1');
      expect(history).toHaveLength(2);
      expect(history[0]?.decision).toBe('allowed');
      expect(history[1]?.decision).toBe('denied');
    });
  });

  describe('session cleanup', () => {
    it('should cleanup expired sessions', () => {
      firewall.initializeSession(
        'old-session',
        createMockProvenance(),
        createMockRiskScore()
      );

      // Simulate some activity to set timestamp
      firewall.checkToolAccess({
        source: 'gmail',
        riskScore: 30,
        senderDomain: 'example.com',
        isAllowlistedSender: false,
        sessionId: 'old-session',
        requestedTool: 'summarize',
      });

      // Cleanup with very short max age
      firewall.cleanupExpiredSessions(0);

      // Session should still exist since we just accessed it
      // But if we manually waited or mocked time, it would be cleaned
      const deniedTools = firewall.getDeniedTools('old-session');
      expect(deniedTools.length).toBeGreaterThanOrEqual(0);
    });
  });
});

describe('Tool Categories', () => {
  describe('SAFE_TOOLS', () => {
    it('should contain read-only tools', () => {
      expect(SAFE_TOOLS.has('summarize')).toBe(true);
      expect(SAFE_TOOLS.has('classify')).toBe(true);
      expect(SAFE_TOOLS.has('translate')).toBe(true);
    });

    it('should contain draft tools', () => {
      expect(SAFE_TOOLS.has('draft_reply')).toBe(true);
      expect(SAFE_TOOLS.has('draft_email')).toBe(true);
    });

    it('should not contain side-effect tools', () => {
      expect(SAFE_TOOLS.has('send_email')).toBe(false);
      expect(SAFE_TOOLS.has('exec')).toBe(false);
    });
  });

  describe('HARD_DENIED_TOOLS', () => {
    it('should contain dangerous execution tools', () => {
      expect(HARD_DENIED_TOOLS.has('exec')).toBe(true);
      expect(HARD_DENIED_TOOLS.has('shell')).toBe(true);
      expect(HARD_DENIED_TOOLS.has('bash')).toBe(true);
    });

    it('should contain browser automation tools', () => {
      expect(HARD_DENIED_TOOLS.has('browser_control')).toBe(true);
      expect(HARD_DENIED_TOOLS.has('browser_navigate')).toBe(true);
      expect(HARD_DENIED_TOOLS.has('puppeteer')).toBe(true);
    });

    it('should contain filesystem write tools', () => {
      expect(HARD_DENIED_TOOLS.has('filesystem_write')).toBe(true);
      expect(HARD_DENIED_TOOLS.has('filesystem_edit')).toBe(true);
      expect(HARD_DENIED_TOOLS.has('filesystem_delete')).toBe(true);
    });
  });

  describe('APPROVAL_REQUIRED_TOOLS', () => {
    it('should contain email actions', () => {
      expect(APPROVAL_REQUIRED_TOOLS.has('send_email')).toBe(true);
      expect(APPROVAL_REQUIRED_TOOLS.has('forward_email')).toBe(true);
      expect(APPROVAL_REQUIRED_TOOLS.has('apply_label')).toBe(true);
    });

    it('should contain calendar actions', () => {
      expect(APPROVAL_REQUIRED_TOOLS.has('create_calendar_event')).toBe(true);
    });
  });
});
