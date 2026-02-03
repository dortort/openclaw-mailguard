/**
 * Lobster Workflow Adapter Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { LobsterAdapter, createLobsterAdapter } from '../src/workflows/lobster_adapter.js';
import type { MailGuardConfig, PluginStorage, Logger, SideEffectPlan } from '../src/types.js';

// Mock logger
function createMockLogger(): Logger {
  return {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  };
}

// Mock storage
function createMockStorage(): PluginStorage {
  const store = new Map<string, unknown>();
  return {
    get: vi.fn(async (key: string) => store.get(key) ?? null),
    set: vi.fn(async (key: string, value: unknown) => { store.set(key, value); }),
    delete: vi.fn(async (key: string) => { store.delete(key); return true; }),
    list: vi.fn(async (prefix: string) =>
      Array.from(store.keys()).filter(k => k.startsWith(prefix))
    ),
  };
}

// Mock config
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
    deniedTools: [],
    approvalRequiredActions: [],
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

describe('LobsterAdapter', () => {
  let config: MailGuardConfig;
  let logger: Logger;
  let storage: PluginStorage;
  let adapter: LobsterAdapter;

  beforeEach(() => {
    config = createMockConfig();
    logger = createMockLogger();
    storage = createMockStorage();
    adapter = createLobsterAdapter(config, logger, storage);
  });

  describe('createApprovalWorkflow', () => {
    it('should create a workflow with approval steps', async () => {
      const plan: SideEffectPlan = {
        id: 'plan-123',
        sessionId: 'session-123',
        actions: [
          {
            id: 'action-1',
            type: 'send_email',
            description: 'Send reply to user',
            requiresApproval: true,
            parameters: { to: 'user@example.com' },
          },
        ],
        status: 'pending_approval',
        approvals: [],
      };

      const workflow = await adapter.createApprovalWorkflow('session-123', plan, {
        from: 'sender@example.com',
        subject: 'Test email',
        riskScore: 45,
        signals: [],
      });

      expect(workflow.id).toMatch(/^wf-/);
      expect(workflow.status).toBe('pending');
      expect(workflow.steps).toHaveLength(1);
      expect(workflow.steps[0]?.type).toBe('approval');
    });

    it('should use UUID for workflow ID', async () => {
      const plan: SideEffectPlan = {
        id: 'plan-123',
        sessionId: 'session-123',
        actions: [],
        status: 'pending_approval',
        approvals: [],
      };

      const workflow = await adapter.createApprovalWorkflow('session-123', plan, {
        from: 'sender@example.com',
        subject: 'Test',
        riskScore: 0,
        signals: [],
      });

      // Should be UUID format (wf-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
      expect(workflow.id).toMatch(/^wf-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    });
  });

  describe('startWorkflow', () => {
    it('should start workflow and set first step to in_progress', async () => {
      const plan: SideEffectPlan = {
        id: 'plan-123',
        sessionId: 'session-123',
        actions: [
          { id: 'action-1', type: 'send_email', description: 'Test', requiresApproval: true, parameters: {} },
        ],
        status: 'pending_approval',
        approvals: [],
      };

      const workflow = await adapter.createApprovalWorkflow('session-123', plan, {
        from: 'sender@example.com',
        subject: 'Test',
        riskScore: 0,
        signals: [],
      });

      await adapter.startWorkflow(workflow.id);

      const status = await adapter.getWorkflowStatus(workflow.id);
      expect(status?.status).toBe('in_progress');
      expect(status?.steps[0]?.status).toBe('in_progress');
    });

    it('should throw for non-existent workflow', async () => {
      await expect(adapter.startWorkflow('wf-nonexistent')).rejects.toThrow('Workflow not found');
    });
  });

  describe('resolveApproval', () => {
    it('should approve and complete workflow', async () => {
      const plan: SideEffectPlan = {
        id: 'plan-123',
        sessionId: 'session-123',
        actions: [
          { id: 'action-1', type: 'send_email', description: 'Test', requiresApproval: true, parameters: {} },
        ],
        status: 'pending_approval',
        approvals: [],
      };

      const workflow = await adapter.createApprovalWorkflow('session-123', plan, {
        from: 'sender@example.com',
        subject: 'Test',
        riskScore: 0,
        signals: [],
      });
      await adapter.startWorkflow(workflow.id);

      const result = await adapter.resolveApproval(
        workflow.id,
        workflow.steps[0]!.id,
        true,
        'admin@example.com'
      );

      expect(result.workflowComplete).toBe(true);
      expect(result.allApproved).toBe(true);
    });

    it('should deny and fail workflow', async () => {
      const plan: SideEffectPlan = {
        id: 'plan-123',
        sessionId: 'session-123',
        actions: [
          { id: 'action-1', type: 'send_email', description: 'Test', requiresApproval: true, parameters: {} },
        ],
        status: 'pending_approval',
        approvals: [],
      };

      const workflow = await adapter.createApprovalWorkflow('session-123', plan, {
        from: 'sender@example.com',
        subject: 'Test',
        riskScore: 0,
        signals: [],
      });
      await adapter.startWorkflow(workflow.id);

      const result = await adapter.resolveApproval(
        workflow.id,
        workflow.steps[0]!.id,
        false,
        'admin@example.com',
        'Too risky'
      );

      expect(result.workflowComplete).toBe(true);
      expect(result.allApproved).toBe(false);
    });
  });

  describe('cancelWorkflow', () => {
    it('should cancel workflow and skip pending steps', async () => {
      const plan: SideEffectPlan = {
        id: 'plan-123',
        sessionId: 'session-123',
        actions: [
          { id: 'action-1', type: 'send_email', description: 'Test1', requiresApproval: true, parameters: {} },
          { id: 'action-2', type: 'send_email', description: 'Test2', requiresApproval: true, parameters: {} },
        ],
        status: 'pending_approval',
        approvals: [],
      };

      const workflow = await adapter.createApprovalWorkflow('session-123', plan, {
        from: 'sender@example.com',
        subject: 'Test',
        riskScore: 0,
        signals: [],
      });
      await adapter.startWorkflow(workflow.id);

      await adapter.cancelWorkflow(workflow.id, 'User requested cancellation');

      const status = await adapter.getWorkflowStatus(workflow.id);
      expect(status?.status).toBe('cancelled');
    });
  });

  describe('getPendingApprovals', () => {
    it('should return pending approvals for session', async () => {
      const plan: SideEffectPlan = {
        id: 'plan-123',
        sessionId: 'session-123',
        actions: [
          { id: 'action-1', type: 'send_email', description: 'Test', requiresApproval: true, parameters: {} },
        ],
        status: 'pending_approval',
        approvals: [],
      };

      const workflow = await adapter.createApprovalWorkflow('session-123', plan, {
        from: 'sender@example.com',
        subject: 'Test',
        riskScore: 0,
        signals: [],
      });
      await adapter.startWorkflow(workflow.id);

      const pending = await adapter.getPendingApprovals('session-123');

      expect(pending).toHaveLength(1);
      expect(pending[0]?.type).toBe('approval');
    });
  });

  describe('checkExpiredWorkflows', () => {
    it('should expire workflows past timeout', async () => {
      const shortTimeoutConfig = createMockConfig({
        lobsterIntegration: {
          enabled: true,
          workflowTemplate: 'mailguard-approval',
          timeout: 0, // Immediate timeout
        },
      });
      const shortAdapter = createLobsterAdapter(shortTimeoutConfig, logger, storage);

      const plan: SideEffectPlan = {
        id: 'plan-123',
        sessionId: 'session-123',
        actions: [
          { id: 'action-1', type: 'send_email', description: 'Test', requiresApproval: true, parameters: {} },
        ],
        status: 'pending_approval',
        approvals: [],
      };

      const workflow = await shortAdapter.createApprovalWorkflow('session-123', plan, {
        from: 'sender@example.com',
        subject: 'Test',
        riskScore: 0,
        signals: [],
      });
      await shortAdapter.startWorkflow(workflow.id);

      // Wait a moment for timeout
      await new Promise(r => setTimeout(r, 10));

      const expired = await shortAdapter.checkExpiredWorkflows();

      expect(expired).toContain(workflow.id);
    });
  });
});
