/**
 * Integration Tests
 * Comprehensive end-to-end testing of MailGuard plugin integration
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { activate, deactivate, MailGuardPlugin } from '../src/index.js';
import type {
  MailGuardConfig,
  OpenClawPluginContext,
  Logger,
  PluginStorage,
  GatewayContext,
  HttpRequest,
  HttpResponse,
  ToolDefinition,
  BackgroundService,
  CliCommand,
  ToolContext,
  HttpHandler,
  SideEffectPlan,
  PlannedAction,
} from '../src/types.js';
import gmailPayloads from './fixtures/gmail_payloads.json';

// ============================================================================
// Mock Implementations
// ============================================================================

function createMockLogger(): Logger {
  return {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  };
}

function createMockStorage(): PluginStorage {
  const store = new Map<string, unknown>();
  return {
    get: vi.fn(async (key: string) => store.get(key)) as <T>(key: string) => Promise<T | undefined>,
    set: vi.fn(async (key: string, value: unknown) => { store.set(key, value); }) as <T>(key: string, value: T, ttlSeconds?: number) => Promise<void>,
    delete: vi.fn(async (key: string) => { store.delete(key); }) as (key: string) => Promise<void>,
    list: vi.fn(async (prefix: string) =>
      Array.from(store.keys()).filter(k => k.startsWith(prefix))
    ) as (prefix: string) => Promise<string[]>,
  };
}

function createMockGateway(): GatewayContext & {
  _httpHandlers: Map<string, HttpHandler>;
  _tools: Map<string, ToolDefinition>;
  _backgroundServices: BackgroundService[];
  _cliCommands: CliCommand[];
} {
  const httpHandlers = new Map<string, HttpHandler>();
  const tools = new Map<string, ToolDefinition>();
  const backgroundServices: BackgroundService[] = [];
  const cliCommands: CliCommand[] = [];

  return {
    _httpHandlers: httpHandlers,
    _tools: tools,
    _backgroundServices: backgroundServices,
    _cliCommands: cliCommands,
    registerHttpHandler: vi.fn((path: string, handler: HttpHandler) => {
      httpHandlers.set(path, handler);
    }),
    registerTool: vi.fn((tool: ToolDefinition) => {
      tools.set(tool.name, tool);
    }),
    registerBackgroundService: vi.fn((service: BackgroundService) => {
      backgroundServices.push(service);
    }),
    registerCliCommand: vi.fn((command: CliCommand) => {
      cliCommands.push(command);
    }),
    emitAuditLog: vi.fn(),
    createApprovalRequest: vi.fn(),
  };
}

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
    deniedTools: ['browser_control', 'exec', 'shell'],
    approvalRequiredActions: ['send_email', 'delete_email', 'forward_email'],
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

function createMockRequest(
  body: unknown,
  overrides?: Partial<HttpRequest>
): HttpRequest {
  const bodyJson = JSON.stringify(body);
  return {
    method: 'POST',
    path: '/mailguard/gmail',
    headers: {
      'x-webhook-secret': 'test-secret-12345678',
      'content-type': 'application/json',
    },
    query: {},
    body,
    rawBody: Buffer.from(bodyJson),
    ...overrides,
  };
}

function createMockResponse(): HttpResponse & { _status: number; _body: unknown } {
  const res = {
    _status: 200,
    _body: null as unknown,
    status(code: number): HttpResponse {
      this._status = code;
      return this;
    },
    json(body: unknown): void {
      this._body = body;
    },
    send(data: string | Buffer): void {
      this._body = data;
    },
    header(_name: string, _value: string): HttpResponse {
      return this;
    },
  };
  return res as HttpResponse & { _status: number; _body: unknown };
}

// ============================================================================
// Test Suite 1: OpenClaw Runtime Integration
// ============================================================================

describe('OpenClaw Runtime Integration', () => {
  let config: MailGuardConfig;
  let logger: Logger;
  let storage: PluginStorage;
  let gateway: ReturnType<typeof createMockGateway>;
  let context: OpenClawPluginContext;

  beforeEach(() => {
    config = createMockConfig();
    logger = createMockLogger();
    storage = createMockStorage();
    gateway = createMockGateway();
    context = { config, logger, storage, gateway };
  });

  describe('plugin lifecycle', () => {
    it('should activate plugin and register all components', async () => {
      const plugin = await activate(context);

      expect(plugin).toBeInstanceOf(MailGuardPlugin);

      // Verify HTTP handler registration
      expect(gateway.registerHttpHandler).toHaveBeenCalledWith(
        config.endpoint,
        expect.objectContaining({
          method: 'POST',
          handler: expect.any(Function),
        })
      );

      // Verify tool registrations
      expect(gateway.registerTool).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'mailguard.policy_check',
        })
      );
      expect(gateway.registerTool).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'mailguard.generate_report',
        })
      );

      // Verify background services
      expect(gateway.registerBackgroundService).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'mailguard-cleanup',
          intervalMs: 300000,
        })
      );
      expect(gateway.registerBackgroundService).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'mailguard-workflow-expiry',
          intervalMs: 60000,
        })
      );

      // Verify CLI commands registered
      expect(gateway.registerCliCommand).toHaveBeenCalled();
      expect(gateway._cliCommands.length).toBeGreaterThan(0);
    });

    it('should reject invalid configuration', async () => {
      const invalidContext = {
        ...context,
        config: { ...config, webhookSecret: '123' }, // Too short (min 16 chars)
      };

      await expect(async () => {
        await activate(invalidContext as OpenClawPluginContext);
      }).rejects.toThrow('Invalid MailGuard configuration');
    });

    it('should deactivate plugin cleanly', async () => {
      const plugin = await activate(context);

      expect(() => deactivate(plugin)).not.toThrow();
      expect(logger.info).toHaveBeenCalledWith('Deactivating MailGuard plugin');
    });

    it('should validate configuration schema', async () => {
      const validPlugin = await activate(context);
      expect(validPlugin.config).toMatchObject({
        endpoint: '/mailguard/gmail',
        webhookSecret: expect.any(String),
        maxPayloadSize: expect.any(Number),
        riskThreshold: expect.any(Number),
      });
    });
  });

  describe('component registration', () => {
    it('should register HTTP handler at configured endpoint', async () => {
      await activate(context);

      const handler = gateway._httpHandlers.get(config.endpoint);
      expect(handler).toBeDefined();
      expect(handler?.method).toBe('POST');
      expect(handler?.handler).toBeInstanceOf(Function);
    });

    it('should register policy check tool with correct schema', async () => {
      await activate(context);

      const tool = gateway._tools.get('mailguard.policy_check');
      expect(tool).toBeDefined();
      expect(tool?.inputSchema).toMatchObject({
        type: 'object',
        properties: {
          action: { type: 'string' },
        },
        required: ['action'],
      });
    });

    it('should register report generation tool', async () => {
      await activate(context);

      const tool = gateway._tools.get('mailguard.generate_report');
      expect(tool).toBeDefined();
      expect(tool?.inputSchema).toMatchObject({
        type: 'object',
        properties: {
          sessionId: { type: 'string' },
          includeApprovals: { type: 'boolean' },
        },
        required: ['sessionId'],
      });
    });

    it('should register cleanup background service', async () => {
      await activate(context);

      const cleanupService = gateway._backgroundServices.find(
        s => s.name === 'mailguard-cleanup'
      );
      expect(cleanupService).toBeDefined();
      expect(cleanupService?.intervalMs).toBe(300000);
      expect(cleanupService?.handler).toBeInstanceOf(Function);
    });

    it('should register workflow expiry background service', async () => {
      await activate(context);

      const expiryService = gateway._backgroundServices.find(
        s => s.name === 'mailguard-workflow-expiry'
      );
      expect(expiryService).toBeDefined();
      expect(expiryService?.intervalMs).toBe(60000);
    });
  });
});

// ============================================================================
// Test Suite 2: Gmail Webhook Full Flow
// ============================================================================

describe('Gmail Webhook Full Flow', () => {
  let config: MailGuardConfig;
  let logger: Logger;
  let storage: PluginStorage;
  let gateway: ReturnType<typeof createMockGateway>;
  let context: OpenClawPluginContext;

  beforeEach(async () => {
    config = createMockConfig();
    logger = createMockLogger();
    storage = createMockStorage();
    gateway = createMockGateway();
    context = { config, logger, storage, gateway };
    await activate(context);
  });

  describe('end-to-end webhook processing', () => {
    it('should process valid message payload through complete flow', async () => {
      const handler = gateway._httpHandlers.get(config.endpoint);
      expect(handler).toBeDefined();

      // Create webhook payload with full message
      const webhookPayload = {
        message: {
          data: gmailPayloads.valid_notification.message.data,
          messageId: gmailPayloads.valid_notification.message.messageId,
          publishTime: gmailPayloads.valid_notification.message.publishTime,
        },
        subscription: gmailPayloads.valid_notification.subscription,
        messagePayload: gmailPayloads.valid_message_payload,
      };

      const req = createMockRequest(webhookPayload);
      const res = createMockResponse();

      await handler!.handler(req, res);

      expect(res._status).toBe(200);
      expect(res._body).toMatchObject({
        status: 'processed',
        sessionId: expect.stringMatching(/^gmail-/),
        envelope: expect.objectContaining({
          headers: expect.objectContaining({
            from: 'sender@example.com',
            subject: 'Quarterly Report Q4 2023',
          }),
          bodyText: expect.any(String),
          riskScore: expect.objectContaining({
            score: expect.any(Number),
            recommendation: expect.any(String),
          }),
        }),
      });
    });

    it('should sanitize and assess risk on email content', async () => {
      const handler = gateway._httpHandlers.get(config.endpoint);

      const webhookPayload = {
        message: {
          data: Buffer.from(JSON.stringify({
            emailAddress: 'victim@example.com',
            historyId: '1234569',
          })).toString('base64'),
          messageId: 'msg-malicious',
          publishTime: new Date().toISOString(),
        },
        subscription: 'test-subscription',
        messagePayload: gmailPayloads.malicious_payload,
      };

      const req = createMockRequest(webhookPayload);
      const res = createMockResponse();

      await handler!.handler(req, res);

      // Should be quarantined due to high risk
      expect(res._status).toBe(200);
      const body = res._body as any;

      if (body.status === 'quarantined') {
        expect(body.riskScore).toBeGreaterThan(config.riskThreshold);
      } else {
        // If processed, should have high risk score and tool denials
        expect(body.envelope.riskScore.score).toBeGreaterThan(0);
        expect(body.deniedTools).toBeDefined();
      }
    });

    it('should return session ID for processed messages', async () => {
      const handler = gateway._httpHandlers.get(config.endpoint);

      const webhookPayload = {
        message: {
          data: gmailPayloads.valid_notification.message.data,
          messageId: 'msg-session-test',
          publishTime: new Date().toISOString(),
        },
        subscription: 'test-subscription',
        messagePayload: gmailPayloads.valid_message_payload,
      };

      const req = createMockRequest(webhookPayload);
      const res = createMockResponse();

      await handler!.handler(req, res);

      expect(res._status).toBe(200);
      const body = res._body as any;
      expect(body.sessionId).toMatch(/^gmail-[a-f0-9-]+$/);
    });
  });

  describe('rate limiting', () => {
    it('should enforce rate limits per sender domain', async () => {
      const handler = gateway._httpHandlers.get(config.endpoint);
      const requests: Promise<void>[] = [];

      // Send more requests than the rate limit
      for (let i = 0; i < config.rateLimitPerSender + 2; i++) {
        const webhookPayload = {
          message: {
            data: Buffer.from(JSON.stringify({
              emailAddress: 'user@example.com',
              historyId: `${12345 + i}`,
            })).toString('base64'),
            messageId: `msg-ratelimit-${i}`,
            publishTime: new Date().toISOString(),
          },
          subscription: 'test-subscription',
          messagePayload: gmailPayloads.valid_message_payload,
        };

        const req = createMockRequest(webhookPayload);
        const res = createMockResponse();

        requests.push(handler!.handler(req, res).then(() => {
          if (i >= config.rateLimitPerSender) {
            expect(res._status).toBe(429);
            expect(res._body).toMatchObject({
              error: 'Rate limit exceeded',
              code: 'RATE_LIMITED',
            });
          }
        }));
      }

      await Promise.all(requests);
    });

    it('should track rate limit remaining count', async () => {
      const handler = gateway._httpHandlers.get(config.endpoint);

      const webhookPayload = {
        message: {
          data: gmailPayloads.valid_notification.message.data,
          messageId: 'msg-remaining',
          publishTime: new Date().toISOString(),
        },
        subscription: 'test-subscription',
        messagePayload: gmailPayloads.valid_message_payload,
      };

      const req = createMockRequest(webhookPayload);
      const res = createMockResponse();

      await handler!.handler(req, res);

      expect(res._status).toBe(200);
      const body = res._body as any;
      expect(body.envelope?.provenance?.rateLimitRemaining).toBeDefined();
      expect(body.envelope?.provenance?.rateLimitRemaining).toBeLessThan(config.rateLimitPerSender);
    });
  });

  describe('quarantine behavior', () => {
    it('should quarantine high-risk emails', async () => {
      const handler = gateway._httpHandlers.get(config.endpoint);

      const webhookPayload = {
        message: {
          data: Buffer.from(JSON.stringify({
            emailAddress: 'victim@example.com',
            historyId: '1234569',
          })).toString('base64'),
          messageId: 'msg-quarantine',
          publishTime: new Date().toISOString(),
        },
        subscription: 'test-subscription',
        messagePayload: gmailPayloads.malicious_payload,
      };

      const req = createMockRequest(webhookPayload);
      const res = createMockResponse();

      await handler!.handler(req, res);

      expect(res._status).toBe(200);
      const body = res._body as any;

      if (body.status === 'quarantined') {
        expect(body.riskScore).toBeGreaterThanOrEqual(config.riskThreshold);
        expect(body.reason).toBeDefined();

        // Verify quarantine storage
        const quarantineKeys = await storage.list('quarantine:');
        expect(quarantineKeys.length).toBeGreaterThan(0);
      }
    });

    it('should not quarantine when quarantine is disabled', async () => {
      // Reconfigure with quarantine disabled
      const noQuarantineConfig = createMockConfig({ quarantineEnabled: false });
      const noQuarantineContext = {
        config: noQuarantineConfig,
        logger,
        storage,
        gateway: createMockGateway(),
      };
      await activate(noQuarantineContext);

      const handler = noQuarantineContext.gateway._httpHandlers.get(noQuarantineConfig.endpoint);

      const webhookPayload = {
        message: {
          data: Buffer.from(JSON.stringify({
            emailAddress: 'victim@example.com',
            historyId: '1234569',
          })).toString('base64'),
          messageId: 'msg-no-quarantine',
          publishTime: new Date().toISOString(),
        },
        subscription: 'test-subscription',
        messagePayload: gmailPayloads.malicious_payload,
      };

      const req = createMockRequest(webhookPayload);
      const res = createMockResponse();

      await handler!.handler(req, res);

      expect(res._status).toBe(200);
      const body = res._body as any;
      expect(body.status).not.toBe('quarantined');
    });
  });

  describe('fixture data processing', () => {
    it('should process message with attachment', async () => {
      const handler = gateway._httpHandlers.get(config.endpoint);

      const webhookPayload = {
        message: {
          data: Buffer.from(JSON.stringify({
            emailAddress: 'user@example.com',
            historyId: '1234568',
          })).toString('base64'),
          messageId: 'msg-attachment',
          publishTime: new Date().toISOString(),
        },
        subscription: 'test-subscription',
        messagePayload: gmailPayloads.message_with_attachment,
      };

      const req = createMockRequest(webhookPayload);
      const res = createMockResponse();

      await handler!.handler(req, res);

      expect(res._status).toBe(200);
      const body = res._body as any;
      expect(body.envelope?.attachments).toBeDefined();
      expect(body.envelope?.attachments.length).toBeGreaterThan(0);
      expect(body.envelope?.attachments[0]).toMatchObject({
        filename: expect.any(String),
        mimeType: expect.any(String),
        size: expect.any(Number),
      });
    });
  });
});

// ============================================================================
// Test Suite 3: End-to-End Approval Workflow
// ============================================================================

describe('End-to-End Approval Workflow', () => {
  let config: MailGuardConfig;
  let logger: Logger;
  let storage: PluginStorage;
  let gateway: ReturnType<typeof createMockGateway>;
  let context: OpenClawPluginContext;
  let plugin: MailGuardPlugin;

  beforeEach(async () => {
    config = createMockConfig({
      lobsterIntegration: {
        enabled: true,
        workflowTemplate: 'mailguard-approval',
        timeout: 3600,
      },
    });
    logger = createMockLogger();
    storage = createMockStorage();
    gateway = createMockGateway();
    context = { config, logger, storage, gateway };
    plugin = await activate(context);
  });

  describe('risky action approval flow', () => {
    it('should deny risky tool and create approval workflow', async () => {
      // First, process an email to create a session
      const handler = gateway._httpHandlers.get(config.endpoint);
      const webhookPayload = {
        message: {
          data: Buffer.from(JSON.stringify({
            emailAddress: 'user@example.com',
            historyId: '12345',
          })).toString('base64'),
          messageId: 'msg-approval',
          publishTime: new Date().toISOString(),
        },
        subscription: 'test-subscription',
        messagePayload: gmailPayloads.valid_message_payload,
      };

      const req = createMockRequest(webhookPayload);
      const res = createMockResponse();
      await handler!.handler(req, res);

      const body = res._body as any;
      const sessionId = body.sessionId;

      // Now check if a risky tool is blocked
      const policyCheckTool = gateway._tools.get('mailguard.policy_check');
      expect(policyCheckTool).toBeDefined();

      const toolContext: ToolContext = {
        sessionId,
        logger,
        riskScore: 45,
        provenance: {
          source: 'gmail',
          hookName: 'mailguard-gmail',
          receivedAt: new Date(),
          senderDomain: 'example.com',
          isAllowlistedDomain: false,
          isBlocklistedDomain: false,
          rateLimitRemaining: 5,
        },
      };

      const decision = await policyCheckTool!.handler(
        { action: 'send_email', parameters: { to: 'target@example.com' } },
        toolContext
      );

      expect(decision).toMatchObject({
        allowed: false,
        requiresApproval: true,
        approvalType: 'lobster',
      });
    });

    it('should complete full approval workflow when approved', async () => {
      // Process email to create session
      const handler = gateway._httpHandlers.get(config.endpoint);
      const webhookPayload = {
        message: {
          data: gmailPayloads.valid_notification.message.data,
          messageId: 'msg-workflow-approve',
          publishTime: new Date().toISOString(),
        },
        subscription: 'test-subscription',
        messagePayload: gmailPayloads.valid_message_payload,
      };

      const req = createMockRequest(webhookPayload);
      const res = createMockResponse();
      await handler!.handler(req, res);

      const body = res._body as any;
      const sessionId = body.sessionId;

      // Create a side effect plan
      const actions: PlannedAction[] = [
        {
          id: 'action-1',
          type: 'send_email',
          description: 'Send reply to user',
          parameters: { to: 'sender@example.com', subject: 'Re: Quarterly Report' },
          requiresApproval: true,
          approved: false,
        },
      ];

      const plan: SideEffectPlan = {
        id: 'plan-123',
        sessionId,
        actions,
        status: 'pending_approval',
        approvals: [],
      };

      // Create workflow via Lobster adapter (accessed via plugin internals)
      // In a real scenario, this would be triggered by the tool firewall
      const lobsterAdapter = (plugin as any).lobsterAdapter;
      const workflow = await lobsterAdapter.createApprovalWorkflow(sessionId, plan, {
        from: 'sender@example.com',
        subject: 'Quarterly Report Q4 2023',
        riskScore: 35,
        signals: [],
      });

      expect(workflow.status).toBe('pending');
      expect(workflow.steps.length).toBeGreaterThan(0);

      // Start workflow
      await lobsterAdapter.startWorkflow(workflow.id);

      const statusAfterStart = await lobsterAdapter.getWorkflowStatus(workflow.id);
      expect(statusAfterStart?.status).toBe('in_progress');

      // Approve the first step
      const approvalResult = await lobsterAdapter.resolveApproval(
        workflow.id,
        workflow.steps[0]!.id,
        true,
        'admin@example.com'
      );

      expect(approvalResult.workflowComplete).toBe(true);
      expect(approvalResult.allApproved).toBe(true);

      const finalStatus = await lobsterAdapter.getWorkflowStatus(workflow.id);
      expect(finalStatus?.status).toBe('completed');
    });

    it('should handle approval denial workflow', async () => {
      // Process email
      const handler = gateway._httpHandlers.get(config.endpoint);
      const webhookPayload = {
        message: {
          data: gmailPayloads.valid_notification.message.data,
          messageId: 'msg-workflow-deny',
          publishTime: new Date().toISOString(),
        },
        subscription: 'test-subscription',
        messagePayload: gmailPayloads.valid_message_payload,
      };

      const req = createMockRequest(webhookPayload);
      const res = createMockResponse();
      await handler!.handler(req, res);

      const body = res._body as any;
      const sessionId = body.sessionId;

      // Create plan with multiple actions
      const actions: PlannedAction[] = [
        {
          id: 'action-1',
          type: 'send_email',
          description: 'Send first email',
          parameters: { to: 'target1@example.com' },
          requiresApproval: true,
          approved: false,
        },
        {
          id: 'action-2',
          type: 'forward_email',
          description: 'Forward to another recipient',
          parameters: { to: 'target2@example.com' },
          requiresApproval: true,
          approved: false,
        },
      ];

      const plan: SideEffectPlan = {
        id: 'plan-deny',
        sessionId,
        actions,
        status: 'pending_approval',
        approvals: [],
      };

      const lobsterAdapter = (plugin as any).lobsterAdapter;
      const workflow = await lobsterAdapter.createApprovalWorkflow(sessionId, plan, {
        from: 'sender@example.com',
        subject: 'Test Email',
        riskScore: 60,
        signals: [],
      });

      await lobsterAdapter.startWorkflow(workflow.id);

      // Deny the first step
      const denialResult = await lobsterAdapter.resolveApproval(
        workflow.id,
        workflow.steps[0]!.id,
        false,
        'admin@example.com',
        'Too risky'
      );

      expect(denialResult.workflowComplete).toBe(true);
      expect(denialResult.allApproved).toBe(false);

      const finalStatus = await lobsterAdapter.getWorkflowStatus(workflow.id);
      expect(finalStatus?.status).toBe('failed');
      expect(finalStatus?.steps[1]?.status).toBe('skipped'); // Second step should be skipped
    });
  });

  describe('approval expiration', () => {
    it('should expire workflows past timeout', async () => {
      // Create a workflow with minimum timeout (60 seconds per schema)
      // We'll manually manipulate the workflow timestamp to simulate expiration
      const shortTimeoutConfig = createMockConfig({
        lobsterIntegration: {
          enabled: true,
          workflowTemplate: 'mailguard-approval',
          timeout: 60, // Minimum allowed timeout
        },
      });

      const shortTimeoutContext = {
        config: shortTimeoutConfig,
        logger,
        storage: createMockStorage(),
        gateway: createMockGateway(),
      };

      const shortTimeoutPlugin = await activate(shortTimeoutContext);

      // Process email
      const handler = shortTimeoutContext.gateway._httpHandlers.get(shortTimeoutConfig.endpoint);
      const webhookPayload = {
        message: {
          data: gmailPayloads.valid_notification.message.data,
          messageId: 'msg-expire',
          publishTime: new Date().toISOString(),
        },
        subscription: 'test-subscription',
        messagePayload: gmailPayloads.valid_message_payload,
      };

      const req = createMockRequest(webhookPayload);
      const res = createMockResponse();
      await handler!.handler(req, res);

      const body = res._body as any;
      const sessionId = body.sessionId;

      // Create workflow
      const actions: PlannedAction[] = [
        {
          id: 'action-expire',
          type: 'send_email',
          description: 'Will expire',
          parameters: {},
          requiresApproval: true,
          approved: false,
        },
      ];

      const plan: SideEffectPlan = {
        id: 'plan-expire',
        sessionId,
        actions,
        status: 'pending_approval',
        approvals: [],
      };

      const lobsterAdapter = (shortTimeoutPlugin as any).lobsterAdapter;
      const workflow = await lobsterAdapter.createApprovalWorkflow(sessionId, plan, {
        from: 'sender@example.com',
        subject: 'Test',
        riskScore: 40,
        signals: [],
      });

      await lobsterAdapter.startWorkflow(workflow.id);

      // Manually manipulate workflow timestamp to simulate expiration
      // Set createdAt to 61 seconds ago (past the 60 second timeout)
      const pastDate = new Date(Date.now() - 61000);
      workflow.createdAt = pastDate;

      // Check for expired workflows
      const expired = await lobsterAdapter.checkExpiredWorkflows();

      expect(expired).toContain(workflow.id);

      const expiredStatus = await lobsterAdapter.getWorkflowStatus(workflow.id);
      expect(expiredStatus?.status).toBe('failed');
      expect(expiredStatus?.steps[0]?.error).toContain('timeout');
    });
  });

  describe('multiple pending approvals', () => {
    it('should handle multiple pending approvals for same session', async () => {
      // Process email
      const handler = gateway._httpHandlers.get(config.endpoint);
      const webhookPayload = {
        message: {
          data: gmailPayloads.valid_notification.message.data,
          messageId: 'msg-multiple',
          publishTime: new Date().toISOString(),
        },
        subscription: 'test-subscription',
        messagePayload: gmailPayloads.valid_message_payload,
      };

      const req = createMockRequest(webhookPayload);
      const res = createMockResponse();
      await handler!.handler(req, res);

      const body = res._body as any;
      const sessionId = body.sessionId;

      // Create multiple actions requiring approval
      const actions: PlannedAction[] = [
        {
          id: 'action-1',
          type: 'send_email',
          description: 'Send email',
          parameters: {},
          requiresApproval: true,
          approved: false,
        },
        {
          id: 'action-2',
          type: 'forward_email',
          description: 'Forward email',
          parameters: {},
          requiresApproval: true,
          approved: false,
        },
        {
          id: 'action-3',
          type: 'delete_email',
          description: 'Delete email',
          parameters: {},
          requiresApproval: true,
          approved: false,
        },
      ];

      const plan: SideEffectPlan = {
        id: 'plan-multiple',
        sessionId,
        actions,
        status: 'pending_approval',
        approvals: [],
      };

      const lobsterAdapter = (plugin as any).lobsterAdapter;
      const workflow = await lobsterAdapter.createApprovalWorkflow(sessionId, plan, {
        from: 'sender@example.com',
        subject: 'Test',
        riskScore: 50,
        signals: [],
      });

      expect(workflow.steps.length).toBe(3);

      await lobsterAdapter.startWorkflow(workflow.id);

      // Get pending approvals
      const pending = lobsterAdapter.getPendingApprovals(sessionId);
      expect(pending.length).toBeGreaterThan(0);
      expect(pending[0]?.status).toBe('in_progress');

      // Approve steps sequentially
      for (let i = 0; i < workflow.steps.length; i++) {
        const step = workflow.steps[i]!;
        const result = await lobsterAdapter.resolveApproval(
          workflow.id,
          step.id,
          true,
          'admin@example.com'
        );

        if (i < workflow.steps.length - 1) {
          expect(result.workflowComplete).toBe(false);
        } else {
          expect(result.workflowComplete).toBe(true);
          expect(result.allApproved).toBe(true);
        }
      }

      const finalStatus = await lobsterAdapter.getWorkflowStatus(workflow.id);
      expect(finalStatus?.status).toBe('completed');
    });
  });

  describe('tool firewall integration', () => {
    it('should block hard-denied tools regardless of approval', async () => {
      // Process email
      const handler = gateway._httpHandlers.get(config.endpoint);
      const webhookPayload = {
        message: {
          data: gmailPayloads.valid_notification.message.data,
          messageId: 'msg-hard-deny',
          publishTime: new Date().toISOString(),
        },
        subscription: 'test-subscription',
        messagePayload: gmailPayloads.valid_message_payload,
      };

      const req = createMockRequest(webhookPayload);
      const res = createMockResponse();
      await handler!.handler(req, res);

      const body = res._body as any;
      const sessionId = body.sessionId;

      // Try to use a hard-denied tool
      const policyCheckTool = gateway._tools.get('mailguard.policy_check');
      const toolContext: ToolContext = {
        sessionId,
        logger,
        riskScore: 35,
      };

      const decision = await policyCheckTool!.handler(
        { action: 'exec', parameters: { command: 'ls -la' } },
        toolContext
      );

      expect(decision).toMatchObject({
        allowed: false,
        requiresApproval: false, // Hard denials don't allow approval
        reason: expect.stringContaining('not available'),
        alternatives: expect.any(Array),
      });
    });

    it('should allow safe tools without approval', async () => {
      // Process email
      const handler = gateway._httpHandlers.get(config.endpoint);
      const webhookPayload = {
        message: {
          data: gmailPayloads.valid_notification.message.data,
          messageId: 'msg-safe-tool',
          publishTime: new Date().toISOString(),
        },
        subscription: 'test-subscription',
        messagePayload: gmailPayloads.valid_message_payload,
      };

      const req = createMockRequest(webhookPayload);
      const res = createMockResponse();
      await handler!.handler(req, res);

      const body = res._body as any;
      const sessionId = body.sessionId;

      // Try to use a safe tool
      const policyCheckTool = gateway._tools.get('mailguard.policy_check');
      const toolContext: ToolContext = {
        sessionId,
        logger,
        riskScore: 35,
      };

      const decision = await policyCheckTool!.handler(
        { action: 'summarize', parameters: {} },
        toolContext
      );

      expect(decision).toMatchObject({
        allowed: true,
        requiresApproval: false,
      });
    });
  });
});
