/**
 * Gmail Ingress Handler Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { GmailIngressHandler } from '../src/http/gmail_ingress.js';
import { ToolFirewall } from '../src/policy/tool_firewall.js';
import type { MailGuardConfig, HttpRequest, HttpResponse, PluginStorage, Logger } from '../src/types.js';

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
    get: vi.fn(async (key: string) => store.get(key)) as <T>(key: string) => Promise<T | undefined>,
    set: vi.fn(async (key: string, value: unknown) => { store.set(key, value); }) as <T>(key: string, value: T, ttlSeconds?: number) => Promise<void>,
    delete: vi.fn(async (key: string) => { store.delete(key); }) as (key: string) => Promise<void>,
    list: vi.fn(async (prefix: string) =>
      Array.from(store.keys()).filter(k => k.startsWith(prefix))
    ) as (prefix: string) => Promise<string[]>,
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

// Mock request
function createMockRequest(overrides?: Partial<HttpRequest>): HttpRequest {
  const defaultBody = {
    message: {
      data: Buffer.from(JSON.stringify({
        emailAddress: 'user@example.com',
        historyId: '12345',
      })).toString('base64'),
    },
  };

  return {
    method: 'POST',
    path: '/mailguard/gmail',
    headers: {
      'x-webhook-secret': 'test-secret-12345678',
      'content-type': 'application/json',
    },
    query: {},
    body: defaultBody,
    rawBody: Buffer.from(JSON.stringify(defaultBody)),
    ...overrides,
  };
}

// Mock response
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
    header(name: string, value: string): HttpResponse {
      return this;
    },
  };
  return res as HttpResponse & { _status: number; _body: unknown };
}

describe('GmailIngressHandler', () => {
  let config: MailGuardConfig;
  let logger: Logger;
  let storage: PluginStorage;
  let toolFirewall: ToolFirewall;
  let handler: GmailIngressHandler;

  beforeEach(() => {
    config = createMockConfig();
    logger = createMockLogger();
    storage = createMockStorage();
    toolFirewall = new ToolFirewall(config, logger);
    handler = new GmailIngressHandler(config, logger, storage, toolFirewall);
  });

  describe('authentication', () => {
    it('should reject requests without authentication', async () => {
      const req = createMockRequest({
        headers: { 'content-type': 'application/json' },
      });
      const res = createMockResponse();

      await handler.handle(req, res);

      expect(res._status).toBe(401);
      expect(res._body).toEqual({ error: 'Unauthorized', code: 'AUTH_FAILED' });
    });

    it('should accept valid webhook secret', async () => {
      const req = createMockRequest();
      const res = createMockResponse();

      await handler.handle(req, res);

      expect(res._status).not.toBe(401);
    });

    it('should accept Bearer token format', async () => {
      const req = createMockRequest({
        headers: {
          'authorization': 'Bearer test-secret-12345678',
          'content-type': 'application/json',
        },
      });
      const res = createMockResponse();

      await handler.handle(req, res);

      expect(res._status).not.toBe(401);
    });
  });

  describe('payload validation', () => {
    it('should reject payloads exceeding max size', async () => {
      const req = createMockRequest({
        rawBody: Buffer.from('x'.repeat(1048577)), // 1MB + 1 byte
      });
      const res = createMockResponse();

      await handler.handle(req, res);

      expect(res._status).toBe(413);
      expect(res._body).toEqual({ error: 'Payload too large', code: 'PAYLOAD_TOO_LARGE' });
    });

    it('should reject invalid payload structure', async () => {
      const req = createMockRequest({
        body: { invalid: 'payload' },
      });
      const res = createMockResponse();

      await handler.handle(req, res);

      expect(res._status).toBe(400);
      expect(res._body).toEqual({ error: 'Invalid payload structure', code: 'INVALID_PAYLOAD' });
    });
  });

  describe('notification handling', () => {
    it('should acknowledge notification when message fetch is required', async () => {
      const req = createMockRequest();
      const res = createMockResponse();

      await handler.handle(req, res);

      expect(res._status).toBe(200);
      expect(res._body).toMatchObject({
        status: 'acknowledged',
        action: 'fetch_required',
      });
    });
  });
});
