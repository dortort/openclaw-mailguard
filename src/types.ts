/**
 * MailGuard Type Definitions
 * Core types for email prompt-injection mitigation
 */

import { z } from 'zod';

// ============================================================================
// Configuration Types
// ============================================================================

export const LobsterConfigSchema = z.object({
  enabled: z.boolean().default(true),
  workflowTemplate: z.string().default('mailguard-approval'),
  timeout: z.number().min(60).max(86400).default(3600),
});

export const MailGuardConfigSchema = z.object({
  endpoint: z.string().default('/mailguard/gmail'),
  webhookSecret: z.string().min(16),
  maxPayloadSize: z.number().min(1024).max(10485760).default(1048576),
  maxBodyLength: z.number().min(1000).max(500000).default(50000),
  riskThreshold: z.number().min(0).max(100).default(70),
  enableMLClassifier: z.boolean().default(false),
  mlClassifierEndpoint: z.string().url().optional(),
  allowedSenderDomains: z.array(z.string()).default([]),
  blockedSenderDomains: z.array(z.string()).default([]),
  allowedRecipientDomains: z.array(z.string()).default([]),
  deniedTools: z.array(z.string()).default([
    'browser_control',
    'browser_navigate',
    'exec',
    'shell',
    'filesystem_write',
    'filesystem_edit',
    'filesystem_delete',
    'web_fetch_unrestricted',
    'patch',
    'code_execute',
  ]),
  approvalRequiredActions: z.array(z.string()).default([
    'send_email',
    'forward_email',
    'delete_email',
    'apply_label',
    'create_draft',
    'move_email',
  ]),
  quarantineEnabled: z.boolean().default(true),
  rateLimitPerSender: z.number().min(1).max(1000).default(10),
  logLevel: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
  auditLogPath: z.string().optional(),
  allowUnsafeExternalContent: z.boolean().default(false),
  lobsterIntegration: LobsterConfigSchema.default({}),
});

export type MailGuardConfig = z.infer<typeof MailGuardConfigSchema>;
export type LobsterConfig = z.infer<typeof LobsterConfigSchema>;

// ============================================================================
// Email Envelope Types
// ============================================================================

export interface EmailHeaders {
  messageId: string;
  threadId?: string;
  from: string;
  to: string[];
  cc?: string[];
  bcc?: string[];
  subject: string;
  date: Date;
  replyTo?: string;
  inReplyTo?: string;
  references?: string[];
  authResults?: AuthenticationResults;
}

export interface AuthenticationResults {
  spf?: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none';
  dkim?: 'pass' | 'fail' | 'none';
  dmarc?: 'pass' | 'fail' | 'none';
}

export interface ExtractedLink {
  url: string;
  domain: string;
  normalizedUrl: string;
  text?: string;
  context?: string;
  suspicious: boolean;
  suspicionReasons?: string[];
}

export interface AttachmentMetadata {
  filename: string;
  mimeType: string;
  size: number;
  contentId?: string;
  isInline: boolean;
}

export interface QuotedBlock {
  content: string;
  depth: number;
  attribution?: string;
}

export interface RiskSignal {
  type: RiskSignalType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  evidence?: string;
  location?: {
    start: number;
    end: number;
  };
}

export type RiskSignalType =
  | 'instruction_override'
  | 'tool_baiting'
  | 'obfuscation'
  | 'urgency_manipulation'
  | 'financial_keywords'
  | 'suspicious_link'
  | 'hidden_content'
  | 'encoding_abuse'
  | 'prompt_leak_attempt'
  | 'role_impersonation'
  | 'data_exfiltration'
  | 'command_injection';

export interface RiskScore {
  score: number; // 0-100
  mlScore?: number; // Optional ML classifier score
  reasons: string[];
  signals: RiskSignal[];
  recommendation: 'allow' | 'review' | 'quarantine' | 'block';
}

export interface SanitizedEnvelope {
  headers: EmailHeaders;
  bodyText: string;
  quotedBlocks: QuotedBlock[];
  links: ExtractedLink[];
  attachments: AttachmentMetadata[];
  signals: RiskSignal[];
  riskScore: RiskScore;
  provenance: EmailProvenance;
  sanitizationMetadata: {
    originalLength: number;
    sanitizedLength: number;
    truncated: boolean;
    hiddenContentRemoved: boolean;
    encodingNormalized: boolean;
    processingTimeMs: number;
  };
}

export interface EmailProvenance {
  source: 'gmail';
  hookName: string;
  receivedAt: Date;
  senderDomain: string;
  isAllowlistedDomain: boolean;
  isBlocklistedDomain: boolean;
  rateLimitRemaining: number;
}

// ============================================================================
// Gmail Webhook Types
// ============================================================================

export interface GmailPubSubPayload {
  message: {
    data: string; // Base64 encoded
    messageId: string;
    publishTime: string;
  };
  subscription: string;
}

export interface GmailNotification {
  emailAddress: string;
  historyId: string;
}

export interface GmailMessagePayload {
  id: string;
  threadId: string;
  labelIds: string[];
  snippet: string;
  payload: {
    partId?: string;
    mimeType: string;
    filename: string;
    headers: Array<{ name: string; value: string }>;
    body: {
      size: number;
      data?: string;
    };
    parts?: GmailMessagePart[];
  };
  sizeEstimate: number;
  historyId: string;
  internalDate: string;
}

export interface GmailMessagePart {
  partId: string;
  mimeType: string;
  filename: string;
  headers: Array<{ name: string; value: string }>;
  body: {
    size: number;
    data?: string;
    attachmentId?: string;
  };
  parts?: GmailMessagePart[];
}

// ============================================================================
// Tool Policy Types
// ============================================================================

export interface ToolPolicyContext {
  source: 'gmail' | 'direct' | 'api' | 'hook';
  riskScore: number;
  senderDomain: string;
  isAllowlistedSender: boolean;
  sessionId: string;
  requestedTool: string;
  requestedAction?: string;
}

export interface ToolPolicyDecision {
  allowed: boolean;
  reason: string;
  requiresApproval: boolean;
  approvalType?: 'lobster' | 'exec-approval';
  denialType?: 'hard' | 'soft';
  alternatives?: string[];
}

// ============================================================================
// Approval Workflow Types
// ============================================================================

export interface ApprovalRequest {
  id: string;
  type: 'side_effect';
  action: string;
  details: Record<string, unknown>;
  riskContext: {
    emailFrom: string;
    emailSubject: string;
    riskScore: number;
    signals: RiskSignal[];
  };
  preview: string;
  createdAt: Date;
  expiresAt: Date;
  status: 'pending' | 'approved' | 'denied' | 'expired';
  resolvedBy?: string;
  resolvedAt?: Date;
}

export interface SideEffectPlan {
  id: string;
  sessionId: string;
  actions: PlannedAction[];
  status: 'pending_approval' | 'approved' | 'partially_approved' | 'denied';
  approvals: ApprovalRequest[];
}

export interface PlannedAction {
  id: string;
  type: string;
  description: string;
  parameters: Record<string, unknown>;
  requiresApproval: boolean;
  approved: boolean;
}

// ============================================================================
// Audit Log Types
// ============================================================================

export interface AuditLogEntry {
  timestamp: Date;
  eventType: AuditEventType;
  sessionId: string;
  emailId?: string;
  details: Record<string, unknown>;
  riskScore?: number;
  signals?: RiskSignal[];
  decision?: string;
  outcome?: string;
}

export type AuditEventType =
  | 'email_received'
  | 'sanitization_complete'
  | 'risk_assessment'
  | 'tool_request'
  | 'tool_denied'
  | 'tool_allowed'
  | 'approval_requested'
  | 'approval_granted'
  | 'approval_denied'
  | 'quarantine'
  | 'rate_limit_exceeded'
  | 'authentication_failed'
  | 'payload_rejected';

// ============================================================================
// Report Types
// ============================================================================

export interface MailGuardReport {
  sessionId: string;
  emailId: string;
  summary: {
    riskScore: number;
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
    recommendation: string;
  };
  safeSummary: string;
  extractedActionItems: string[];
  proposedReplyDraft?: string;
  pendingApprovals: ApprovalRequest[];
  deniedTools: string[];
  warnings: string[];
  metadata: {
    processingTimeMs: number;
    sanitizationApplied: boolean;
    quarantined: boolean;
  };
}

// ============================================================================
// OpenClaw Plugin Interface Types
// ============================================================================

export interface OpenClawPluginContext {
  config: MailGuardConfig;
  logger: Logger;
  storage: PluginStorage;
  gateway: GatewayContext;
}

export interface Logger {
  debug(message: string, meta?: Record<string, unknown>): void;
  info(message: string, meta?: Record<string, unknown>): void;
  warn(message: string, meta?: Record<string, unknown>): void;
  error(message: string, meta?: Record<string, unknown>): void;
}

export interface PluginStorage {
  get<T>(key: string): Promise<T | undefined>;
  set<T>(key: string, value: T, ttlSeconds?: number): Promise<void>;
  delete(key: string): Promise<void>;
  list(prefix: string): Promise<string[]>;
}

export interface GatewayContext {
  registerHttpHandler(
    path: string,
    handler: HttpHandler
  ): void;
  registerTool(tool: ToolDefinition): void;
  registerBackgroundService(service: BackgroundService): void;
  registerCliCommand(command: CliCommand): void;
  emitAuditLog(entry: AuditLogEntry): void;
  createApprovalRequest(request: Omit<ApprovalRequest, 'id' | 'createdAt' | 'status'>): Promise<ApprovalRequest>;
}

export interface HttpHandler {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  handler: (req: HttpRequest, res: HttpResponse) => Promise<void>;
}

export interface HttpRequest {
  method: string;
  path: string;
  headers: Record<string, string>;
  query: Record<string, string>;
  body: unknown;
  rawBody: Buffer;
}

export interface HttpResponse {
  status(code: number): HttpResponse;
  json(data: unknown): void;
  send(data: string | Buffer): void;
  header(name: string, value: string): HttpResponse;
}

export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  handler: (input: unknown, context: ToolContext) => Promise<unknown>;
}

export interface ToolContext {
  sessionId: string;
  provenance?: EmailProvenance;
  riskScore?: number;
  logger: Logger;
}

export interface BackgroundService {
  name: string;
  intervalMs: number;
  handler: () => Promise<void>;
}

export interface CliCommand {
  name: string;
  description: string;
  options?: CliOption[];
  handler: (args: Record<string, unknown>) => Promise<void>;
}

export interface CliOption {
  name: string;
  alias?: string;
  description: string;
  type: 'string' | 'boolean' | 'number';
  required?: boolean;
  default?: unknown;
}
