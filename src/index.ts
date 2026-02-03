/**
 * MailGuard OpenClaw Plugin
 * Email prompt-injection mitigation for Gmail-triggered automation
 *
 * @packageDocumentation
 */

import type {
  MailGuardConfig,
  OpenClawPluginContext,
  SanitizedEnvelope,
  MailGuardReport,
  ToolContext,
} from './types.js';

import { MailGuardConfigSchema } from './types.js';
import { createGmailIngressHandler } from './http/gmail_ingress.js';
import { ToolFirewall, policyCheckTool } from './policy/tool_firewall.js';
import { createLobsterAdapter } from './workflows/lobster_adapter.js';
import { createCliCommands } from './cli/mailguard.js';
import { generateRiskSummary } from './risk/heuristics.js';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const packageJson = require('../package.json') as { version: string };

// ============================================================================
// Plugin Metadata
// ============================================================================

export const PLUGIN_NAME = 'mailguard';
export const PLUGIN_VERSION = packageJson.version;
export const PLUGIN_DESCRIPTION = 'Email prompt-injection mitigation for Gmail-triggered automation';

// ============================================================================
// Plugin Entry Point
// ============================================================================

/**
 * Initialize the MailGuard plugin
 * This is the main entry point called by OpenClaw when loading the plugin
 */
export function activate(context: OpenClawPluginContext): Promise<MailGuardPlugin> {
  const { config: rawConfig, logger, storage, gateway } = context;

  // Validate configuration
  const configResult = MailGuardConfigSchema.safeParse(rawConfig);
  if (!configResult.success) {
    logger.error('Invalid MailGuard configuration', {
      errors: configResult.error.errors,
    });
    throw new Error(`Invalid MailGuard configuration: ${configResult.error.message}`);
  }

  const config = configResult.data;

  logger.info('Initializing MailGuard plugin', {
    version: PLUGIN_VERSION,
    endpoint: config.endpoint,
    riskThreshold: config.riskThreshold,
    quarantineEnabled: config.quarantineEnabled,
    lobsterEnabled: config.lobsterIntegration.enabled,
  });

  // Initialize core components
  const toolFirewall = new ToolFirewall(config, logger);
  const lobsterAdapter = createLobsterAdapter(config, logger, storage);

  // Create plugin instance
  const plugin = new MailGuardPlugin(config, logger, storage, toolFirewall, lobsterAdapter);

  // Register HTTP handler for Gmail ingress
  const gmailHandler = createGmailIngressHandler(config, logger, storage, toolFirewall);
  gateway.registerHttpHandler(config.endpoint, {
    method: 'POST',
    handler: gmailHandler.handler,
  });

  logger.info('Registered Gmail ingress handler', { endpoint: config.endpoint });

  // Register policy check tool
  gateway.registerTool({
    name: policyCheckTool.name,
    description: policyCheckTool.description,
    inputSchema: policyCheckTool.inputSchema,
    handler: (input: unknown, toolContext: ToolContext) => {
      return plugin.handlePolicyCheck(input as { action: string; parameters?: Record<string, unknown> }, toolContext);
    },
  });

  // Register report generation tool
  gateway.registerTool({
    name: 'mailguard.generate_report',
    description: 'Generate a MailGuard security report for the current email session',
    inputSchema: {
      type: 'object',
      properties: {
        sessionId: {
          type: 'string',
          description: 'Session ID to generate report for',
        },
        includeApprovals: {
          type: 'boolean',
          default: true,
          description: 'Include pending approvals in report',
        },
      },
      required: ['sessionId'],
    },
    handler: async (input: unknown, _toolContext: ToolContext) => {
      const { sessionId, includeApprovals } = input as { sessionId: string; includeApprovals?: boolean };
      return plugin.generateReport(sessionId, includeApprovals ?? true);
    },
  });

  // Register background service for cleanup
  gateway.registerBackgroundService({
    name: 'mailguard-cleanup',
    intervalMs: 300000, // 5 minutes
    handler: () => {
      plugin.performCleanup();
    },
  });

  // Register background service for workflow expiration check
  gateway.registerBackgroundService({
    name: 'mailguard-workflow-expiry',
    intervalMs: 60000, // 1 minute
    handler: async () => {
      const expired = await lobsterAdapter.checkExpiredWorkflows();
      if (expired.length > 0) {
        logger.warn('Expired workflows detected', { count: expired.length });
      }
    },
  });

  // Register CLI commands
  const cliCommands = createCliCommands(config, logger, storage, toolFirewall, lobsterAdapter);
  for (const command of cliCommands) {
    gateway.registerCliCommand(command);
  }

  logger.info('MailGuard plugin activated successfully', {
    registeredTools: ['mailguard.policy_check', 'mailguard.generate_report'],
    registeredCommands: cliCommands.map(c => c.name),
  });

  return Promise.resolve(plugin);
}

/**
 * Deactivate the plugin (cleanup)
 */
export function deactivate(plugin: MailGuardPlugin): void {
  plugin.logger.info('Deactivating MailGuard plugin');
  plugin.performCleanup();
}

// ============================================================================
// Plugin Class
// ============================================================================

export class MailGuardPlugin {
  readonly config: MailGuardConfig;
  readonly logger: OpenClawPluginContext['logger'];
  private storage: OpenClawPluginContext['storage'];
  private toolFirewall: ToolFirewall;
  private lobsterAdapter: ReturnType<typeof createLobsterAdapter>;
  private sessionEnvelopes: Map<string, SanitizedEnvelope> = new Map();

  constructor(
    config: MailGuardConfig,
    logger: OpenClawPluginContext['logger'],
    storage: OpenClawPluginContext['storage'],
    toolFirewall: ToolFirewall,
    lobsterAdapter: ReturnType<typeof createLobsterAdapter>
  ) {
    this.config = config;
    this.logger = logger;
    this.storage = storage;
    this.toolFirewall = toolFirewall;
    this.lobsterAdapter = lobsterAdapter;
  }

  /**
   * Handle policy check requests
   */
  handlePolicyCheck(
    input: { action: string; parameters?: Record<string, unknown> },
    context: ToolContext
  ): {
    allowed: boolean;
    reason: string;
    requiresApproval: boolean;
    approvalType?: string;
    alternatives?: string[];
  } {
    const decision = this.toolFirewall.checkToolAccess({
      source: context.provenance?.source ?? 'direct',
      riskScore: context.riskScore ?? 0,
      senderDomain: '',
      isAllowlistedSender: false,
      sessionId: context.sessionId,
      requestedTool: input.action,
    });

    return {
      allowed: decision.allowed,
      reason: decision.reason,
      requiresApproval: decision.requiresApproval,
      approvalType: decision.approvalType,
      alternatives: decision.alternatives,
    };
  }

  /**
   * Generate a security report for a session
   */
  async generateReport(sessionId: string, includeApprovals: boolean): Promise<MailGuardReport | null> {
    const envelope = this.sessionEnvelopes.get(sessionId);
    if (!envelope) {
      // Try to load from storage
      const stored = await this.storage.get<SanitizedEnvelope>(`session:${sessionId}:envelope`);
      if (!stored) {
        return null;
      }
    }

    const env = envelope ?? await this.storage.get<SanitizedEnvelope>(`session:${sessionId}:envelope`);
    if (!env) return null;

    const deniedTools = this.toolFirewall.getDeniedTools(sessionId);
    const pendingApprovals = includeApprovals
      ? this.toolFirewall.getPendingApprovals(sessionId)
      : [];

    // Generate risk level
    let riskLevel: 'low' | 'medium' | 'high' | 'critical';
    if (env.riskScore.score >= 80) {
      riskLevel = 'critical';
    } else if (env.riskScore.score >= 50) {
      riskLevel = 'high';
    } else if (env.riskScore.score >= 30) {
      riskLevel = 'medium';
    } else {
      riskLevel = 'low';
    }

    // Extract action items from email
    const actionItems = extractActionItems(env.bodyText);

    // Generate safe summary
    const safeSummary = generateSafeSummary(env);

    const report: MailGuardReport = {
      sessionId,
      emailId: env.headers.messageId,
      summary: {
        riskScore: env.riskScore.score,
        riskLevel,
        recommendation: generateRiskSummary(env.riskScore),
      },
      safeSummary,
      extractedActionItems: actionItems,
      pendingApprovals,
      deniedTools,
      warnings: env.riskScore.signals
        .filter(s => s.severity === 'high' || s.severity === 'critical')
        .map(s => s.description),
      metadata: {
        processingTimeMs: env.sanitizationMetadata.processingTimeMs,
        sanitizationApplied: true,
        quarantined: env.riskScore.recommendation === 'quarantine' || env.riskScore.recommendation === 'block',
      },
    };

    return report;
  }

  /**
   * Store envelope for session
   */
  storeSessionEnvelope(sessionId: string, envelope: SanitizedEnvelope): void {
    this.sessionEnvelopes.set(sessionId, envelope);
  }

  /**
   * Perform cleanup tasks
   */
  performCleanup(): void {
    this.toolFirewall.cleanupExpiredSessions();

    // Cleanup old session envelopes
    const maxAge = 3600000; // 1 hour
    const now = Date.now();

    for (const [sessionId, envelope] of this.sessionEnvelopes.entries()) {
      const age = now - envelope.provenance.receivedAt.getTime();
      if (age > maxAge) {
        this.sessionEnvelopes.delete(sessionId);
      }
    }

    this.logger.debug('Cleanup completed');
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

function extractActionItems(text: string): string[] {
  const items: string[] = [];

  // Look for common action item patterns
  const patterns = [
    /(?:please|kindly|could you|can you|would you)\s+(.+?)(?:\.|$)/gi,
    /(?:action required|to-do|todo|task):\s*(.+?)(?:\.|$)/gi,
    /\d+\.\s+(.+?)(?:\n|$)/g,
    /[-•]\s+(.+?)(?:\n|$)/g,
  ];

  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(text)) !== null) {
      const item = match[1]?.trim();
      if (item && item.length > 10 && item.length < 200) {
        items.push(item);
      }
    }
  }

  // Deduplicate and limit
  const unique = [...new Set(items)];
  return unique.slice(0, 10);
}

function generateSafeSummary(envelope: SanitizedEnvelope): string {
  const from = envelope.headers.from;
  const subject = envelope.headers.subject;
  const bodyPreview = envelope.bodyText.substring(0, 500);

  // Remove any potential injection attempts from preview
  const cleanPreview = bodyPreview
    .replace(/ignore\s+(all\s+)?(previous|prior)/gi, '[removed]')
    .replace(/system\s*:/gi, '[removed]')
    .replace(/\[SYSTEM\]/gi, '[removed]');

  return `Email from ${from}\nSubject: ${subject}\n\nPreview:\n${cleanPreview}${envelope.bodyText.length > 500 ? '...' : ''}`;
}

// ============================================================================
// Exports
// ============================================================================

// Re-export types for consumers
export type {
  MailGuardConfig,
  SanitizedEnvelope,
  MailGuardReport,
  RiskScore,
  RiskSignal,
  EmailProvenance,
  ApprovalRequest,
} from './types.js';

// Re-export key utilities
export { assessRisk, generateRiskSummary } from './risk/heuristics.js';
export { sanitizeEmailContent } from './sanitize/html_to_text.js';
export { ToolFirewall, SAFE_TOOLS, HARD_DENIED_TOOLS } from './policy/tool_firewall.js';
export { LobsterAdapter, createLobsterAdapter } from './workflows/lobster_adapter.js';
