/**
 * Gmail Ingress HTTP Handler
 * Receives Gmail webhook payloads, sanitizes content, and forwards to agent
 */

import { timingSafeEqual as cryptoTimingSafeEqual, randomUUID } from 'crypto';

import type {
  HttpRequest,
  HttpResponse,
  MailGuardConfig,
  GmailPubSubPayload,
  GmailMessagePayload,
  SanitizedEnvelope,
  EmailProvenance,
  AuditLogEntry,
  Logger,
  PluginStorage,
} from '../types.js';

import {
  sanitizeEmailContent,
  parseEmailHeaders,
  extractAttachmentMetadata,
  extractBodyContent,
} from '../sanitize/html_to_text.js';

import { assessRisk, classifyWithML, combineScores, shouldQuarantine } from '../risk/heuristics.js';
import { ToolFirewall } from '../policy/tool_firewall.js';

// ============================================================================
// Rate Limiting
// ============================================================================

interface RateLimitEntry {
  count: number;
  windowStart: number;
}

class RateLimiter {
  private limits: Map<string, RateLimitEntry> = new Map();
  private windowMs: number = 3600000; // 1 hour

  constructor(private maxPerWindow: number) {}

  check(key: string): { allowed: boolean; remaining: number } {
    const now = Date.now();
    const entry = this.limits.get(key);

    if (!entry || now - entry.windowStart > this.windowMs) {
      this.limits.set(key, { count: 1, windowStart: now });
      return { allowed: true, remaining: this.maxPerWindow - 1 };
    }

    if (entry.count >= this.maxPerWindow) {
      return { allowed: false, remaining: 0 };
    }

    entry.count++;
    return { allowed: true, remaining: this.maxPerWindow - entry.count };
  }

  cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.limits.entries()) {
      if (now - entry.windowStart > this.windowMs) {
        this.limits.delete(key);
      }
    }
  }
}

// ============================================================================
// Gmail Ingress Handler
// ============================================================================

export class GmailIngressHandler {
  private config: MailGuardConfig;
  private logger: Logger;
  private storage: PluginStorage;
  private toolFirewall: ToolFirewall;
  private rateLimiter: RateLimiter;

  constructor(
    config: MailGuardConfig,
    logger: Logger,
    storage: PluginStorage,
    toolFirewall: ToolFirewall
  ) {
    this.config = config;
    this.logger = logger;
    this.storage = storage;
    this.toolFirewall = toolFirewall;
    this.rateLimiter = new RateLimiter(config.rateLimitPerSender);
  }

  /**
   * Main handler for Gmail webhook requests
   */
  async handle(req: HttpRequest, res: HttpResponse): Promise<void> {
    const startTime = Date.now();
    const requestId = generateRequestId();

    this.logger.info('Gmail ingress request received', { requestId });

    try {
      // Validate authentication
      if (!this.validateAuthentication(req)) {
        this.logger.warn('Authentication failed', { requestId });
        await this.emitAuditLog({
          timestamp: new Date(),
          eventType: 'authentication_failed',
          sessionId: requestId,
          details: { reason: 'Invalid or missing webhook secret' },
        });
        res.status(401).json({ error: 'Unauthorized', code: 'AUTH_FAILED' });
        return;
      }

      // Validate payload size
      if (req.rawBody.length > this.config.maxPayloadSize) {
        this.logger.warn('Payload too large', {
          requestId,
          size: req.rawBody.length,
          maxSize: this.config.maxPayloadSize,
        });
        await this.emitAuditLog({
          timestamp: new Date(),
          eventType: 'payload_rejected',
          sessionId: requestId,
          details: { reason: 'Payload too large', size: req.rawBody.length },
        });
        res.status(413).json({ error: 'Payload too large', code: 'PAYLOAD_TOO_LARGE' });
        return;
      }

      // Parse the Gmail Pub/Sub payload
      const pubsubPayload = req.body as GmailPubSubPayload;
      if (!pubsubPayload?.message?.data) {
        this.logger.warn('Invalid payload structure', { requestId });
        res.status(400).json({ error: 'Invalid payload structure', code: 'INVALID_PAYLOAD' });
        return;
      }

      // Decode the notification
      const notificationData = Buffer.from(pubsubPayload.message.data, 'base64').toString('utf-8');
      const notification = JSON.parse(notificationData) as { emailAddress: string; historyId: string };

      // For this handler, we expect the full message payload to be provided
      // In a real integration, you would fetch the message using the Gmail API
      // For now, we'll check if there's an extended payload with the message content
      const messagePayload = (req.body as GmailPubSubPayload & { messagePayload?: GmailMessagePayload }).messagePayload;

      if (!messagePayload) {
        // Acknowledge the notification but indicate message fetch is needed
        this.logger.info('Notification received, message fetch required', {
          requestId,
          emailAddress: notification.emailAddress,
          historyId: notification.historyId,
        });
        res.status(200).json({
          status: 'acknowledged',
          action: 'fetch_required',
          historyId: notification.historyId,
        });
        return;
      }

      // Process the full message
      const envelope = await this.processMessage(messagePayload, requestId, startTime);

      if (!envelope) {
        res.status(500).json({ error: 'Failed to process message', code: 'PROCESSING_FAILED' });
        return;
      }

      // Check rate limits
      const senderDomain = envelope.provenance.senderDomain;
      const rateCheck = this.rateLimiter.check(senderDomain);

      if (!rateCheck.allowed) {
        this.logger.warn('Rate limit exceeded', { requestId, senderDomain });
        await this.emitAuditLog({
          timestamp: new Date(),
          eventType: 'rate_limit_exceeded',
          sessionId: requestId,
          emailId: envelope.headers.messageId,
          details: { senderDomain },
        });
        res.status(429).json({
          error: 'Rate limit exceeded',
          code: 'RATE_LIMITED',
          retryAfter: 3600,
        });
        return;
      }

      envelope.provenance.rateLimitRemaining = rateCheck.remaining;

      // Check if should be quarantined
      if (shouldQuarantine(envelope.riskScore, this.config)) {
        await this.quarantineMessage(envelope, requestId);
        res.status(200).json({
          status: 'quarantined',
          messageId: envelope.headers.messageId,
          riskScore: envelope.riskScore.score,
          reason: envelope.riskScore.recommendation,
        });
        return;
      }

      // Initialize tool firewall session
      const sessionId = `gmail-${randomUUID()}`;
      this.toolFirewall.initializeSession(sessionId, envelope.provenance, envelope.riskScore);

      // Return sanitized envelope for agent processing
      res.status(200).json({
        status: 'processed',
        sessionId,
        envelope: this.serializeEnvelope(envelope),
        deniedTools: this.toolFirewall.getDeniedTools(sessionId),
      });

    } catch (error) {
      this.logger.error('Error processing Gmail ingress', {
        requestId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({ error: 'Internal server error', code: 'INTERNAL_ERROR' });
    }
  }

  /**
   * Process a Gmail message into a sanitized envelope
   */
  private async processMessage(
    payload: GmailMessagePayload,
    requestId: string,
    startTime: number
  ): Promise<SanitizedEnvelope | null> {
    try {
      // Parse headers
      const headers = parseEmailHeaders(payload);

      // Check if sender is blocklisted
      const senderDomain = this.extractDomain(headers.from);
      if (this.config.blockedSenderDomains.includes(senderDomain)) {
        this.logger.warn('Blocked sender domain', { requestId, senderDomain });
        await this.emitAuditLog({
          timestamp: new Date(),
          eventType: 'payload_rejected',
          sessionId: requestId,
          emailId: headers.messageId,
          details: { reason: 'Blocked sender domain', domain: senderDomain },
        });
        return null;
      }

      // Extract body content
      const { html, plain } = extractBodyContent(payload);

      // Sanitize content
      const sanitizationResult = sanitizeEmailContent(
        html,
        plain,
        this.config.maxBodyLength
      );

      // Extract attachment metadata
      const attachments = extractAttachmentMetadata(payload);

      // Create provenance record
      const provenance: EmailProvenance = {
        source: 'gmail',
        hookName: 'mailguard-gmail',
        receivedAt: new Date(),
        senderDomain,
        isAllowlistedDomain: this.config.allowedSenderDomains.includes(senderDomain),
        isBlocklistedDomain: false,
        rateLimitRemaining: 0, // Will be set later
      };

      // Assess risk
      let riskScore = assessRisk(
        sanitizationResult.bodyText,
        sanitizationResult.links,
        headers,
        this.config
      );

      // Optional: ML classification
      if (this.config.enableMLClassifier && this.config.mlClassifierEndpoint) {
        const mlResult = await classifyWithML(
          sanitizationResult.bodyText,
          this.config.mlClassifierEndpoint
        );
        if (mlResult) {
          riskScore = {
            ...riskScore,
            score: combineScores(riskScore.score, mlResult),
            mlScore: mlResult.score,
          };
        }
      }

      const processingTimeMs = Date.now() - startTime;

      // Build sanitized envelope
      const envelope: SanitizedEnvelope = {
        headers,
        bodyText: sanitizationResult.bodyText,
        quotedBlocks: sanitizationResult.quotedBlocks,
        links: sanitizationResult.links,
        attachments,
        signals: riskScore.signals,
        riskScore,
        provenance,
        sanitizationMetadata: {
          originalLength: sanitizationResult.originalLength,
          sanitizedLength: sanitizationResult.sanitizedLength,
          truncated: sanitizationResult.sanitizedLength < sanitizationResult.originalLength,
          hiddenContentRemoved: sanitizationResult.hiddenContentRemoved,
          encodingNormalized: sanitizationResult.encodingNormalized,
          processingTimeMs,
        },
      };

      // Emit audit log
      await this.emitAuditLog({
        timestamp: new Date(),
        eventType: 'sanitization_complete',
        sessionId: requestId,
        emailId: headers.messageId,
        details: {
          from: headers.from,
          subject: headers.subject,
          sanitizedLength: sanitizationResult.sanitizedLength,
          linkCount: sanitizationResult.links.length,
          attachmentCount: attachments.length,
        },
        riskScore: riskScore.score,
        signals: riskScore.signals,
        decision: riskScore.recommendation,
      });

      this.logger.info('Message processed successfully', {
        requestId,
        messageId: headers.messageId,
        riskScore: riskScore.score,
        recommendation: riskScore.recommendation,
        processingTimeMs,
      });

      return envelope;

    } catch (error) {
      this.logger.error('Error processing message', {
        requestId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return null;
    }
  }

  /**
   * Quarantine a high-risk message
   */
  private async quarantineMessage(envelope: SanitizedEnvelope, requestId: string): Promise<void> {
    const quarantineKey = `quarantine:${envelope.headers.messageId}`;

    await this.storage.set(quarantineKey, {
      envelope,
      quarantinedAt: new Date().toISOString(),
      requestId,
      reason: envelope.riskScore.recommendation,
    }, 86400 * 7); // 7 days TTL

    await this.emitAuditLog({
      timestamp: new Date(),
      eventType: 'quarantine',
      sessionId: requestId,
      emailId: envelope.headers.messageId,
      details: {
        from: envelope.headers.from,
        subject: envelope.headers.subject,
        reason: envelope.riskScore.recommendation,
      },
      riskScore: envelope.riskScore.score,
      signals: envelope.riskScore.signals,
    });

    this.logger.warn('Message quarantined', {
      requestId,
      messageId: envelope.headers.messageId,
      riskScore: envelope.riskScore.score,
      signalCount: envelope.riskScore.signals.length,
    });
  }

  /**
   * Validate webhook authentication
   */
  private validateAuthentication(req: HttpRequest): boolean {
    // Check for webhook secret in headers
    const authHeader = req.headers['x-webhook-secret'] ??
                       req.headers['authorization'] ??
                       req.headers['x-mailguard-secret'];

    if (!authHeader) {
      return false;
    }

    // Handle Bearer token format
    const secret = authHeader.startsWith('Bearer ')
      ? authHeader.slice(7)
      : authHeader;

    // Constant-time comparison to prevent timing attacks
    return timingSafeEqual(secret, this.config.webhookSecret);
  }

  /**
   * Extract domain from email address
   */
  private extractDomain(email: string): string {
    const match = email.match(/@([^\s>]+)/);
    return match?.[1]?.toLowerCase() ?? '';
  }

  /**
   * Serialize envelope for JSON response (handle Date objects)
   */
  private serializeEnvelope(envelope: SanitizedEnvelope): Record<string, unknown> {
    return {
      ...envelope,
      headers: {
        ...envelope.headers,
        date: envelope.headers.date.toISOString(),
      },
      provenance: {
        ...envelope.provenance,
        receivedAt: envelope.provenance.receivedAt.toISOString(),
      },
    };
  }

  /**
   * Emit audit log entry
   */
  private async emitAuditLog(entry: AuditLogEntry): Promise<void> {
    // Store in plugin storage for retrieval
    const logKey = `audit:${entry.timestamp.getTime()}-${Math.random().toString(36).slice(2)}`;
    await this.storage.set(logKey, entry, 86400 * 30); // 30 days TTL
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

function generateRequestId(): string {
  return `req-${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
}

/**
 * Timing-safe string comparison that prevents length leakage
 */
function timingSafeEqual(a: string, b: string): boolean {
  // Convert strings to buffers
  const aBuffer = Buffer.from(a);
  const bBuffer = Buffer.from(b);

  // Handle different lengths without leaking timing information
  // by comparing against a buffer of the expected length
  if (aBuffer.length !== bBuffer.length) {
    // Still perform a comparison to maintain constant time
    // Compare aBuffer against itself to prevent timing leakage
    cryptoTimingSafeEqual(aBuffer, aBuffer);
    return false;
  }

  return cryptoTimingSafeEqual(aBuffer, bBuffer);
}

// ============================================================================
// Handler Factory
// ============================================================================

export function createGmailIngressHandler(
  config: MailGuardConfig,
  logger: Logger,
  storage: PluginStorage,
  toolFirewall: ToolFirewall
): { method: 'POST'; handler: (req: HttpRequest, res: HttpResponse) => Promise<void> } {
  const handler = new GmailIngressHandler(config, logger, storage, toolFirewall);

  return {
    method: 'POST',
    handler: handler.handle.bind(handler),
  };
}
