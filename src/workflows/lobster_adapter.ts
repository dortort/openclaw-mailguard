/**
 * Lobster Workflow Adapter
 * Integrates with OpenClaw's Lobster deterministic workflow system for approval gating
 */

import { randomUUID } from 'crypto';
import type {
  MailGuardConfig,
  ApprovalRequest,
  SideEffectPlan,
  PlannedAction,
  RiskSignal,
  Logger,
  PluginStorage,
} from '../types.js';

// ============================================================================
// Lobster Workflow Types
// ============================================================================

export interface LobsterWorkflow {
  id: string;
  name: string;
  template: string;
  steps: LobsterStep[];
  status: 'pending' | 'in_progress' | 'completed' | 'failed' | 'cancelled';
  createdAt: Date;
  updatedAt: Date;
  context: Record<string, unknown>;
}

export interface LobsterStep {
  id: string;
  name: string;
  type: 'approval' | 'action' | 'condition' | 'wait';
  status: 'pending' | 'in_progress' | 'completed' | 'skipped' | 'failed';
  config: Record<string, unknown>;
  result?: unknown;
  error?: string;
}

export interface LobsterApprovalStep extends LobsterStep {
  type: 'approval';
  config: {
    title: string;
    description: string;
    preview: string;
    timeout: number;
    approvers?: string[];
    requiredApprovals?: number;
  };
  result?: {
    approved: boolean;
    approvedBy?: string;
    approvedAt?: Date;
    comment?: string;
  };
}

// ============================================================================
// Lobster Adapter
// ============================================================================

export class LobsterAdapter {
  private config: MailGuardConfig;
  private logger: Logger;
  private storage: PluginStorage;
  private activeWorkflows: Map<string, LobsterWorkflow> = new Map();

  constructor(config: MailGuardConfig, logger: Logger, storage: PluginStorage) {
    this.config = config;
    this.logger = logger;
    this.storage = storage;
  }

  /**
   * Create a Lobster workflow for approving side effects
   */
  async createApprovalWorkflow(
    sessionId: string,
    plan: SideEffectPlan,
    emailContext: {
      from: string;
      subject: string;
      riskScore: number;
      signals: RiskSignal[];
    }
  ): Promise<LobsterWorkflow> {
    const workflowId = `wf-${randomUUID()}`;

    // Build approval steps for each action requiring approval
    const steps: LobsterStep[] = [];

    for (const action of plan.actions) {
      if (action.requiresApproval) {
        const approvalStep: LobsterApprovalStep = {
          id: `step-${action.id}`,
          name: `Approve: ${action.type}`,
          type: 'approval',
          status: 'pending',
          config: {
            title: `Approve ${action.type}`,
            description: this.buildApprovalDescription(action, emailContext),
            preview: action.description,
            timeout: this.config.lobsterIntegration.timeout,
          },
        };
        steps.push(approvalStep);
      }
    }

    const workflow: LobsterWorkflow = {
      id: workflowId,
      name: `MailGuard Approval - ${emailContext.subject.substring(0, 50)}`,
      template: this.config.lobsterIntegration.workflowTemplate,
      steps,
      status: 'pending',
      createdAt: new Date(),
      updatedAt: new Date(),
      context: {
        sessionId,
        planId: plan.id,
        emailFrom: emailContext.from,
        emailSubject: emailContext.subject,
        riskScore: emailContext.riskScore,
        signalCount: emailContext.signals.length,
      },
    };

    // Store workflow
    this.activeWorkflows.set(workflowId, workflow);
    await this.persistWorkflow(workflow);

    this.logger.info('Lobster workflow created', {
      workflowId,
      sessionId,
      stepCount: steps.length,
      riskScore: emailContext.riskScore,
    });

    return workflow;
  }

  /**
   * Start a workflow (begin processing approval steps)
   */
  async startWorkflow(workflowId: string): Promise<void> {
    const workflow = this.activeWorkflows.get(workflowId);
    if (!workflow) {
      throw new Error(`Workflow not found: ${workflowId}`);
    }

    workflow.status = 'in_progress';
    workflow.updatedAt = new Date();

    // Start first pending step
    const firstPending = workflow.steps.find(s => s.status === 'pending');
    if (firstPending) {
      firstPending.status = 'in_progress';
    }

    await this.persistWorkflow(workflow);

    this.logger.info('Lobster workflow started', {
      workflowId,
      currentStep: firstPending?.id,
    });
  }

  /**
   * Resolve an approval step
   */
  async resolveApproval(
    workflowId: string,
    stepId: string,
    approved: boolean,
    approvedBy: string,
    comment?: string
  ): Promise<{ workflowComplete: boolean; allApproved: boolean }> {
    const workflow = this.activeWorkflows.get(workflowId);
    if (!workflow) {
      throw new Error(`Workflow not found: ${workflowId}`);
    }

    const step = workflow.steps.find(s => s.id === stepId) as LobsterApprovalStep | undefined;
    if (!step || step.type !== 'approval') {
      throw new Error(`Approval step not found: ${stepId}`);
    }

    step.status = approved ? 'completed' : 'failed';
    step.result = {
      approved,
      approvedBy,
      approvedAt: new Date(),
      comment,
    };

    workflow.updatedAt = new Date();

    // Check if all steps are resolved
    const pendingSteps = workflow.steps.filter(s => s.status === 'pending' || s.status === 'in_progress');
    const failedSteps = workflow.steps.filter(s => s.status === 'failed');

    if (pendingSteps.length === 0) {
      workflow.status = failedSteps.length > 0 ? 'failed' : 'completed';
    } else if (approved) {
      // Start next pending step
      const nextPending = workflow.steps.find(s => s.status === 'pending');
      if (nextPending) {
        nextPending.status = 'in_progress';
      }
    } else {
      // If denied, cancel remaining steps
      for (const s of pendingSteps) {
        s.status = 'skipped';
      }
      workflow.status = 'failed';
    }

    await this.persistWorkflow(workflow);

    this.logger.info('Approval resolved', {
      workflowId,
      stepId,
      approved,
      approvedBy,
      workflowStatus: workflow.status,
    });

    return {
      workflowComplete: workflow.status === 'completed' || workflow.status === 'failed',
      allApproved: workflow.status === 'completed',
    };
  }

  /**
   * Get workflow status
   */
  async getWorkflowStatus(workflowId: string): Promise<LobsterWorkflow | null> {
    // Try memory first
    let workflow = this.activeWorkflows.get(workflowId);

    // Fall back to storage
    if (!workflow) {
      workflow = await this.storage.get<LobsterWorkflow>(`lobster:workflow:${workflowId}`);
      if (workflow) {
        this.activeWorkflows.set(workflowId, workflow);
      }
    }

    return workflow ?? null;
  }

  /**
   * Get pending approvals for a session
   */
  getPendingApprovals(sessionId: string): LobsterApprovalStep[] {
    const pending: LobsterApprovalStep[] = [];

    for (const workflow of this.activeWorkflows.values()) {
      if (workflow.context.sessionId === sessionId && workflow.status === 'in_progress') {
        for (const step of workflow.steps) {
          if (step.type === 'approval' && step.status === 'in_progress') {
            pending.push(step as LobsterApprovalStep);
          }
        }
      }
    }

    return pending;
  }

  /**
   * Cancel a workflow
   */
  async cancelWorkflow(workflowId: string, reason: string): Promise<void> {
    const workflow = this.activeWorkflows.get(workflowId);
    if (!workflow) {
      throw new Error(`Workflow not found: ${workflowId}`);
    }

    workflow.status = 'cancelled';
    workflow.updatedAt = new Date();

    for (const step of workflow.steps) {
      if (step.status === 'pending' || step.status === 'in_progress') {
        step.status = 'skipped';
        step.error = reason;
      }
    }

    await this.persistWorkflow(workflow);

    this.logger.info('Workflow cancelled', { workflowId, reason });
  }

  /**
   * Check for expired workflows
   */
  async checkExpiredWorkflows(): Promise<string[]> {
    const expired: string[] = [];
    const now = Date.now();

    for (const [workflowId, workflow] of this.activeWorkflows.entries()) {
      if (workflow.status === 'in_progress') {
        const ageMs = now - workflow.createdAt.getTime();
        const timeoutMs = this.config.lobsterIntegration.timeout * 1000;

        if (ageMs > timeoutMs) {
          workflow.status = 'failed';
          workflow.updatedAt = new Date();

          for (const step of workflow.steps) {
            if (step.status === 'pending' || step.status === 'in_progress') {
              step.status = 'failed';
              step.error = 'Approval timeout exceeded';
            }
          }

          await this.persistWorkflow(workflow);
          expired.push(workflowId);

          this.logger.warn('Workflow expired', { workflowId, ageMs });
        }
      }
    }

    return expired;
  }

  /**
   * Generate approval request from workflow step
   */
  workflowStepToApprovalRequest(
    workflow: LobsterWorkflow,
    step: LobsterApprovalStep
  ): ApprovalRequest {
    return {
      id: step.id,
      type: 'side_effect',
      action: step.name.replace('Approve: ', ''),
      details: step.config,
      riskContext: {
        emailFrom: workflow.context.emailFrom as string,
        emailSubject: workflow.context.emailSubject as string,
        riskScore: workflow.context.riskScore as number,
        signals: [],
      },
      preview: step.config.preview,
      createdAt: workflow.createdAt,
      expiresAt: new Date(workflow.createdAt.getTime() + step.config.timeout * 1000),
      status: step.status === 'in_progress' ? 'pending' : step.status === 'completed' ? 'approved' : 'denied',
    };
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  private buildApprovalDescription(
    action: PlannedAction,
    emailContext: { from: string; subject: string; riskScore: number; signals: RiskSignal[] }
  ): string {
    const lines = [
      `**Action:** ${action.type}`,
      `**Description:** ${action.description}`,
      '',
      '**Email Context:**',
      `- From: ${emailContext.from}`,
      `- Subject: ${emailContext.subject}`,
      `- Risk Score: ${emailContext.riskScore}/100`,
    ];

    if (emailContext.signals.length > 0) {
      lines.push('', '**Risk Signals:**');
      const topSignals = emailContext.signals.slice(0, 5);
      for (const signal of topSignals) {
        lines.push(`- [${signal.severity.toUpperCase()}] ${signal.description}`);
      }
      if (emailContext.signals.length > 5) {
        lines.push(`- ... and ${emailContext.signals.length - 5} more signals`);
      }
    }

    return lines.join('\n');
  }

  private async persistWorkflow(workflow: LobsterWorkflow): Promise<void> {
    const key = `lobster:workflow:${workflow.id}`;
    const ttlSeconds = this.config.lobsterIntegration.timeout + 3600; // Timeout + 1 hour buffer
    await this.storage.set(key, workflow, ttlSeconds);
  }
}

// ============================================================================
// Workflow Template Definitions
// ============================================================================

export const MAILGUARD_APPROVAL_TEMPLATE = {
  name: 'mailguard-approval',
  description: 'Standard MailGuard approval workflow for email-triggered side effects',
  defaultTimeout: 3600,
  steps: [
    {
      name: 'Review Risk Assessment',
      type: 'condition',
      description: 'Check risk score and signals before presenting approval',
    },
    {
      name: 'Present Approval Request',
      type: 'approval',
      description: 'Show operator the action details and request approval',
    },
    {
      name: 'Execute Approved Action',
      type: 'action',
      description: 'Execute the action if approved',
    },
  ],
};

// ============================================================================
// Factory
// ============================================================================

export function createLobsterAdapter(
  config: MailGuardConfig,
  logger: Logger,
  storage: PluginStorage
): LobsterAdapter {
  return new LobsterAdapter(config, logger, storage);
}
