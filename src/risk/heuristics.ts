/**
 * Risk Scoring Heuristics Module
 * Detects prompt injection patterns and assesses email risk
 */

import type {
  RiskSignal,
  RiskSignalType,
  RiskScore,
  ExtractedLink,
  EmailHeaders,
  MailGuardConfig,
} from '../types.js';
import { ALL_MULTILINGUAL_PATTERNS } from '../data/multilingual-patterns.js';
import { z } from 'zod';

// ============================================================================
// Constants
// ============================================================================

// Maximum input length to prevent ReDoS attacks
const MAX_BODY_LENGTH_FOR_PATTERNS = 100000; // 100KB

// ============================================================================
// Pattern Definitions
// ============================================================================

export interface PatternDefinition {
  pattern: RegExp;
  type: RiskSignalType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  weight: number;
  /** Language code: 'en', 'es', 'zh', 'universal', etc. Defaults to 'en' */
  language?: string;
}

// Instruction override patterns - attempts to override system/developer instructions
const INSTRUCTION_OVERRIDE_PATTERNS: PatternDefinition[] = [
  {
    pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|guidelines?)/i,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Attempt to ignore previous instructions',
    weight: 30,
  },
  {
    pattern: /disregard\s+(all\s+)?(your\s+)?(previous|prior|above|earlier)?\s*(instructions?|prompts?|rules?|programming)/i,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Attempt to disregard instructions',
    weight: 30,
  },
  {
    pattern: /forget\s+(everything|all|what)\s+(you|i)\s+(told|said|know)/i,
    type: 'instruction_override',
    severity: 'high',
    description: 'Attempt to reset context',
    weight: 25,
  },
  {
    pattern: /new\s+(instructions?|rules?|mode|persona|role):/i,
    type: 'instruction_override',
    severity: 'high',
    description: 'Attempt to set new instructions',
    weight: 25,
  },
  {
    pattern: /you\s+are\s+(now|actually|really)\s+(a|an|my)/i,
    type: 'role_impersonation',
    severity: 'high',
    description: 'Attempt to change AI role/identity',
    weight: 25,
  },
  {
    pattern: /pretend\s+(you\s+are|to\s+be|that)/i,
    type: 'role_impersonation',
    severity: 'medium',
    description: 'Role pretend instruction',
    weight: 15,
  },
  {
    pattern: /act\s+as\s+(if|though|a|an|my)/i,
    type: 'role_impersonation',
    severity: 'medium',
    description: 'Act-as instruction',
    weight: 15,
  },
  {
    pattern: /system\s*:\s*|developer\s*:\s*|admin\s*:\s*/i,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Fake system/developer message marker',
    weight: 35,
  },
  {
    pattern: /\[SYSTEM\]|\[ADMIN\]|\[DEVELOPER\]|\[INTERNAL\]/i,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Fake bracketed authority marker',
    weight: 35,
  },
  {
    pattern: /override\s+(safety|security|restrictions?|filters?|guardrails?)/i,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Explicit override attempt',
    weight: 40,
  },
  {
    pattern: /bypass\s+(safety|security|restrictions?|filters?|guardrails?|protection)/i,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Explicit bypass attempt',
    weight: 40,
  },
  {
    pattern: /jailbreak|DAN\s*mode|do\s+anything\s+now/i,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Known jailbreak pattern',
    weight: 45,
  },
];

// Tool baiting patterns - attempts to get AI to use specific tools
const TOOL_BAITING_PATTERNS: PatternDefinition[] = [
  {
    pattern: /run\s+(this|the\s+following)?\s*(command|script|code)/i,
    type: 'tool_baiting',
    severity: 'high',
    description: 'Command execution request',
    weight: 25,
  },
  {
    pattern: /execute\s+(this|the\s+following)?\s*(command|script|code|program)/i,
    type: 'tool_baiting',
    severity: 'high',
    description: 'Execution request',
    weight: 25,
  },
  {
    pattern: /curl\s+.*\|\s*(ba)?sh/i,
    type: 'tool_baiting',
    severity: 'critical',
    description: 'Pipe to shell pattern',
    weight: 40,
  },
  {
    pattern: /wget\s+.*&&\s*(ba)?sh/i,
    type: 'tool_baiting',
    severity: 'critical',
    description: 'Download and execute pattern',
    weight: 40,
  },
  {
    pattern: /open\s+(this|the)?\s*(link|url|website)\s+(and|then)\s+(login|sign\s*in|enter)/i,
    type: 'tool_baiting',
    severity: 'high',
    description: 'Credential phishing attempt',
    weight: 30,
  },
  {
    pattern: /visit\s+(this|the)?\s*(link|url|website)\s+(and|then)\s+(download|install)/i,
    type: 'tool_baiting',
    severity: 'high',
    description: 'Download bait',
    weight: 25,
  },
  {
    pattern: /send\s+(this|an?)?\s*(email|message|reply)\s+to/i,
    type: 'tool_baiting',
    severity: 'medium',
    description: 'Email sending request',
    weight: 15,
  },
  {
    pattern: /forward\s+(this|the)?\s*(email|message)\s+to/i,
    type: 'tool_baiting',
    severity: 'medium',
    description: 'Email forwarding request',
    weight: 15,
  },
  {
    pattern: /delete\s+(all|this|the|my)\s*(emails?|messages?|files?)/i,
    type: 'tool_baiting',
    severity: 'high',
    description: 'Deletion request',
    weight: 25,
  },
  {
    pattern: /write\s+(this|the\s+following)?\s*\w*\s*(to|into)\s+(a\s+)?file/i,
    type: 'tool_baiting',
    severity: 'high',
    description: 'File write request',
    weight: 20,
  },
  {
    pattern: /create\s+(a\s+)?(new\s+)?(file|script|program)\s+(called|named|at)/i,
    type: 'tool_baiting',
    severity: 'high',
    description: 'File creation request',
    weight: 20,
  },
  {
    pattern: /download\s+(and\s+)?(run|execute|open|install)/i,
    type: 'tool_baiting',
    severity: 'critical',
    description: 'Download and execute request',
    weight: 35,
  },
  {
    pattern: /install\s+(this|the)?\s*(package|module|software|program|extension)/i,
    type: 'tool_baiting',
    severity: 'high',
    description: 'Installation request',
    weight: 25,
  },
];

// Data exfiltration patterns
const DATA_EXFILTRATION_PATTERNS: PatternDefinition[] = [
  {
    pattern: /send\s+(me|to\s+\S+@\S+)\s+(your|the|all)?\s*(api\s*key|secret|password|credential|token)/i,
    type: 'data_exfiltration',
    severity: 'critical',
    description: 'Credential exfiltration attempt',
    weight: 45,
  },
  {
    pattern: /include\s+(your|the|all)?\s*(api\s*key|secret|password|credential|token)\s+in\s+(your|the)\s+(response|reply)/i,
    type: 'data_exfiltration',
    severity: 'critical',
    description: 'Credential disclosure request',
    weight: 45,
  },
  {
    pattern: /what\s+(is|are)\s+(your|the)\s*(api\s*key|secret|password|credential|token|system\s*prompt)/i,
    type: 'prompt_leak_attempt',
    severity: 'high',
    description: 'System information disclosure attempt',
    weight: 30,
  },
  {
    pattern: /reveal\s+(your|the)\s*(instructions?|prompt|rules?|guidelines?|system)/i,
    type: 'prompt_leak_attempt',
    severity: 'high',
    description: 'Prompt leak attempt',
    weight: 30,
  },
  {
    pattern: /print\s+(your|the)\s*(instructions?|prompt|rules?|guidelines?|system)/i,
    type: 'prompt_leak_attempt',
    severity: 'high',
    description: 'Prompt disclosure attempt',
    weight: 30,
  },
  {
    pattern: /output\s+(all|your|the)\s*(files?|data|content|information)\s+(to|at)\s+\S+/i,
    type: 'data_exfiltration',
    severity: 'high',
    description: 'Data output to external destination',
    weight: 30,
  },
  {
    pattern: /upload\s+(all|your|the|my)?\s*(files?|data|documents?)\s+(to|at)/i,
    type: 'data_exfiltration',
    severity: 'high',
    description: 'Upload request',
    weight: 25,
  },
];

// Obfuscation patterns
const OBFUSCATION_PATTERNS: PatternDefinition[] = [
  {
    pattern: /[A-Za-z0-9+/]{32,}={0,2}/,
    type: 'obfuscation',
    severity: 'medium',
    description: 'Potential base64 encoded content',
    weight: 10,
  },
  {
    pattern: /\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){5,}/i,
    type: 'obfuscation',
    severity: 'high',
    description: 'Hex escape sequence',
    weight: 20,
  },
  {
    pattern: /\\u[0-9a-f]{4}(\\u[0-9a-f]{4}){5,}/i,
    type: 'obfuscation',
    severity: 'high',
    description: 'Unicode escape sequence',
    weight: 20,
  },
  {
    pattern: /&#\d{2,3};(&#\d{2,3};){5,}/,
    type: 'encoding_abuse',
    severity: 'medium',
    description: 'HTML numeric entities',
    weight: 15,
  },
  {
    pattern: /(%[0-9a-f]{2}){5,}/i,
    type: 'encoding_abuse',
    severity: 'medium',
    description: 'URL encoded sequence',
    weight: 15,
  },
  {
    pattern: /[\u200B-\u200D\uFEFF\u2060\u180E]/,
    type: 'hidden_content',
    severity: 'high',
    description: 'Zero-width characters detected',
    weight: 25,
  },
  {
    pattern: /[\u202A-\u202E\u2066-\u2069]/,
    type: 'hidden_content',
    severity: 'high',
    description: 'Unicode directional override characters',
    weight: 25,
  },
];

// Command injection patterns
const COMMAND_INJECTION_PATTERNS: PatternDefinition[] = [
  {
    pattern: /;\s*(rm|del|format|fdisk|dd|mkfs)\s/i,
    type: 'command_injection',
    severity: 'critical',
    description: 'Destructive command injection',
    weight: 45,
  },
  {
    pattern: /\|\s*(ba)?sh\s*$/im,
    type: 'command_injection',
    severity: 'critical',
    description: 'Pipe to shell',
    weight: 40,
  },
  {
    pattern: /`[^`]+`/,
    type: 'command_injection',
    severity: 'medium',
    description: 'Backtick command substitution',
    weight: 15,
  },
  {
    pattern: /\$\([^)]+\)/,
    type: 'command_injection',
    severity: 'medium',
    description: 'Command substitution',
    weight: 15,
  },
  {
    pattern: /;\s*(curl|wget|nc|netcat)\s+/i,
    type: 'command_injection',
    severity: 'high',
    description: 'Network command injection',
    weight: 30,
  },
  {
    pattern: /&&\s*(sudo|su|chmod|chown)\s+/i,
    type: 'command_injection',
    severity: 'high',
    description: 'Privilege escalation attempt',
    weight: 30,
  },
];

// Urgency and social engineering patterns
const URGENCY_PATTERNS: PatternDefinition[] = [
  {
    pattern: /urgent|immediately|right\s+now|asap|time\s+sensitive|act\s+(fast|now|quickly)/i,
    type: 'urgency_manipulation',
    severity: 'low',
    description: 'Urgency language',
    weight: 5,
  },
  {
    pattern: /your\s+account\s+(will\s+be|has\s+been)\s+(suspended|locked|closed|terminated)/i,
    type: 'urgency_manipulation',
    severity: 'medium',
    description: 'Account threat language',
    weight: 15,
  },
  {
    pattern: /verify\s+your\s+(identity|account|information)\s+(immediately|now|within)/i,
    type: 'urgency_manipulation',
    severity: 'medium',
    description: 'Verification urgency',
    weight: 15,
  },
  {
    pattern: /limited\s+time|expires?\s+(soon|today|in\s+\d+)|only\s+\d+\s+(left|remaining)/i,
    type: 'urgency_manipulation',
    severity: 'low',
    description: 'Scarcity language',
    weight: 5,
  },
];

// Financial keywords
const FINANCIAL_PATTERNS: PatternDefinition[] = [
  {
    pattern: /wire\s+transfer|bank\s+transfer|send\s+money|payment\s+details/i,
    type: 'financial_keywords',
    severity: 'medium',
    description: 'Wire transfer request',
    weight: 15,
  },
  {
    pattern: /bitcoin|cryptocurrency|crypto\s+wallet|btc\s+address/i,
    type: 'financial_keywords',
    severity: 'medium',
    description: 'Cryptocurrency reference',
    weight: 10,
  },
  {
    pattern: /gift\s+card|itunes\s+card|google\s+play\s+card|amazon\s+card/i,
    type: 'financial_keywords',
    severity: 'high',
    description: 'Gift card scam indicator',
    weight: 25,
  },
  {
    pattern: /invoice\s+attached|payment\s+(overdue|due)|outstanding\s+balance/i,
    type: 'financial_keywords',
    severity: 'low',
    description: 'Invoice/payment language',
    weight: 5,
  },
];

// All patterns combined (English + Multilingual)
const ALL_PATTERNS: PatternDefinition[] = [
  // English patterns (default language)
  ...INSTRUCTION_OVERRIDE_PATTERNS.map(p => ({ ...p, language: p.language ?? 'en' })),
  ...TOOL_BAITING_PATTERNS.map(p => ({ ...p, language: p.language ?? 'en' })),
  ...DATA_EXFILTRATION_PATTERNS.map(p => ({ ...p, language: p.language ?? 'en' })),
  ...OBFUSCATION_PATTERNS.map(p => ({ ...p, language: p.language ?? 'universal' })),
  ...COMMAND_INJECTION_PATTERNS.map(p => ({ ...p, language: p.language ?? 'universal' })),
  ...URGENCY_PATTERNS.map(p => ({ ...p, language: p.language ?? 'en' })),
  ...FINANCIAL_PATTERNS.map(p => ({ ...p, language: p.language ?? 'en' })),
  // Multilingual patterns (Spanish, French, German, Portuguese, Chinese, Japanese, Russian, Arabic, Korean, Italian)
  ...ALL_MULTILINGUAL_PATTERNS,
];

// Pre-compile patterns for performance and safety
const COMPILED_PATTERNS = ALL_PATTERNS.map(p => ({
  ...p,
  compiled: new RegExp(p.pattern.source, p.pattern.flags + (p.pattern.flags.includes('g') ? '' : 'g')),
}));

// ============================================================================
// Risk Assessment Functions
// ============================================================================

export function assessRisk(
  bodyText: string,
  links: ExtractedLink[],
  headers: EmailHeaders,
  config: MailGuardConfig
): RiskScore {
  const signals: RiskSignal[] = [];
  let totalWeight = 0;

  // Truncate input to prevent ReDoS
  const truncatedText = bodyText.length > MAX_BODY_LENGTH_FOR_PATTERNS
    ? bodyText.substring(0, MAX_BODY_LENGTH_FOR_PATTERNS)
    : bodyText;

  // Scan for patterns using pre-compiled regex
  for (const patternDef of COMPILED_PATTERNS) {
    try {
      // Reset lastIndex for global patterns
      patternDef.compiled.lastIndex = 0;
      const matches = truncatedText.matchAll(patternDef.compiled);
      for (const match of matches) {
        signals.push({
          type: patternDef.type,
          severity: patternDef.severity,
          description: patternDef.description,
          evidence: match[0].substring(0, 100),
          location: match.index !== undefined ? {
            start: match.index,
            end: match.index + match[0].length,
          } : undefined,
        });
        totalWeight += patternDef.weight;

        // Limit signals per pattern to prevent memory issues
        if (signals.filter(s => s.description === patternDef.description).length >= 10) {
          break;
        }
      }
    } catch {
      // Skip patterns that cause errors (e.g., timeout)
      continue;
    }
  }

  // Assess suspicious links
  for (const link of links) {
    if (link.suspicious) {
      signals.push({
        type: 'suspicious_link',
        severity: 'medium',
        description: `Suspicious link detected: ${link.domain}`,
        evidence: link.url.substring(0, 100),
      });
      totalWeight += 15;

      if (link.suspicionReasons) {
        for (const reason of link.suspicionReasons) {
          if (reason.includes('IP address') || reason.includes('lookalike')) {
            totalWeight += 10;
          }
        }
      }
    }
  }

  // Check authentication results
  if (headers.authResults) {
    if (headers.authResults.spf === 'fail') {
      signals.push({
        type: 'suspicious_link',
        severity: 'high',
        description: 'SPF authentication failed',
      });
      totalWeight += 20;
    }
    if (headers.authResults.dkim === 'fail') {
      signals.push({
        type: 'suspicious_link',
        severity: 'high',
        description: 'DKIM authentication failed',
      });
      totalWeight += 20;
    }
    if (headers.authResults.dmarc === 'fail') {
      signals.push({
        type: 'suspicious_link',
        severity: 'high',
        description: 'DMARC authentication failed',
      });
      totalWeight += 25;
    }
  }

  // Check sender domain against blocklist
  const senderDomain = extractSenderDomain(headers.from);
  if (config.blockedSenderDomains.includes(senderDomain)) {
    signals.push({
      type: 'suspicious_link',
      severity: 'critical',
      description: 'Sender domain is blocklisted',
    });
    totalWeight += 50;
  }

  // Apply trust discount for allowlisted domains
  if (config.allowedSenderDomains.includes(senderDomain)) {
    totalWeight = Math.floor(totalWeight * 0.5);
  }

  // Cap the score at 100
  const score = Math.min(100, totalWeight);

  // Determine recommendation
  let recommendation: RiskScore['recommendation'];
  if (score >= 80) {
    recommendation = 'block';
  } else if (score >= config.riskThreshold) {
    recommendation = 'quarantine';
  } else if (score >= 30) {
    recommendation = 'review';
  } else {
    recommendation = 'allow';
  }

  // Compile reasons
  const reasons = signals.map(s => s.description);
  const uniqueReasons = [...new Set(reasons)];

  return {
    score,
    reasons: uniqueReasons,
    signals,
    recommendation,
  };
}

// ============================================================================
// ML Classifier Integration (Optional)
// ============================================================================

export interface MLClassifierResult {
  score: number;
  confidence: number;
  labels: string[];
}

const MLClassifierResultSchema = z.object({
  score: z.number().min(0).max(100),
  confidence: z.number().min(0).max(1),
  labels: z.array(z.string()),
});

export async function classifyWithML(
  bodyText: string,
  endpoint: string
): Promise<MLClassifierResult | null> {
  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        text: bodyText.substring(0, 10000), // Limit input size
      }),
    });

    if (!response.ok) {
      return null;
    }

    const rawResult = await response.json();
    const parseResult = MLClassifierResultSchema.safeParse(rawResult);

    if (!parseResult.success) {
      return null;
    }

    return parseResult.data;
  } catch {
    return null;
  }
}

export function combineScores(
  heuristicScore: number,
  mlResult: MLClassifierResult | null,
  mlWeight: number = 0.3
): number {
  if (!mlResult) {
    return heuristicScore;
  }

  // Weighted combination, with ML having configurable influence
  const combined = (heuristicScore * (1 - mlWeight)) + (mlResult.score * mlWeight);
  return Math.min(100, Math.round(combined));
}

// ============================================================================
// Helper Functions
// ============================================================================

function extractSenderDomain(from: string): string {
  const match = from.match(/@([^\s>]+)/);
  return match?.[1]?.toLowerCase() ?? '';
}

export function generateRiskSummary(riskScore: RiskScore): string {
  const levelDescriptions: Record<RiskScore['recommendation'], string> = {
    allow: 'This email appears to be safe.',
    review: 'This email has some suspicious characteristics and should be reviewed.',
    quarantine: 'This email has multiple risk indicators and has been quarantined.',
    block: 'This email has critical risk indicators and has been blocked.',
  };

  let summary = levelDescriptions[riskScore.recommendation];

  if (riskScore.signals.length > 0) {
    const criticalSignals = riskScore.signals.filter(s => s.severity === 'critical');
    const highSignals = riskScore.signals.filter(s => s.severity === 'high');

    if (criticalSignals.length > 0) {
      summary += ` Critical issues detected: ${criticalSignals.map(s => s.description).join(', ')}.`;
    }
    if (highSignals.length > 0) {
      summary += ` High-risk patterns found: ${highSignals.map(s => s.description).join(', ')}.`;
    }
  }

  return summary;
}

export function shouldQuarantine(riskScore: RiskScore, config: MailGuardConfig): boolean {
  if (!config.quarantineEnabled) {
    return false;
  }

  return riskScore.recommendation === 'quarantine' || riskScore.recommendation === 'block';
}
