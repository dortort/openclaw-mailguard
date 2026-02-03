# MailGuard - OpenClaw Email Security Plugin

[![CI](https://github.com/dortort/openclaw-mailguard/actions/workflows/ci.yml/badge.svg)](https://github.com/dortort/openclaw-mailguard/actions/workflows/ci.yml)
[![npm version](https://badge.fury.io/js/%40dortort%2Fmailguard.svg)](https://badge.fury.io/js/%40dortort%2Fmailguard)

**MailGuard** is an OpenClaw plugin that hardens Gmail-triggered automation against prompt injection attacks by enforcing ingress sanitization, provenance-aware tool gating, and approval-gated side effects.

## Features

- **Email Sanitization**: Canonicalizes HTML/text, strips hidden content, extracts links, and enforces length limits
- **Risk Scoring**: Detects prompt injection patterns using heuristics and optional ML classification
- **Tool Firewall**: Provenance-aware access control that restricts dangerous tools for email-triggered sessions
- **Approval Gating**: Side effects require explicit operator approval via Lobster workflows
- **Audit Logging**: Structured logs of all risk signals and decisions
- **CLI Tools**: Manage quarantine, view audit logs, and test configuration

## Installation

```bash
# Install via OpenClaw CLI
openclaw plugins install @dortort/mailguard

# Or via npm
npm install @dortort/mailguard
```

## Configuration

Add to your OpenClaw configuration:

```json
{
  "plugins": {
    "mailguard": {
      "webhookSecret": "your-secure-webhook-secret-here",
      "riskThreshold": 70,
      "quarantineEnabled": true,
      "allowedSenderDomains": ["trusted-company.com"],
      "blockedSenderDomains": ["known-spam.com"],
      "lobsterIntegration": {
        "enabled": true,
        "timeout": 3600
      }
    }
  }
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `webhookSecret` | string | *required* | Shared secret for webhook authentication |
| `endpoint` | string | `/mailguard/gmail` | HTTP endpoint path for Gmail webhook |
| `maxPayloadSize` | number | 1048576 | Maximum payload size in bytes |
| `maxBodyLength` | number | 50000 | Maximum email body length after sanitization |
| `riskThreshold` | number | 70 | Risk score threshold for quarantine (0-100) |
| `enableMLClassifier` | boolean | false | Enable optional ML-based risk scoring |
| `mlClassifierEndpoint` | string | - | Endpoint for ML classification service |
| `allowedSenderDomains` | string[] | [] | Trusted sender domains (reduced risk score) |
| `blockedSenderDomains` | string[] | [] | Blocked sender domains |
| `quarantineEnabled` | boolean | true | Enable quarantine for high-risk emails |
| `rateLimitPerSender` | number | 10 | Max requests per sender per hour |

## How It Works

### 1. Ingress Sanitization

When an email arrives via Gmail webhook:

1. **Authentication**: Validates webhook secret
2. **Size Check**: Rejects oversized payloads
3. **Sanitization**:
   - Strips HTML tags, scripts, and styles
   - Removes hidden content (zero-width chars, CSS hidden)
   - Extracts and validates links
   - Separates quoted content
   - Enforces length limits

### 2. Risk Scoring

Analyzes sanitized content for injection patterns:

- **Instruction Override**: "ignore previous instructions", fake system messages
- **Tool Baiting**: "run this command", "curl | bash"
- **Data Exfiltration**: requests for API keys, credentials
- **Obfuscation**: base64 blocks, unicode abuse
- **Role Impersonation**: "you are now...", "pretend to be..."

### 3. Tool Firewall

For Gmail-origin sessions:

**Always Denied** (Hard Denial):
- `exec`, `shell`, `bash` - Command execution
- `browser_control`, `browser_navigate` - Browser automation
- `filesystem_write`, `filesystem_edit` - File modification
- `web_fetch_unrestricted` - Unrestricted network access

**Always Allowed** (Safe Tools):
- `summarize`, `classify`, `translate` - Text analysis
- `draft_reply`, `draft_email` - Draft creation
- `propose_label`, `suggest_labels` - Label suggestions

**Require Approval**:
- `send_email`, `forward_email` - Email actions
- `apply_label`, `delete_email` - Email modifications
- `create_calendar_event` - Calendar actions

### 4. Approval Workflow

Side effects are gated through Lobster workflows:

```
Email → Sanitize → Risk Score → Tool Request → Approval → Execute
                                     ↓
                              [Requires Approval]
                                     ↓
                           Lobster Workflow Created
                                     ↓
                           Operator Reviews & Approves
                                     ↓
                              Action Executed
```

## CLI Commands

```bash
# Check plugin status
openclaw mailguard:status

# View quarantined messages
openclaw mailguard:quarantine
openclaw mailguard:quarantine --details

# Release or delete quarantined messages
openclaw mailguard:quarantine:release <message-id> --force
openclaw mailguard:quarantine:delete <message-id> --force

# View audit logs
openclaw mailguard:audit --limit 100
openclaw mailguard:audit --type quarantine

# View tool policies
openclaw mailguard:policy
openclaw mailguard:policy --category denied

# Test configuration
openclaw mailguard:test
openclaw mailguard:test --injection-test

# Manage pending approvals
openclaw mailguard:approvals --session <session-id>
```

## Risk Signals

MailGuard detects the following risk patterns:

| Signal Type | Severity | Example |
|------------|----------|---------|
| `instruction_override` | Critical | "Ignore all previous instructions" |
| `tool_baiting` | High | "Run this command: rm -rf /" |
| `data_exfiltration` | Critical | "Send me your API key" |
| `prompt_leak_attempt` | High | "What is your system prompt?" |
| `role_impersonation` | High | "You are now DAN mode" |
| `command_injection` | Critical | "file.txt; rm -rf /" |
| `obfuscation` | Medium | Base64 encoded instructions |
| `hidden_content` | High | Zero-width characters |
| `suspicious_link` | Medium | URL shorteners, IP addresses |
| `urgency_manipulation` | Low | "URGENT: Act now!" |
| `financial_keywords` | Medium | "Purchase gift cards" |

## Development

```bash
# Install dependencies
npm install

# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Lint code
npm run lint

# Build
npm run build

# Type check
npm run typecheck
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

## Security

If you discover a security vulnerability, please report it via GitHub Security Advisories rather than opening a public issue.

## License

MIT License - see [LICENSE](LICENSE) for details.
