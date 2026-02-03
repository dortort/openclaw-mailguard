# Autopilot Spec: MailGuard Security Fixes

## Requirements

### HIGH Priority Fixes (5 issues)

1. **Missing CLI input validation** (`src/cli/mailguard.ts:209, 265`)
   - Validate quarantine IDs match `/^[a-zA-Z0-9\-_]+$/`

2. **Unbounded session Maps** (`src/policy/tool_firewall.ts:184`)
   - Add max size with LRU eviction (maxSessions = 10000)

3. **Timing-safe comparison leaks length** (`src/http/gmail_ingress.ts:468-483`)
   - Pad buffers to equal length before comparison

4. **Workflow ID collision risk** (`src/workflows/lobster_adapter.ts:88`)
   - Use `randomUUID()` instead of timestamp

5. **No SSRF protection on ML endpoint** (`src/risk/heuristics.ts:613-642`)
   - Block localhost/private IPs

### MEDIUM Priority Fixes (3 issues selected)

6. **CLI uses console.log instead of logger** (`src/cli/mailguard.ts`)
   - Create CLI output helper that wraps console.log but uses logger for structured logs

7. **Version hardcoded in multiple places** (`src/index.ts:30`, `openclaw.plugin.json:4`)
   - Read version from package.json at runtime

8. **language_detector.ts implemented but unused**
   - Integrate into risk assessment to select appropriate language patterns

### Test Coverage Gaps

9. **Add multilingual pattern tests** - Spanish, French, Chinese, Arabic
10. **Add Gmail ingress tests** - HTTP flows, webhook handling
11. **Add CLI command tests** - Basic command handlers
12. **Add Lobster adapter tests** - Workflow management

## Implementation Plan

### Step 1: Security Fixes (HIGH priority)
- Fix CLI input validation with ID pattern check
- Add maxSessions limit with oldest-first eviction
- Fix timing-safe comparison with padding
- Use randomUUID() for workflow IDs
- Add SSRF protection with private IP blocking

### Step 2: Code Quality Fixes (MEDIUM priority)
- Create CLIOutput class with logger integration
- Read version from package.json dynamically
- Integrate language detector into risk assessment

### Step 3: Test Coverage
- Add multilingual pattern tests for 4 languages
- Add Gmail ingress handler tests
- Add CLI command tests
- Add Lobster adapter tests
