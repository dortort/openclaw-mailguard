/**
 * HTML/Text Sanitization Module
 * Converts email content to safe, canonical plaintext
 */

import type {
  ExtractedLink,
  QuotedBlock,
  AttachmentMetadata,
  EmailHeaders,
  AuthenticationResults,
  GmailMessagePayload,
  GmailMessagePart,
} from '../types.js';

// ============================================================================
// Constants
// ============================================================================

const ZERO_WIDTH_CHARS = /[\u200B-\u200D\uFEFF\u2060\u180E]/g;
const HIDDEN_UNICODE = /[\u2028\u2029\u202A-\u202E\u2066-\u2069]/g;
const EXCESSIVE_WHITESPACE = /[\t ]{3,}/g;
const MULTIPLE_NEWLINES = /\n{4,}/g;
const HTML_COMMENT = /<!--[\s\S]*?-->/g;
const STYLE_TAG = /<style[^>]*>[\s\S]*?<\/style>/gi;
const SCRIPT_TAG = /<script[^>]*>[\s\S]*?<\/script>/gi;
const HIDDEN_ELEMENT = /<[^>]+(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)[^>]*>[\s\S]*?<\/[^>]+>/gi;
const HTML_TAG = /<[^>]+>/g;

// URL extraction patterns
const URL_PATTERN = /https?:\/\/[^\s<>"')\]]+/gi;
const HREF_PATTERN = /href\s*=\s*["']([^"']+)["']/gi;
const MAILTO_PATTERN = /mailto:([^\s<>"']+)/gi;

// Quote detection patterns
const QUOTE_PREFIXES = [
  /^>\s*/gm,
  /^On .+ wrote:$/gm,
  /^-{3,}\s*Original Message\s*-{3,}$/gim,
  /^From:\s+.+$/gm,
  /^Sent:\s+.+$/gm,
];

// Suspicious URL patterns
const SUSPICIOUS_URL_PATTERNS = [
  /bit\.ly/i,
  /tinyurl\.com/i,
  /goo\.gl/i,
  /t\.co/i,
  /rb\.gy/i,
  /ow\.ly/i,
  /is\.gd/i,
  /buff\.ly/i,
  /adf\.ly/i,
  /shorte\.st/i,
  /data:/i,
  /javascript:/i,
  /vbscript:/i,
  /@[^/]+\//,  // URL with @ before domain (credential phishing)
  /[^\w]login[^\w]/i,
  /[^\w]signin[^\w]/i,
  /[^\w]password[^\w]/i,
  /[^\w]verify[^\w]/i,
  /[^\w]confirm[^\w]/i,
  /[^\w]secure[^\w]/i,
  /[^\w]account[^\w]/i,
  /[^\w]update[^\w]/i,
];

// ============================================================================
// Main Sanitization Functions
// ============================================================================

export interface SanitizationResult {
  bodyText: string;
  quotedBlocks: QuotedBlock[];
  links: ExtractedLink[];
  hiddenContentRemoved: boolean;
  encodingNormalized: boolean;
  originalLength: number;
  sanitizedLength: number;
}

export function sanitizeEmailContent(
  htmlContent: string | undefined,
  plainContent: string | undefined,
  maxLength: number
): SanitizationResult {
  const startLength = (htmlContent?.length ?? 0) + (plainContent?.length ?? 0);
  let hiddenContentRemoved = false;
  let encodingNormalized = false;

  // Extract links from HTML before stripping tags
  const linksFromHtml = htmlContent ? extractLinksFromHtml(htmlContent) : [];

  // Convert HTML to text
  let text = '';
  if (htmlContent) {
    const htmlResult = htmlToText(htmlContent);
    text = htmlResult.text;
    hiddenContentRemoved = htmlResult.hiddenContentRemoved;
  } else if (plainContent) {
    text = plainContent;
  }

  // Normalize encoding
  const normalizedResult = normalizeEncoding(text);
  text = normalizedResult.text;
  encodingNormalized = normalizedResult.modified;

  // Remove zero-width and hidden unicode characters
  const beforeZeroWidth = text;
  text = text.replace(ZERO_WIDTH_CHARS, '');
  text = text.replace(HIDDEN_UNICODE, '');
  if (text !== beforeZeroWidth) {
    hiddenContentRemoved = true;
  }

  // Normalize whitespace
  text = text.replace(EXCESSIVE_WHITESPACE, '  ');
  text = text.replace(MULTIPLE_NEWLINES, '\n\n\n');
  text = text.trim();

  // Extract quoted blocks
  const { mainContent, quotedBlocks } = extractQuotedBlocks(text);
  text = mainContent;

  // Extract links from plaintext
  const linksFromText = extractLinksFromText(text);

  // Merge and deduplicate links
  const allLinks = mergeLinks(linksFromHtml, linksFromText);

  // Truncate if necessary
  let truncated = false;
  if (text.length > maxLength) {
    text = text.substring(0, maxLength);
    // Try to end at a word boundary
    const lastSpace = text.lastIndexOf(' ');
    if (lastSpace > maxLength * 0.8) {
      text = text.substring(0, lastSpace);
    }
    text += '\n[Content truncated for safety]';
    truncated = true;
  }

  return {
    bodyText: text,
    quotedBlocks,
    links: allLinks,
    hiddenContentRemoved,
    encodingNormalized,
    originalLength: startLength,
    sanitizedLength: text.length,
  };
}

// ============================================================================
// HTML Processing
// ============================================================================

interface HtmlToTextResult {
  text: string;
  hiddenContentRemoved: boolean;
}

function htmlToText(html: string): HtmlToTextResult {
  let text = html;
  let hiddenContentRemoved = false;

  // Remove comments
  const beforeComments = text;
  text = text.replace(HTML_COMMENT, '');
  if (text !== beforeComments) hiddenContentRemoved = true;

  // Remove style tags
  const beforeStyle = text;
  text = text.replace(STYLE_TAG, '');
  if (text !== beforeStyle) hiddenContentRemoved = true;

  // Remove script tags
  const beforeScript = text;
  text = text.replace(SCRIPT_TAG, '');
  if (text !== beforeScript) hiddenContentRemoved = true;

  // Remove hidden elements
  const beforeHidden = text;
  text = text.replace(HIDDEN_ELEMENT, '');
  if (text !== beforeHidden) hiddenContentRemoved = true;

  // Convert block elements to newlines
  text = text.replace(/<\/?(p|div|br|hr|h[1-6]|li|tr|table|blockquote)[^>]*>/gi, '\n');

  // Convert list items
  text = text.replace(/<li[^>]*>/gi, '\n• ');

  // Remove remaining HTML tags
  text = text.replace(HTML_TAG, '');

  // Decode HTML entities
  text = decodeHtmlEntities(text);

  return { text, hiddenContentRemoved };
}

function decodeHtmlEntities(text: string): string {
  const entities: Record<string, string> = {
    '&nbsp;': ' ',
    '&amp;': '&',
    '&lt;': '<',
    '&gt;': '>',
    '&quot;': '"',
    '&#39;': "'",
    '&apos;': "'",
    '&copy;': '©',
    '&reg;': '®',
    '&trade;': '™',
    '&mdash;': '—',
    '&ndash;': '–',
    '&hellip;': '…',
    '&lsquo;': ''',
    '&rsquo;': ''',
    '&ldquo;': '"',
    '&rdquo;': '"',
    '&bull;': '•',
  };

  let result = text;
  for (const [entity, char] of Object.entries(entities)) {
    result = result.split(entity).join(char);
  }

  // Decode numeric entities
  result = result.replace(/&#(\d+);/g, (_, code) => {
    const num = parseInt(code, 10);
    return num > 0 && num < 65536 ? String.fromCharCode(num) : '';
  });

  result = result.replace(/&#x([0-9a-f]+);/gi, (_, code) => {
    const num = parseInt(code, 16);
    return num > 0 && num < 65536 ? String.fromCharCode(num) : '';
  });

  return result;
}

// ============================================================================
// Encoding Normalization
// ============================================================================

interface NormalizeResult {
  text: string;
  modified: boolean;
}

function normalizeEncoding(text: string): NormalizeResult {
  let modified = false;
  let result = text;

  // Detect and decode base64 blocks that look like they might be hidden instructions
  const base64Pattern = /(?:^|\s)([A-Za-z0-9+/]{20,}={0,2})(?:\s|$)/g;
  let match;
  while ((match = base64Pattern.exec(text)) !== null) {
    try {
      const decoded = Buffer.from(match[1] ?? '', 'base64').toString('utf-8');
      // Only flag as suspicious if it decodes to readable text
      if (/^[\x20-\x7E\s]+$/.test(decoded) && decoded.length > 10) {
        // Don't replace, but mark as modified for flagging
        modified = true;
      }
    } catch {
      // Not valid base64, ignore
    }
  }

  // Normalize common unicode confusables to ASCII
  const confusables: Record<string, string> = {
    'а': 'a', // Cyrillic
    'е': 'e',
    'о': 'o',
    'р': 'p',
    'с': 'c',
    'у': 'y',
    'х': 'x',
    'ѕ': 's',
    'і': 'i',
    'ј': 'j',
    'ԁ': 'd',
    'ɡ': 'g',
    'ʜ': 'H',
    'ɴ': 'N',
    'ꮪ': 'S',
    'ꭺ': 'A',
    '\uff41': 'a', // Fullwidth
    '\uff42': 'b',
    '\uff43': 'c',
  };

  for (const [confusable, ascii] of Object.entries(confusables)) {
    if (result.includes(confusable)) {
      result = result.split(confusable).join(ascii);
      modified = true;
    }
  }

  return { text: result, modified };
}

// ============================================================================
// Quote Extraction
// ============================================================================

interface QuoteExtractionResult {
  mainContent: string;
  quotedBlocks: QuotedBlock[];
}

function extractQuotedBlocks(text: string): QuoteExtractionResult {
  const quotedBlocks: QuotedBlock[] = [];
  const lines = text.split('\n');
  const mainLines: string[] = [];
  let currentQuote: string[] = [];
  let currentDepth = 0;
  let attribution: string | undefined;

  for (const line of lines) {
    // Check for quote markers
    const quoteMatch = line.match(/^(>+)\s*/);

    if (quoteMatch) {
      const depth = quoteMatch[1]?.length ?? 1;
      const content = line.substring(quoteMatch[0]?.length ?? 0);

      if (depth !== currentDepth && currentQuote.length > 0) {
        // Save current quote block
        quotedBlocks.push({
          content: currentQuote.join('\n'),
          depth: currentDepth,
          attribution,
        });
        currentQuote = [];
        attribution = undefined;
      }

      currentDepth = depth;
      currentQuote.push(content);
    } else if (isQuoteAttribution(line)) {
      if (currentQuote.length > 0) {
        quotedBlocks.push({
          content: currentQuote.join('\n'),
          depth: currentDepth,
          attribution,
        });
        currentQuote = [];
      }
      attribution = line;
      currentDepth = 1;
    } else {
      if (currentQuote.length > 0) {
        quotedBlocks.push({
          content: currentQuote.join('\n'),
          depth: currentDepth,
          attribution,
        });
        currentQuote = [];
        currentDepth = 0;
        attribution = undefined;
      }
      mainLines.push(line);
    }
  }

  // Don't forget the last quote block
  if (currentQuote.length > 0) {
    quotedBlocks.push({
      content: currentQuote.join('\n'),
      depth: currentDepth,
      attribution,
    });
  }

  return {
    mainContent: mainLines.join('\n'),
    quotedBlocks,
  };
}

function isQuoteAttribution(line: string): boolean {
  const patterns = [
    /^On .+ wrote:$/i,
    /^-{3,}\s*Original Message\s*-{3,}$/i,
    /^_{3,}\s*$/,
    /^From:\s+.+\[mailto:/i,
  ];

  return patterns.some(pattern => pattern.test(line.trim()));
}

// ============================================================================
// Link Extraction
// ============================================================================

function extractLinksFromHtml(html: string): ExtractedLink[] {
  const links: ExtractedLink[] = [];

  // Extract from href attributes
  let match;
  while ((match = HREF_PATTERN.exec(html)) !== null) {
    const url = match[1];
    if (url && !url.startsWith('#') && !url.startsWith('mailto:')) {
      links.push(createExtractedLink(url));
    }
  }

  return links;
}

function extractLinksFromText(text: string): ExtractedLink[] {
  const links: ExtractedLink[] = [];

  let match;
  while ((match = URL_PATTERN.exec(text)) !== null) {
    if (match[0]) {
      links.push(createExtractedLink(match[0]));
    }
  }

  return links;
}

function createExtractedLink(url: string): ExtractedLink {
  const normalizedUrl = normalizeUrl(url);
  const domain = extractDomain(normalizedUrl);
  const { suspicious, reasons } = checkSuspiciousUrl(normalizedUrl, domain);

  return {
    url,
    domain,
    normalizedUrl,
    suspicious,
    suspicionReasons: reasons.length > 0 ? reasons : undefined,
  };
}

function normalizeUrl(url: string): string {
  try {
    const parsed = new URL(url);
    // Remove tracking parameters
    const trackingParams = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'fbclid', 'gclid'];
    trackingParams.forEach(param => parsed.searchParams.delete(param));
    return parsed.toString();
  } catch {
    return url;
  }
}

function extractDomain(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.hostname.toLowerCase();
  } catch {
    return 'unknown';
  }
}

function checkSuspiciousUrl(url: string, domain: string): { suspicious: boolean; reasons: string[] } {
  const reasons: string[] = [];

  for (const pattern of SUSPICIOUS_URL_PATTERNS) {
    if (pattern.test(url)) {
      reasons.push(`URL matches suspicious pattern: ${pattern.source}`);
    }
  }

  // Check for IP address instead of domain
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
    reasons.push('URL uses IP address instead of domain name');
  }

  // Check for excessive subdomains
  const subdomainCount = domain.split('.').length - 2;
  if (subdomainCount > 3) {
    reasons.push('URL has excessive subdomains');
  }

  // Check for lookalike domains
  const lookalikes = ['paypa1', 'g00gle', 'micros0ft', 'amaz0n', 'faceb00k'];
  if (lookalikes.some(l => domain.includes(l))) {
    reasons.push('Domain appears to be a lookalike/typosquat');
  }

  return { suspicious: reasons.length > 0, reasons };
}

function mergeLinks(links1: ExtractedLink[], links2: ExtractedLink[]): ExtractedLink[] {
  const seen = new Set<string>();
  const merged: ExtractedLink[] = [];

  for (const link of [...links1, ...links2]) {
    if (!seen.has(link.normalizedUrl)) {
      seen.add(link.normalizedUrl);
      merged.push(link);
    }
  }

  return merged;
}

// ============================================================================
// Header Parsing
// ============================================================================

export function parseEmailHeaders(payload: GmailMessagePayload): EmailHeaders {
  const headers = payload.payload.headers;

  const getHeader = (name: string): string | undefined => {
    const header = headers.find(h => h.name.toLowerCase() === name.toLowerCase());
    return header?.value;
  };

  const getHeaderList = (name: string): string[] => {
    const value = getHeader(name);
    if (!value) return [];
    return value.split(',').map(s => s.trim()).filter(Boolean);
  };

  const parseAuthResults = (value: string | undefined): AuthenticationResults | undefined => {
    if (!value) return undefined;

    const results: AuthenticationResults = {};

    if (/spf=pass/i.test(value)) results.spf = 'pass';
    else if (/spf=fail/i.test(value)) results.spf = 'fail';
    else if (/spf=softfail/i.test(value)) results.spf = 'softfail';
    else if (/spf=neutral/i.test(value)) results.spf = 'neutral';
    else if (/spf=none/i.test(value)) results.spf = 'none';

    if (/dkim=pass/i.test(value)) results.dkim = 'pass';
    else if (/dkim=fail/i.test(value)) results.dkim = 'fail';
    else if (/dkim=none/i.test(value)) results.dkim = 'none';

    if (/dmarc=pass/i.test(value)) results.dmarc = 'pass';
    else if (/dmarc=fail/i.test(value)) results.dmarc = 'fail';
    else if (/dmarc=none/i.test(value)) results.dmarc = 'none';

    return results;
  };

  return {
    messageId: payload.id,
    threadId: payload.threadId,
    from: getHeader('From') ?? '',
    to: getHeaderList('To'),
    cc: getHeaderList('Cc') || undefined,
    bcc: getHeaderList('Bcc') || undefined,
    subject: getHeader('Subject') ?? '(No Subject)',
    date: new Date(parseInt(payload.internalDate, 10)),
    replyTo: getHeader('Reply-To'),
    inReplyTo: getHeader('In-Reply-To'),
    references: getHeader('References')?.split(/\s+/).filter(Boolean),
    authResults: parseAuthResults(getHeader('Authentication-Results')),
  };
}

// ============================================================================
// Attachment Extraction
// ============================================================================

export function extractAttachmentMetadata(payload: GmailMessagePayload): AttachmentMetadata[] {
  const attachments: AttachmentMetadata[] = [];

  function processPartRecursive(part: GmailMessagePart): void {
    if (part.filename && part.filename.length > 0) {
      attachments.push({
        filename: part.filename,
        mimeType: part.mimeType,
        size: part.body.size,
        contentId: part.headers.find(h => h.name.toLowerCase() === 'content-id')?.value,
        isInline: part.headers.some(h =>
          h.name.toLowerCase() === 'content-disposition' &&
          h.value.toLowerCase().includes('inline')
        ),
      });
    }

    if (part.parts) {
      part.parts.forEach(processPartRecursive);
    }
  }

  if (payload.payload.parts) {
    payload.payload.parts.forEach(processPartRecursive);
  }

  return attachments;
}

// ============================================================================
// Body Content Extraction from Gmail Payload
// ============================================================================

export function extractBodyContent(payload: GmailMessagePayload): { html?: string; plain?: string } {
  let html: string | undefined;
  let plain: string | undefined;

  function processPartRecursive(part: GmailMessagePart | GmailMessagePayload['payload']): void {
    if (part.body.data) {
      const content = Buffer.from(part.body.data, 'base64').toString('utf-8');

      if (part.mimeType === 'text/html') {
        html = content;
      } else if (part.mimeType === 'text/plain') {
        plain = content;
      }
    }

    if ('parts' in part && part.parts) {
      for (const subpart of part.parts) {
        processPartRecursive(subpart);
      }
    }
  }

  processPartRecursive(payload.payload);

  return { html, plain };
}
