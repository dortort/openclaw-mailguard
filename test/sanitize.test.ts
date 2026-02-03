/**
 * Sanitization Module Tests
 */

import { describe, it, expect } from 'vitest';
import {
  sanitizeEmailContent,
  parseEmailHeaders,
  extractAttachmentMetadata,
  extractBodyContent,
} from '../src/sanitize/html_to_text.js';
import type { GmailMessagePayload } from '../src/types.js';

describe('sanitizeEmailContent', () => {
  describe('basic sanitization', () => {
    it('should convert HTML to plain text', () => {
      const html = '<html><body><p>Hello</p><p>World</p></body></html>';
      const result = sanitizeEmailContent(html, undefined, 50000);

      expect(result.bodyText).toContain('Hello');
      expect(result.bodyText).toContain('World');
      expect(result.bodyText).not.toContain('<p>');
      expect(result.bodyText).not.toContain('</p>');
    });

    it('should preserve plain text when no HTML', () => {
      const plain = 'Hello World\n\nThis is a test.';
      const result = sanitizeEmailContent(undefined, plain, 50000);

      expect(result.bodyText).toBe(plain);
    });

    it('should prefer HTML when both are provided', () => {
      const html = '<html><body><p>HTML Content</p></body></html>';
      const plain = 'Plain Content';
      const result = sanitizeEmailContent(html, plain, 50000);

      expect(result.bodyText).toContain('HTML Content');
    });
  });

  describe('hidden content removal', () => {
    it('should remove HTML comments', () => {
      const html = '<html><body>Visible<!-- Hidden comment -->Text</body></html>';
      const result = sanitizeEmailContent(html, undefined, 50000);

      expect(result.bodyText).not.toContain('Hidden comment');
      expect(result.bodyText).toContain('Visible');
      expect(result.bodyText).toContain('Text');
      expect(result.hiddenContentRemoved).toBe(true);
    });

    it('should remove style tags', () => {
      const html = '<html><head><style>.hidden { display: none; }</style></head><body>Content</body></html>';
      const result = sanitizeEmailContent(html, undefined, 50000);

      expect(result.bodyText).not.toContain('.hidden');
      expect(result.bodyText).not.toContain('display: none');
      expect(result.hiddenContentRemoved).toBe(true);
    });

    it('should remove script tags', () => {
      const html = '<html><body><script>alert("malicious")</script>Safe Content</body></html>';
      const result = sanitizeEmailContent(html, undefined, 50000);

      expect(result.bodyText).not.toContain('alert');
      expect(result.bodyText).not.toContain('malicious');
      expect(result.bodyText).toContain('Safe Content');
    });

    it('should remove zero-width characters', () => {
      const plain = 'Normal\u200B\u200Btext\u200Dwith\uFEFFhidden\u2060chars';
      const result = sanitizeEmailContent(undefined, plain, 50000);

      expect(result.bodyText).toBe('Normaltextwithhiddenchars');
      expect(result.hiddenContentRemoved).toBe(true);
    });

    it('should remove unicode directional overrides', () => {
      const plain = 'Text with\u202Ahidden\u202Cdirection\u202Eoverrides';
      const result = sanitizeEmailContent(undefined, plain, 50000);

      expect(result.bodyText).not.toContain('\u202A');
      expect(result.bodyText).not.toContain('\u202E');
      expect(result.hiddenContentRemoved).toBe(true);
    });
  });

  describe('length enforcement', () => {
    it('should truncate content exceeding max length', () => {
      const longText = 'A'.repeat(60000);
      const result = sanitizeEmailContent(undefined, longText, 50000);

      expect(result.sanitizedLength).toBeLessThanOrEqual(50100); // Allow for truncation message
      expect(result.bodyText).toContain('[Content truncated for safety]');
    });

    it('should not truncate content within limit', () => {
      const shortText = 'Short text content';
      const result = sanitizeEmailContent(undefined, shortText, 50000);

      expect(result.bodyText).toBe(shortText);
      expect(result.bodyText).not.toContain('truncated');
    });
  });

  describe('link extraction', () => {
    it('should extract links from HTML href attributes', () => {
      const html = '<a href="https://example.com/page">Link</a><a href="https://test.com">Test</a>';
      const result = sanitizeEmailContent(html, undefined, 50000);

      expect(result.links).toHaveLength(2);
      expect(result.links[0]?.domain).toBe('example.com');
      expect(result.links[1]?.domain).toBe('test.com');
    });

    it('should extract links from plain text', () => {
      const plain = 'Visit https://example.com or https://test.com/path?query=1';
      const result = sanitizeEmailContent(undefined, plain, 50000);

      expect(result.links.length).toBeGreaterThanOrEqual(2);
    });

    it('should flag suspicious shortened URLs', () => {
      const html = '<a href="https://bit.ly/abc123">Click here</a>';
      const result = sanitizeEmailContent(html, undefined, 50000);

      expect(result.links[0]?.suspicious).toBe(true);
      expect(result.links[0]?.suspicionReasons).toBeDefined();
    });

    it('should flag URLs with IP addresses', () => {
      const plain = 'Visit http://192.168.1.1/login';
      const result = sanitizeEmailContent(undefined, plain, 50000);

      const ipLink = result.links.find(l => l.domain.match(/^\d+\.\d+\.\d+\.\d+$/));
      expect(ipLink?.suspicious).toBe(true);
    });

    it('should deduplicate links', () => {
      const html = '<a href="https://example.com">Link 1</a><a href="https://example.com">Link 2</a>';
      const result = sanitizeEmailContent(html, undefined, 50000);

      const exampleLinks = result.links.filter(l => l.domain === 'example.com');
      expect(exampleLinks).toHaveLength(1);
    });
  });

  describe('quote extraction', () => {
    it('should extract quoted blocks with > prefix', () => {
      const plain = 'My reply\n\n> Previous message\n> continues here\n\nMore reply';
      const result = sanitizeEmailContent(undefined, plain, 50000);

      expect(result.quotedBlocks.length).toBeGreaterThan(0);
      expect(result.quotedBlocks[0]?.content).toContain('Previous message');
    });

    it('should separate quoted content from main content', () => {
      const plain = 'Main content\n\n> Quoted content\n\nMore main content';
      const result = sanitizeEmailContent(undefined, plain, 50000);

      expect(result.bodyText).toContain('Main content');
      expect(result.bodyText).toContain('More main content');
    });
  });

  describe('HTML entity decoding', () => {
    it('should decode common HTML entities', () => {
      const html = '<p>&amp; &lt; &gt; &quot; &nbsp;</p>';
      const result = sanitizeEmailContent(html, undefined, 50000);

      expect(result.bodyText).toContain('&');
      expect(result.bodyText).toContain('<');
      expect(result.bodyText).toContain('>');
      expect(result.bodyText).toContain('"');
    });

    it('should decode numeric HTML entities', () => {
      const html = '<p>&#65;&#66;&#67;</p>'; // ABC
      const result = sanitizeEmailContent(html, undefined, 50000);

      expect(result.bodyText).toContain('ABC');
    });

    it('should decode hex HTML entities', () => {
      const html = '<p>&#x41;&#x42;&#x43;</p>'; // ABC
      const result = sanitizeEmailContent(html, undefined, 50000);

      expect(result.bodyText).toContain('ABC');
    });
  });
});

describe('parseEmailHeaders', () => {
  it('should parse standard email headers', () => {
    const payload: GmailMessagePayload = {
      id: 'msg123',
      threadId: 'thread123',
      labelIds: ['INBOX'],
      snippet: 'Test',
      payload: {
        mimeType: 'text/plain',
        filename: '',
        headers: [
          { name: 'From', value: 'sender@example.com' },
          { name: 'To', value: 'recipient@example.com' },
          { name: 'Subject', value: 'Test Subject' },
          { name: 'Date', value: 'Mon, 15 Jan 2024 10:00:00 +0000' },
        ],
        body: { size: 0 },
      },
      sizeEstimate: 100,
      historyId: '123',
      internalDate: '1705312800000',
    };

    const headers = parseEmailHeaders(payload);

    expect(headers.messageId).toBe('msg123');
    expect(headers.threadId).toBe('thread123');
    expect(headers.from).toBe('sender@example.com');
    expect(headers.to).toContain('recipient@example.com');
    expect(headers.subject).toBe('Test Subject');
  });

  it('should parse authentication results', () => {
    const payload: GmailMessagePayload = {
      id: 'msg123',
      threadId: 'thread123',
      labelIds: [],
      snippet: '',
      payload: {
        mimeType: 'text/plain',
        filename: '',
        headers: [
          { name: 'From', value: 'sender@example.com' },
          { name: 'To', value: 'recipient@example.com' },
          { name: 'Subject', value: 'Test' },
          { name: 'Authentication-Results', value: 'mx.example.com; spf=pass; dkim=pass; dmarc=pass' },
        ],
        body: { size: 0 },
      },
      sizeEstimate: 100,
      historyId: '123',
      internalDate: '1705312800000',
    };

    const headers = parseEmailHeaders(payload);

    expect(headers.authResults?.spf).toBe('pass');
    expect(headers.authResults?.dkim).toBe('pass');
    expect(headers.authResults?.dmarc).toBe('pass');
  });

  it('should handle failed authentication', () => {
    const payload: GmailMessagePayload = {
      id: 'msg123',
      threadId: 'thread123',
      labelIds: [],
      snippet: '',
      payload: {
        mimeType: 'text/plain',
        filename: '',
        headers: [
          { name: 'From', value: 'sender@suspicious.com' },
          { name: 'To', value: 'victim@example.com' },
          { name: 'Subject', value: 'Suspicious' },
          { name: 'Authentication-Results', value: 'mx.example.com; spf=fail; dkim=fail; dmarc=fail' },
        ],
        body: { size: 0 },
      },
      sizeEstimate: 100,
      historyId: '123',
      internalDate: '1705312800000',
    };

    const headers = parseEmailHeaders(payload);

    expect(headers.authResults?.spf).toBe('fail');
    expect(headers.authResults?.dkim).toBe('fail');
    expect(headers.authResults?.dmarc).toBe('fail');
  });

  it('should handle multiple recipients', () => {
    const payload: GmailMessagePayload = {
      id: 'msg123',
      threadId: 'thread123',
      labelIds: [],
      snippet: '',
      payload: {
        mimeType: 'text/plain',
        filename: '',
        headers: [
          { name: 'From', value: 'sender@example.com' },
          { name: 'To', value: 'user1@example.com, user2@example.com' },
          { name: 'Cc', value: 'cc1@example.com, cc2@example.com' },
          { name: 'Subject', value: 'Test' },
        ],
        body: { size: 0 },
      },
      sizeEstimate: 100,
      historyId: '123',
      internalDate: '1705312800000',
    };

    const headers = parseEmailHeaders(payload);

    expect(headers.to).toHaveLength(2);
    expect(headers.cc).toHaveLength(2);
  });
});

describe('extractAttachmentMetadata', () => {
  it('should extract attachment information', () => {
    const payload: GmailMessagePayload = {
      id: 'msg123',
      threadId: 'thread123',
      labelIds: [],
      snippet: '',
      payload: {
        mimeType: 'multipart/mixed',
        filename: '',
        headers: [],
        body: { size: 0 },
        parts: [
          {
            partId: '0',
            mimeType: 'text/plain',
            filename: '',
            headers: [],
            body: { size: 100 },
          },
          {
            partId: '1',
            mimeType: 'application/pdf',
            filename: 'document.pdf',
            headers: [
              { name: 'Content-Disposition', value: 'attachment; filename="document.pdf"' },
            ],
            body: { size: 50000, attachmentId: 'att123' },
          },
        ],
      },
      sizeEstimate: 60000,
      historyId: '123',
      internalDate: '1705312800000',
    };

    const attachments = extractAttachmentMetadata(payload);

    expect(attachments).toHaveLength(1);
    expect(attachments[0]?.filename).toBe('document.pdf');
    expect(attachments[0]?.mimeType).toBe('application/pdf');
    expect(attachments[0]?.size).toBe(50000);
    expect(attachments[0]?.isInline).toBe(false);
  });

  it('should identify inline attachments', () => {
    const payload: GmailMessagePayload = {
      id: 'msg123',
      threadId: 'thread123',
      labelIds: [],
      snippet: '',
      payload: {
        mimeType: 'multipart/mixed',
        filename: '',
        headers: [],
        body: { size: 0 },
        parts: [
          {
            partId: '1',
            mimeType: 'image/png',
            filename: 'image.png',
            headers: [
              { name: 'Content-Disposition', value: 'inline; filename="image.png"' },
              { name: 'Content-Id', value: '<image001>' },
            ],
            body: { size: 10000 },
          },
        ],
      },
      sizeEstimate: 15000,
      historyId: '123',
      internalDate: '1705312800000',
    };

    const attachments = extractAttachmentMetadata(payload);

    expect(attachments[0]?.isInline).toBe(true);
    expect(attachments[0]?.contentId).toBe('<image001>');
  });
});

describe('extractBodyContent', () => {
  it('should extract plain text body', () => {
    const payload: GmailMessagePayload = {
      id: 'msg123',
      threadId: 'thread123',
      labelIds: [],
      snippet: '',
      payload: {
        mimeType: 'text/plain',
        filename: '',
        headers: [],
        body: {
          size: 20,
          data: Buffer.from('Hello World').toString('base64'),
        },
      },
      sizeEstimate: 100,
      historyId: '123',
      internalDate: '1705312800000',
    };

    const { html, plain } = extractBodyContent(payload);

    expect(plain).toBe('Hello World');
    expect(html).toBeUndefined();
  });

  it('should extract both HTML and plain text from multipart', () => {
    const payload: GmailMessagePayload = {
      id: 'msg123',
      threadId: 'thread123',
      labelIds: [],
      snippet: '',
      payload: {
        mimeType: 'multipart/alternative',
        filename: '',
        headers: [],
        body: { size: 0 },
        parts: [
          {
            partId: '0',
            mimeType: 'text/plain',
            filename: '',
            headers: [],
            body: {
              size: 20,
              data: Buffer.from('Plain text version').toString('base64'),
            },
          },
          {
            partId: '1',
            mimeType: 'text/html',
            filename: '',
            headers: [],
            body: {
              size: 40,
              data: Buffer.from('<html><body>HTML version</body></html>').toString('base64'),
            },
          },
        ],
      },
      sizeEstimate: 200,
      historyId: '123',
      internalDate: '1705312800000',
    };

    const { html, plain } = extractBodyContent(payload);

    expect(plain).toBe('Plain text version');
    expect(html).toBe('<html><body>HTML version</body></html>');
  });
});
