/**
 * Script Mixing Detection Module
 * Detects homoglyph attacks by identifying mixed-script words
 */

// ============================================================================
// Unicode Script Ranges
// ============================================================================

// Common scripts that may be used in homoglyph attacks
const SCRIPT_RANGES: Array<{
  name: string;
  ranges: Array<[number, number]>;
}> = [
  {
    name: 'Latin',
    ranges: [
      [0x0041, 0x005A], // A-Z
      [0x0061, 0x007A], // a-z
      [0x00C0, 0x00FF], // Latin Extended-A (partial)
      [0x0100, 0x017F], // Latin Extended-A
      [0x0180, 0x024F], // Latin Extended-B
      [0x1E00, 0x1EFF], // Latin Extended Additional
    ],
  },
  {
    name: 'Cyrillic',
    ranges: [
      [0x0400, 0x04FF], // Cyrillic
      [0x0500, 0x052F], // Cyrillic Supplement
      [0x2DE0, 0x2DFF], // Cyrillic Extended-A
      [0xA640, 0xA69F], // Cyrillic Extended-B
    ],
  },
  {
    name: 'Greek',
    ranges: [
      [0x0370, 0x03FF], // Greek and Coptic
      [0x1F00, 0x1FFF], // Greek Extended
    ],
  },
  {
    name: 'Armenian',
    ranges: [
      [0x0530, 0x058F], // Armenian
    ],
  },
  {
    name: 'Cherokee',
    ranges: [
      [0x13A0, 0x13FF], // Cherokee
      [0xAB70, 0xABBF], // Cherokee Supplement
    ],
  },
  {
    name: 'Hebrew',
    ranges: [
      [0x0590, 0x05FF], // Hebrew
    ],
  },
  {
    name: 'Arabic',
    ranges: [
      [0x0600, 0x06FF], // Arabic
      [0x0750, 0x077F], // Arabic Supplement
      [0x08A0, 0x08FF], // Arabic Extended-A
      [0xFB50, 0xFDFF], // Arabic Presentation Forms-A
      [0xFE70, 0xFEFF], // Arabic Presentation Forms-B
    ],
  },
  {
    name: 'CJK',
    ranges: [
      [0x4E00, 0x9FFF], // CJK Unified Ideographs
      [0x3400, 0x4DBF], // CJK Unified Ideographs Extension A
      [0x3040, 0x309F], // Hiragana
      [0x30A0, 0x30FF], // Katakana
      [0xAC00, 0xD7AF], // Hangul Syllables
      [0x1100, 0x11FF], // Hangul Jamo
    ],
  },
  {
    name: 'Mathematical',
    ranges: [
      [0x1D400, 0x1D7FF], // Mathematical Alphanumeric Symbols
    ],
  },
];

// Characters that are common across scripts (numbers, punctuation, etc.)
const COMMON_RANGES: Array<[number, number]> = [
  [0x0020, 0x0040], // Basic punctuation and digits
  [0x005B, 0x0060], // More punctuation
  [0x007B, 0x007F], // More punctuation
  [0x2000, 0x206F], // General Punctuation
];

// ============================================================================
// Types
// ============================================================================

export interface ScriptAnalysis {
  /** Set of unique scripts detected in the text */
  scripts: Set<string>;
  /** Words containing characters from multiple scripts */
  mixedScriptWords: MixedScriptWord[];
  /** Overall suspicion score (0-100) */
  suspicionScore: number;
  /** Whether the text contains suspicious script mixing */
  isSuspicious: boolean;
}

export interface MixedScriptWord {
  /** The original word */
  word: string;
  /** Scripts detected within this word */
  scripts: string[];
  /** Position in the original text */
  position: number;
  /** Confidence that this is an attack (0-1) */
  confidence: number;
}

// ============================================================================
// Script Detection Functions
// ============================================================================

/**
 * Determine which script a character belongs to
 */
function getCharacterScript(codePoint: number): string | null {
  // Check if it's a common character (should not contribute to mixing)
  for (const [start, end] of COMMON_RANGES) {
    if (codePoint >= start && codePoint <= end) {
      return null; // Common character, no specific script
    }
  }

  // Check each script
  for (const script of SCRIPT_RANGES) {
    for (const [start, end] of script.ranges) {
      if (codePoint >= start && codePoint <= end) {
        return script.name;
      }
    }
  }

  return 'Other';
}

/**
 * Analyze a single word for script mixing
 */
function analyzeWord(word: string, position: number): MixedScriptWord | null {
  const scripts = new Set<string>();
  const scriptPositions: Map<string, number[]> = new Map();

  for (let i = 0; i < word.length; i++) {
    const codePoint = word.codePointAt(i);
    if (codePoint === undefined) continue;

    const script = getCharacterScript(codePoint);
    if (script && script !== 'Other') {
      scripts.add(script);
      const positions = scriptPositions.get(script) ?? [];
      positions.push(i);
      scriptPositions.set(script, positions);
    }

    // Handle surrogate pairs
    if (codePoint > 0xFFFF) {
      i++;
    }
  }

  // Only flag if we have 2+ scripts (excluding common chars)
  if (scripts.size < 2) {
    return null;
  }

  // Calculate confidence based on how suspicious the mix is
  let confidence = 0.5; // Base confidence for any mixed script

  // High confidence: Latin + Cyrillic mix (most common homoglyph attack)
  if (scripts.has('Latin') && scripts.has('Cyrillic')) {
    confidence = 0.9;
  }

  // High confidence: Latin + Greek mix
  if (scripts.has('Latin') && scripts.has('Greek')) {
    confidence = 0.85;
  }

  // Medium-high: Latin + Mathematical
  if (scripts.has('Latin') && scripts.has('Mathematical')) {
    confidence = 0.75;
  }

  // Check for alternating scripts (very suspicious pattern)
  const scriptsArray = [...scripts];
  if (scriptsArray.length === 2) {
    const script1 = scriptsArray[0];
    const script2 = scriptsArray[1];
    if (script1 && script2) {
      const pos1 = scriptPositions.get(script1) ?? [];
      const pos2 = scriptPositions.get(script2) ?? [];
      const allPositions = [...pos1.map(p => ({ p, s: 0 })), ...pos2.map(p => ({ p, s: 1 }))];
      allPositions.sort((a, b) => a.p - b.p);

      // Count alternations
      let alternations = 0;
      for (let i = 1; i < allPositions.length; i++) {
        if (allPositions[i]?.s !== allPositions[i - 1]?.s) {
          alternations++;
        }
      }

      // Many alternations in a short word = very suspicious
      if (alternations >= 3 && word.length <= 10) {
        confidence = Math.min(1, confidence + 0.1);
      }
    }
  }

  return {
    word,
    scripts: [...scripts],
    position,
    confidence,
  };
}

// ============================================================================
// Main Analysis Function
// ============================================================================

/**
 * Analyze text for suspicious script mixing (homoglyph attacks)
 */
export function analyzeScriptMixing(text: string): ScriptAnalysis {
  const allScripts = new Set<string>();
  const mixedScriptWords: MixedScriptWord[] = [];

  // Split into words (including Unicode word boundaries)
  const wordPattern = /[\p{L}\p{M}\p{N}]+/gu;
  let match: RegExpExecArray | null;

  while ((match = wordPattern.exec(text)) !== null) {
    const word = match[0];
    const position = match.index;

    // Skip very short words (single chars can legitimately mix)
    if (word.length < 2) {
      continue;
    }

    // Collect scripts from this word
    for (let i = 0; i < word.length; i++) {
      const codePoint = word.codePointAt(i);
      if (codePoint !== undefined) {
        const script = getCharacterScript(codePoint);
        if (script && script !== 'Other') {
          allScripts.add(script);
        }
        // Handle surrogate pairs
        if (codePoint > 0xFFFF) {
          i++;
        }
      }
    }

    // Check if this word has mixed scripts
    const analysis = analyzeWord(word, position);
    if (analysis) {
      mixedScriptWords.push(analysis);
    }
  }

  // Calculate overall suspicion score
  let suspicionScore = 0;

  if (mixedScriptWords.length > 0) {
    // Base score from number of mixed words
    suspicionScore = Math.min(50, mixedScriptWords.length * 15);

    // Add weighted confidence from each mixed word
    const avgConfidence = mixedScriptWords.reduce((sum, w) => sum + w.confidence, 0) / mixedScriptWords.length;
    suspicionScore += Math.round(avgConfidence * 40);

    // Check for known attack patterns (words that look like common targets)
    const attackPatterns = [
      /p[aа]yp[aа]l/i, // paypal with mixed scripts
      /g[oо][oо]gl[eе]/i, // google with mixed scripts
      /m[iі]cr[oо]s[oо]ft/i, // microsoft with mixed scripts
      /[aа]m[aа]z[oо]n/i, // amazon with mixed scripts
      /[aа]ppl[eе]/i, // apple with mixed scripts
      /p[aа]ssw[oо]rd/i, // password with mixed scripts
      /l[oо]g[iі]n/i, // login with mixed scripts
      /[aа]cc[oо]unt/i, // account with mixed scripts
      /v[eе]r[iі]fy/i, // verify with mixed scripts
      /s[eе]cur[eе]/i, // secure with mixed scripts
    ];

    for (const word of mixedScriptWords) {
      for (const pattern of attackPatterns) {
        if (pattern.test(word.word)) {
          suspicionScore = Math.min(100, suspicionScore + 20);
          word.confidence = Math.min(1, word.confidence + 0.2);
        }
      }
    }
  }

  // Cap the score
  suspicionScore = Math.min(100, suspicionScore);

  return {
    scripts: allScripts,
    mixedScriptWords,
    suspicionScore,
    isSuspicious: suspicionScore >= 25 || mixedScriptWords.length > 0,
  };
}

/**
 * Get a summary of script mixing for logging/reporting
 */
export function getScriptMixingSummary(analysis: ScriptAnalysis): string {
  if (!analysis.isSuspicious) {
    return 'No suspicious script mixing detected';
  }

  const parts: string[] = [];

  if (analysis.mixedScriptWords.length > 0) {
    const highConfidence = analysis.mixedScriptWords.filter(w => w.confidence >= 0.8);
    if (highConfidence.length > 0) {
      parts.push(`${highConfidence.length} highly suspicious mixed-script word(s): ${highConfidence.map(w => `"${w.word}"`).join(', ')}`);
    }

    const medConfidence = analysis.mixedScriptWords.filter(w => w.confidence >= 0.5 && w.confidence < 0.8);
    if (medConfidence.length > 0) {
      parts.push(`${medConfidence.length} moderately suspicious word(s)`);
    }
  }

  if (analysis.scripts.size > 2) {
    parts.push(`${analysis.scripts.size} different scripts detected: ${[...analysis.scripts].join(', ')}`);
  }

  return parts.join('; ') || 'Minor script mixing detected';
}
