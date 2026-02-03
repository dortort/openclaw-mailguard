/**
 * Language Detection Module
 * Lightweight trigram-based language detection for top 15 languages
 */

// ============================================================================
// Language Trigram Profiles
// ============================================================================

// Top trigrams for each supported language (most frequent)
// These are derived from corpus analysis of each language
const TRIGRAM_PROFILES: Record<string, string[]> = {
  en: [
    'the', 'and', 'ing', 'ion', 'tio', 'ent', 'ati', 'for', 'her', 'ter',
    'hat', 'tha', 'ere', 'ate', 'his', 'con', 'res', 'ver', 'all', 'ons',
    'nce', 'men', 'ith', 'ted', 'ers', 'pro', 'thi', 'wit', 'are', 'ess',
  ],
  es: [
    'de ', 'que', 'ión', 'ent', 'ció', ' de', 'la ', ' la', 'el ', 'en ',
    'los', ' en', 'aci', 'con', 'nte', ' lo', ' co', 'del', 'es ', 'as ',
    'com', 'est', 'ado', 'par', 'men', 'ien', 'sta', 'tra', 'ara', 'ero',
  ],
  fr: [
    ' de', 'de ', 'ent', 'le ', 'es ', ' le', 'ion', 'tio', 'la ', ' la',
    'on ', 'que', ' et', ' qu', 'et ', 'ati', 'les', 'ons', 'des', ' pa',
    're ', 'eur', ' co', 'men', 'par', 'eme', 'con', 'ns ', ' un', 'ait',
  ],
  de: [
    'en ', 'er ', 'der', 'ein', 'ich', 'che', 'die', 'ung', 'und', ' de',
    'sch', 'den', 'ine', 'and', 'gen', 'nde', ' un', 'hen', 'eit', 'ier',
    'te ', ' di', 'ren', 'ter', 'lic', 'ach', 'cht', 'es ', 'bei', 'auf',
  ],
  pt: [
    'de ', ' de', 'ent', 'ção', 'ão ', ' qu', 'que', 'os ', 'ado', ' co',
    'com', 'as ', 'açã', 'sta', 'men', 'est', 'par', 'con', ' pa', ' da',
    'ara', ' se', 'pro', 'res', ' es', 'ter', 'nto', 'ica', 'nte', 'ame',
  ],
  it: [
    ' di', 'di ', 'che', 'ion', 'ent', 'la ', ' la', 'one', 'zio', 'ell',
    ' de', 'del', 'azi', 'con', 'lla', 'per', 'to ', 'nto', 'ato', ' pe',
    'nte', 'ta ', 'te ', 'era', ' in', ' co', 'men', 'le ', 'ali', 'ita',
  ],
  nl: [
    'en ', 'de ', 'an ', 'van', ' de', 'een', ' va', 'het', 'oor', ' he',
    'ing', ' ee', 'nde', 'ver', 'aar', ' in', 'er ', ' vo', 'aan', 'erd',
    'der', 'ste', ' me', 'gen', 'rin', 'oor', ' on', 'ter', 'den', 'ond',
  ],
  pl: [
    'nie', ' ni', ' po', 'owi', 'ie ', 'ani', 'icz', 'prz', 'ego', 'rze',
    'ych', 'nia', ' pr', 'sta', 'cze', 'czy', ' na', 'ych', 'eni', 'wie',
    'ski', 'cie', ' je', ' do', 'nej', 'kie', 'owa', 'rzy', ' za', 'jed',
  ],
  ru: [
    'ени', 'ост', 'ние', ' пр', 'про', 'ать', 'ого', 'ств', 'тел', 'ова',
    'ани', 'ель', 'ной', 'при', ' по', ' на', 'ить', ' ко', 'ком', 'ого',
    'ере', ' не', 'ест', 'ско', 'ных', 'ия ', 'ции', ' об', 'ста', 'нос',
  ],
  zh: [
    '的是', '是一', '一个', '的人', '在这', '这个', '个人', '不是', '有的', '我们',
    '他们', '什么', '没有', '可以', '就是', '这样', '那个', '知道', '现在', '因为',
    '所以', '如果', '自己', '已经', '时候', '出来', '这里', '那里', '怎么', '只是',
  ],
  ja: [
    'です', 'ます', 'して', 'ない', 'った', 'ある', 'tion', 'ている', 'れた', 'ける',
    'から', 'られ', 'ment', 'った', 'てい', 'という', 'する', 'ション', 'ング', 'ィン',
    'ート', 'トの', 'まし', 'のは', 'こと', 'これ', 'その', 'たち', 'いる', 'なっ',
  ],
  ko: [
    '하는', '니다', '입니', '습니', '에서', '으로', '고있', '이다', '하고', '하여',
    '에는', '것이', '들을', '적인', '되어', '되는', '대한', '에대', '위해', '것을',
    '을통', '한다', '기위', '있는', '있다', '이라', '에의', '로서', '것은', '과의',
  ],
  ar: [
    'الم', 'من', 'في', 'على', 'إلى', 'هذا', 'وال', 'ان', 'التي', 'لم',
    'عن', 'مع', 'أن', 'كان', 'ذلك', 'هذه', 'كل', 'لا', 'عند', 'قد',
    'بين', 'حيث', 'أو', 'له', 'ثم', 'بعد', 'حتى', 'ما', 'كما', 'لها',
  ],
  tr: [
    'lar', 'ler', 'bir', ' bi', 'ın ', 'eri', 'ını', 'nın', 'esi', 'ası',
    'ara', 'ile', 'yor', 'inde', 'dir', 'dır', 'ını', 'nin', 'dan', 'den',
    'arak', 'inde', 'lik', 'lık', 'ünü', 'anı', 'aya', 'için', 'oldu', 'olan',
  ],
  vi: [
    'của', 'các', 'cho', 'trong', 'với', 'được', 'người', 'này', 'về', 'có',
    'một', 'những', 'theo', 'tại', 'khi', 'đã', 'hay', 'cũng', 'năm', 'từ',
    'đến', 'như', 'nhưng', 'trên', 'họ', 'là', 'ông', 'bà', 'không', 'ra',
  ],
};

// Script-based language hints (for faster initial detection)
const SCRIPT_HINTS: Record<string, string[]> = {
  cyrillic: ['ru'],
  arabic: ['ar'],
  cjk: ['zh', 'ja'],
  hangul: ['ko'],
  thai: ['th'],
  hebrew: ['he'],
};

// ============================================================================
// Types
// ============================================================================

export interface LanguageDetectionResult {
  /** Primary detected language (ISO 639-1 code) */
  primary: string;
  /** Detection confidence (0-1) */
  confidence: number;
  /** Secondary language if detected (for mixed-language text) */
  secondary?: string;
  /** Confidence for secondary language */
  secondaryConfidence?: number;
  /** Scripts detected in the text */
  scripts: string[];
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Extract trigrams from text
 */
function extractTrigrams(text: string): Map<string, number> {
  const trigrams = new Map<string, number>();
  const normalizedText = text.toLowerCase().replace(/[^\p{L}\p{M}\s]/gu, '');

  for (let i = 0; i < normalizedText.length - 2; i++) {
    const trigram = normalizedText.substring(i, i + 3);
    trigrams.set(trigram, (trigrams.get(trigram) ?? 0) + 1);
  }

  return trigrams;
}

/**
 * Calculate similarity score between text trigrams and language profile
 */
function calculateSimilarity(textTrigrams: Map<string, number>, profile: string[]): number {
  let matches = 0;
  let totalWeight = 0;

  // Weight earlier (more common) trigrams higher
  for (let i = 0; i < profile.length; i++) {
    const trigram = profile[i];
    if (!trigram) continue;

    const weight = profile.length - i; // Higher weight for more common trigrams
    totalWeight += weight;

    if (textTrigrams.has(trigram)) {
      matches += weight * Math.min(1, (textTrigrams.get(trigram) ?? 0) / 3);
    }
  }

  return totalWeight > 0 ? matches / totalWeight : 0;
}

/**
 * Detect script type from character code points
 */
function detectScripts(text: string): string[] {
  const scripts = new Set<string>();

  for (let i = 0; i < text.length; i++) {
    const codePoint = text.codePointAt(i);
    if (codePoint === undefined) continue;

    // Latin
    if (
      (codePoint >= 0x0041 && codePoint <= 0x007A) ||
      (codePoint >= 0x00C0 && codePoint <= 0x024F)
    ) {
      scripts.add('latin');
    }

    // Cyrillic
    if (codePoint >= 0x0400 && codePoint <= 0x04FF) {
      scripts.add('cyrillic');
    }

    // Arabic
    if (
      (codePoint >= 0x0600 && codePoint <= 0x06FF) ||
      (codePoint >= 0x0750 && codePoint <= 0x077F)
    ) {
      scripts.add('arabic');
    }

    // CJK (Chinese, Japanese Kanji)
    if (codePoint >= 0x4E00 && codePoint <= 0x9FFF) {
      scripts.add('cjk');
    }

    // Hiragana/Katakana (Japanese)
    if (
      (codePoint >= 0x3040 && codePoint <= 0x309F) ||
      (codePoint >= 0x30A0 && codePoint <= 0x30FF)
    ) {
      scripts.add('japanese');
    }

    // Hangul (Korean)
    if (
      (codePoint >= 0xAC00 && codePoint <= 0xD7AF) ||
      (codePoint >= 0x1100 && codePoint <= 0x11FF)
    ) {
      scripts.add('hangul');
    }

    // Hebrew
    if (codePoint >= 0x0590 && codePoint <= 0x05FF) {
      scripts.add('hebrew');
    }

    // Greek
    if (codePoint >= 0x0370 && codePoint <= 0x03FF) {
      scripts.add('greek');
    }

    // Handle surrogate pairs
    if (codePoint > 0xFFFF) {
      i++;
    }
  }

  return [...scripts];
}

// ============================================================================
// Main Detection Function
// ============================================================================

/**
 * Detect the language of the given text
 */
export function detectLanguage(text: string): LanguageDetectionResult {
  // Skip very short text
  if (text.length < 20) {
    return {
      primary: 'unknown',
      confidence: 0,
      scripts: detectScripts(text),
    };
  }

  const scripts = detectScripts(text);
  const trigrams = extractTrigrams(text);

  // Early exit for non-Latin scripts with strong hints
  for (const [script, languages] of Object.entries(SCRIPT_HINTS)) {
    if (scripts.includes(script) && scripts.length === 1) {
      // Strong hint - single script detected
      const lang = languages[0];
      const profile = lang ? TRIGRAM_PROFILES[lang] : undefined;
      if (lang && profile) {
        const similarity = calculateSimilarity(trigrams, profile);
        return {
          primary: lang,
          confidence: Math.max(0.7, similarity),
          scripts,
        };
      }
    }
  }

  // Special handling for Japanese (mix of CJK + kana)
  if (scripts.includes('japanese') || (scripts.includes('cjk') && scripts.includes('japanese'))) {
    const similarity = calculateSimilarity(trigrams, TRIGRAM_PROFILES.ja ?? []);
    if (similarity > 0.1) {
      return {
        primary: 'ja',
        confidence: Math.max(0.6, similarity),
        scripts,
      };
    }
  }

  // Special handling for Korean
  if (scripts.includes('hangul')) {
    const similarity = calculateSimilarity(trigrams, TRIGRAM_PROFILES.ko ?? []);
    return {
      primary: 'ko',
      confidence: Math.max(0.7, similarity),
      scripts,
    };
  }

  // Special handling for Chinese (CJK without Japanese kana)
  if (scripts.includes('cjk') && !scripts.includes('japanese')) {
    return {
      primary: 'zh',
      confidence: 0.8,
      scripts,
    };
  }

  // For Latin-based languages, use trigram matching
  const scores: Array<{ lang: string; score: number }> = [];

  for (const [lang, profile] of Object.entries(TRIGRAM_PROFILES)) {
    // Skip non-Latin languages for Latin text
    if (!['zh', 'ja', 'ko', 'ar', 'ru'].includes(lang) || scripts.includes('latin')) {
      const score = calculateSimilarity(trigrams, profile);
      scores.push({ lang, score });
    }
  }

  // Sort by score descending
  scores.sort((a, b) => b.score - a.score);

  const best = scores[0];
  const second = scores[1];

  if (!best || best.score < 0.05) {
    return {
      primary: 'unknown',
      confidence: 0,
      scripts,
    };
  }

  // Check if we have a strong secondary language (mixed-language text)
  const result: LanguageDetectionResult = {
    primary: best.lang,
    confidence: Math.min(1, best.score * 2), // Scale up to 0-1 range
    scripts,
  };

  if (second && second.score > 0.1 && second.score > best.score * 0.5) {
    result.secondary = second.lang;
    result.secondaryConfidence = Math.min(1, second.score * 2);
  }

  return result;
}

/**
 * Quick check if text is likely non-English
 * More efficient than full detection for pre-filtering
 */
export function isLikelyNonEnglish(text: string): boolean {
  const scripts = detectScripts(text);

  // Non-Latin scripts are definitely not English
  if (scripts.some(s => ['cyrillic', 'arabic', 'cjk', 'japanese', 'hangul', 'hebrew'].includes(s))) {
    return true;
  }

  // Check for common non-English Latin characters
  const nonEnglishChars = /[àáâãäåæçèéêëìíîïñòóôõöùúûüýÿœßžšđ]/i;
  if (nonEnglishChars.test(text)) {
    // Could be non-English, do quick trigram check
    const trigrams = extractTrigrams(text.substring(0, 500)); // Sample first 500 chars
    const enScore = calculateSimilarity(trigrams, TRIGRAM_PROFILES.en ?? []);
    return enScore < 0.15;
  }

  return false;
}
