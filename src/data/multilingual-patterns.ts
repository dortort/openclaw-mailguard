/**
 * Multilingual Prompt Injection Patterns
 * Covers top 10 languages by email volume (~85% of non-English attacks)
 */

import type { PatternDefinition } from '../risk/heuristics.js';

// ============================================================================
// Spanish (es) Patterns
// ============================================================================

export const SPANISH_PATTERNS: PatternDefinition[] = [
  // Instruction override - critical
  {
    pattern: /ignora\s+(todas?\s+)?(las?\s+)?(instrucciones?|reglas?|directivas?)\s+(anteriores?|previas?|pasadas?)/i,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Spanish: Attempt to ignore previous instructions',
    weight: 30,
    language: 'es',
  },
  {
    pattern: /olvida\s+(todo\s+)?(lo\s+)?(que\s+)?(te\s+)?(dije|he\s+dicho|mencion[eé])/i,
    type: 'instruction_override',
    severity: 'high',
    description: 'Spanish: Attempt to reset context',
    weight: 25,
    language: 'es',
  },
  {
    pattern: /nuevas?\s+(instrucciones?|reglas?|modo|rol):/i,
    type: 'instruction_override',
    severity: 'high',
    description: 'Spanish: Attempt to set new instructions',
    weight: 25,
    language: 'es',
  },
  // Role impersonation
  {
    pattern: /(ahora\s+)?eres\s+(un|una|mi)\s+/i,
    type: 'role_impersonation',
    severity: 'high',
    description: 'Spanish: Attempt to change AI role',
    weight: 25,
    language: 'es',
  },
  {
    pattern: /finge\s+(que\s+)?(eres|ser)/i,
    type: 'role_impersonation',
    severity: 'medium',
    description: 'Spanish: Role pretend instruction',
    weight: 15,
    language: 'es',
  },
  // System markers
  {
    pattern: /\[SISTEMA\]|\[ADMIN(ISTRADOR)?\]|\[DESARROLLADOR\]|\[INTERNO\]/i,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Spanish: Fake authority marker',
    weight: 35,
    language: 'es',
  },
];

// ============================================================================
// French (fr) Patterns
// ============================================================================

export const FRENCH_PATTERNS: PatternDefinition[] = [
  // Instruction override - critical
  {
    pattern: /ignore[rz]?\s+(toutes?\s+)?(les?\s+)?(instructions?|r[eè]gles?|directives?)\s+(pr[eé]c[eé]dentes?|ant[eé]rieures?)/i,
    type: 'instruction_override',
    severity: 'critical',
    description: 'French: Attempt to ignore previous instructions',
    weight: 30,
    language: 'fr',
  },
  {
    pattern: /oublie[rz]?\s+(tout\s+)?(ce\s+)?(que\s+)?(je\s+)?(t'ai\s+dit|ai\s+dit)/i,
    type: 'instruction_override',
    severity: 'high',
    description: 'French: Attempt to reset context',
    weight: 25,
    language: 'fr',
  },
  {
    pattern: /nouvelles?\s+(instructions?|r[eè]gles?|mode|r[oô]le):/i,
    type: 'instruction_override',
    severity: 'high',
    description: 'French: Attempt to set new instructions',
    weight: 25,
    language: 'fr',
  },
  // Role impersonation
  {
    pattern: /(maintenant\s+)?tu\s+es\s+(un|une|mon|ma)/i,
    type: 'role_impersonation',
    severity: 'high',
    description: 'French: Attempt to change AI role',
    weight: 25,
    language: 'fr',
  },
  {
    pattern: /fais\s+semblant\s+(d'[eê]tre|que\s+tu\s+es)/i,
    type: 'role_impersonation',
    severity: 'medium',
    description: 'French: Role pretend instruction',
    weight: 15,
    language: 'fr',
  },
  // System markers
  {
    pattern: /\[SYST[EÈ]ME\]|\[ADMIN(ISTRATEUR)?\]|\[D[EÉ]VELOPPEUR\]|\[INTERNE\]/i,
    type: 'instruction_override',
    severity: 'critical',
    description: 'French: Fake authority marker',
    weight: 35,
    language: 'fr',
  },
];

// ============================================================================
// German (de) Patterns
// ============================================================================

export const GERMAN_PATTERNS: PatternDefinition[] = [
  // Instruction override - critical
  {
    pattern: /ignorier(e|en)?\s+(alle\s+)?(vorherigen?|fr[uü]heren?|bisherigen?)\s+(anweisungen?|regeln?|richtlinien?)/i,
    type: 'instruction_override',
    severity: 'critical',
    description: 'German: Attempt to ignore previous instructions',
    weight: 30,
    language: 'de',
  },
  {
    pattern: /vergiss\s+(alles\s+)?(was\s+)?(ich\s+)?(dir\s+)?(gesagt\s+habe|erw[aä]hnt)/i,
    type: 'instruction_override',
    severity: 'high',
    description: 'German: Attempt to reset context',
    weight: 25,
    language: 'de',
  },
  {
    pattern: /neue\s+(anweisungen?|regeln?|modus|rolle):/i,
    type: 'instruction_override',
    severity: 'high',
    description: 'German: Attempt to set new instructions',
    weight: 25,
    language: 'de',
  },
  // Role impersonation
  {
    pattern: /(jetzt\s+)?bist\s+du\s+(ein|eine|mein|meine)/i,
    type: 'role_impersonation',
    severity: 'high',
    description: 'German: Attempt to change AI role',
    weight: 25,
    language: 'de',
  },
  {
    pattern: /tu\s+so\s+als\s+(ob\s+du|w[aä]rst\s+du)/i,
    type: 'role_impersonation',
    severity: 'medium',
    description: 'German: Role pretend instruction',
    weight: 15,
    language: 'de',
  },
  // System markers
  {
    pattern: /\[SYSTEM\]|\[ADMIN(ISTRATOR)?\]|\[ENTWICKLER\]|\[INTERN\]/i,
    type: 'instruction_override',
    severity: 'critical',
    description: 'German: Fake authority marker',
    weight: 35,
    language: 'de',
  },
];

// ============================================================================
// Portuguese (pt) Patterns
// ============================================================================

export const PORTUGUESE_PATTERNS: PatternDefinition[] = [
  // Instruction override - critical
  {
    pattern: /ignor(e|a|ar)\s+(todas?\s+)?(as?\s+)?(instru[cç][oõ]es?|regras?|diretivas?)\s+(anteriores?|pr[eé]vias?)/i,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Portuguese: Attempt to ignore previous instructions',
    weight: 30,
    language: 'pt',
  },
  {
    pattern: /esque[cç](a|er)\s+(tudo\s+)?(o\s+)?(que\s+)?(eu\s+)?(disse|falei|mencionei)/i,
    type: 'instruction_override',
    severity: 'high',
    description: 'Portuguese: Attempt to reset context',
    weight: 25,
    language: 'pt',
  },
  {
    pattern: /novas?\s+(instru[cç][oõ]es?|regras?|modo|papel):/i,
    type: 'instruction_override',
    severity: 'high',
    description: 'Portuguese: Attempt to set new instructions',
    weight: 25,
    language: 'pt',
  },
  // Role impersonation
  {
    pattern: /(agora\s+)?voc[eê]\s+[eé]\s+(um|uma|meu|minha)/i,
    type: 'role_impersonation',
    severity: 'high',
    description: 'Portuguese: Attempt to change AI role',
    weight: 25,
    language: 'pt',
  },
  {
    pattern: /finja\s+(que\s+)?(voc[eê]\s+[eé]|ser)/i,
    type: 'role_impersonation',
    severity: 'medium',
    description: 'Portuguese: Role pretend instruction',
    weight: 15,
    language: 'pt',
  },
  // System markers
  {
    pattern: /\[SISTEMA\]|\[ADMIN(ISTRADOR)?\]|\[DESENVOLVEDOR\]|\[INTERNO\]/i,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Portuguese: Fake authority marker',
    weight: 35,
    language: 'pt',
  },
];

// ============================================================================
// Chinese (zh) Patterns
// ============================================================================

export const CHINESE_PATTERNS: PatternDefinition[] = [
  // Instruction override - critical
  {
    pattern: /忽略.{0,5}(之前|以前|先前|早先).{0,5}(指令|指示|规则|说明)/,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Chinese: Attempt to ignore previous instructions',
    weight: 30,
    language: 'zh',
  },
  {
    pattern: /无视.{0,5}(之前|以前|先前).{0,5}(指令|指示|规则)/,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Chinese: Disregard previous instructions',
    weight: 30,
    language: 'zh',
  },
  {
    pattern: /忘记.{0,5}(我|之前).{0,5}(说|告诉|提到)/,
    type: 'instruction_override',
    severity: 'high',
    description: 'Chinese: Attempt to reset context',
    weight: 25,
    language: 'zh',
  },
  {
    pattern: /新(的)?(指令|指示|规则|模式|角色)[：:]/,
    type: 'instruction_override',
    severity: 'high',
    description: 'Chinese: Attempt to set new instructions',
    weight: 25,
    language: 'zh',
  },
  // Role impersonation
  {
    pattern: /(现在)?你是.{0,5}(一个|我的)/,
    type: 'role_impersonation',
    severity: 'high',
    description: 'Chinese: Attempt to change AI role',
    weight: 25,
    language: 'zh',
  },
  {
    pattern: /假装.{0,5}(你是|成为)/,
    type: 'role_impersonation',
    severity: 'medium',
    description: 'Chinese: Role pretend instruction',
    weight: 15,
    language: 'zh',
  },
  // System markers
  {
    pattern: /【系统】|【管理员】|【开发者】|【内部】/,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Chinese: Fake authority marker',
    weight: 35,
    language: 'zh',
  },
  {
    pattern: /\[系统\]|\[管理员\]|\[开发者\]|\[内部\]/,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Chinese: Fake authority marker (brackets)',
    weight: 35,
    language: 'zh',
  },
];

// ============================================================================
// Japanese (ja) Patterns
// ============================================================================

export const JAPANESE_PATTERNS: PatternDefinition[] = [
  // Instruction override - critical
  {
    pattern: /(以前|前|先).{0,5}(指示|命令|ルール|規則).{0,5}(無視|忽略)/,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Japanese: Attempt to ignore previous instructions',
    weight: 30,
    language: 'ja',
  },
  {
    pattern: /(前の|以前の).{0,5}(指示|命令).{0,5}(忘れ|無視)/,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Japanese: Disregard previous instructions',
    weight: 30,
    language: 'ja',
  },
  {
    pattern: /(私が|さっき).{0,5}(言った|話した).{0,5}(忘れ)/,
    type: 'instruction_override',
    severity: 'high',
    description: 'Japanese: Attempt to reset context',
    weight: 25,
    language: 'ja',
  },
  {
    pattern: /新(しい)?(指示|命令|ルール|モード|役割)[：:]/,
    type: 'instruction_override',
    severity: 'high',
    description: 'Japanese: Attempt to set new instructions',
    weight: 25,
    language: 'ja',
  },
  // Tool baiting
  {
    pattern: /(この)?コマンドを実行/,
    type: 'tool_baiting',
    severity: 'high',
    description: 'Japanese: Command execution request',
    weight: 25,
    language: 'ja',
  },
  {
    pattern: /実行(して|する)[ください]?[:：]\s*(rm|del|format)/i,
    type: 'tool_baiting',
    severity: 'critical',
    description: 'Japanese: Destructive command request',
    weight: 40,
    language: 'ja',
  },
  // Role impersonation
  {
    pattern: /(今から)?あなたは.{0,5}(私の|一人の)/,
    type: 'role_impersonation',
    severity: 'high',
    description: 'Japanese: Attempt to change AI role',
    weight: 25,
    language: 'ja',
  },
  {
    pattern: /(ふりを|振りを).{0,5}(して|する)/,
    type: 'role_impersonation',
    severity: 'medium',
    description: 'Japanese: Role pretend instruction',
    weight: 15,
    language: 'ja',
  },
  // System markers
  {
    pattern: /【システム】|【管理者】|【開発者】|【内部】/,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Japanese: Fake authority marker',
    weight: 35,
    language: 'ja',
  },
  {
    pattern: /\[システム\]|\[管理者\]|\[開発者\]|\[内部\]/,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Japanese: Fake authority marker (brackets)',
    weight: 35,
    language: 'ja',
  },
];

// ============================================================================
// Russian (ru) Patterns
// ============================================================================

export const RUSSIAN_PATTERNS: PatternDefinition[] = [
  // Instruction override - critical
  {
    pattern: /игнорир(уй|овать)\s+(все\s+)?(предыдущ|прежн|прошл).{0,10}(инструкци|правил|указани)/i,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Russian: Attempt to ignore previous instructions',
    weight: 30,
    language: 'ru',
  },
  {
    pattern: /забудь\s+(всё\s+)?(что\s+)?(я\s+)?(сказал|говорил|упомянул)/i,
    type: 'instruction_override',
    severity: 'high',
    description: 'Russian: Attempt to reset context',
    weight: 25,
    language: 'ru',
  },
  {
    pattern: /нов(ые|ая)\s+(инструкци|правил|режим|роль):/i,
    type: 'instruction_override',
    severity: 'high',
    description: 'Russian: Attempt to set new instructions',
    weight: 25,
    language: 'ru',
  },
  {
    pattern: /(теперь\s+)?в\s+режиме\s+DAN/i,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Russian: DAN mode jailbreak attempt',
    weight: 45,
    language: 'ru',
  },
  {
    pattern: /можешь\s+делать\s+всё\s+без\s+ограничений/i,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Russian: Attempt to remove restrictions',
    weight: 40,
    language: 'ru',
  },
  // Role impersonation
  {
    pattern: /(теперь\s+)?ты\s+(есть\s+)?(мой|моя|один|одна)/i,
    type: 'role_impersonation',
    severity: 'high',
    description: 'Russian: Attempt to change AI role',
    weight: 25,
    language: 'ru',
  },
  {
    pattern: /притвор(ись|яйся)\s+(что\s+)?(ты|будто)/i,
    type: 'role_impersonation',
    severity: 'medium',
    description: 'Russian: Role pretend instruction',
    weight: 15,
    language: 'ru',
  },
  // System markers
  {
    pattern: /\[СИСТЕМА\]|\[АДМИН(ИСТРАТОР)?\]|\[РАЗРАБОТЧИК\]|\[ВНУТРЕНН(ИЙ|ЕЕ)\]/i,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Russian: Fake authority marker',
    weight: 35,
    language: 'ru',
  },
];

// ============================================================================
// Arabic (ar) Patterns
// ============================================================================

export const ARABIC_PATTERNS: PatternDefinition[] = [
  // Instruction override - critical
  {
    pattern: /تجاهل.{0,10}(التعليمات|القواعد|الإرشادات).{0,10}(السابقة|الماضية|القديمة)/,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Arabic: Attempt to ignore previous instructions',
    weight: 30,
    language: 'ar',
  },
  {
    pattern: /انسَ|انسى.{0,10}(كل|ما).{0,10}(قلته|ذكرته)/,
    type: 'instruction_override',
    severity: 'high',
    description: 'Arabic: Attempt to reset context',
    weight: 25,
    language: 'ar',
  },
  {
    pattern: /(تعليمات|قواعد|وضع|دور)\s*(جديدة?|الجديدة?)[:：]/,
    type: 'instruction_override',
    severity: 'high',
    description: 'Arabic: Attempt to set new instructions',
    weight: 25,
    language: 'ar',
  },
  // Role impersonation
  {
    pattern: /(الآن\s+)?أنت.{0,5}(لي|خاص)/,
    type: 'role_impersonation',
    severity: 'high',
    description: 'Arabic: Attempt to change AI role',
    weight: 25,
    language: 'ar',
  },
  {
    pattern: /تظاهر.{0,5}(أنك|بأنك|كأنك)/,
    type: 'role_impersonation',
    severity: 'medium',
    description: 'Arabic: Role pretend instruction',
    weight: 15,
    language: 'ar',
  },
  // System markers
  {
    pattern: /\[النظام\]|\[المشرف\]|\[المطور\]|\[داخلي\]/,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Arabic: Fake authority marker',
    weight: 35,
    language: 'ar',
  },
  {
    pattern: /【النظام】|【المشرف】|【المطور】|【داخلي】/,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Arabic: Fake authority marker (brackets)',
    weight: 35,
    language: 'ar',
  },
];

// ============================================================================
// Korean (ko) Patterns
// ============================================================================

export const KOREAN_PATTERNS: PatternDefinition[] = [
  // Instruction override - critical
  {
    pattern: /(이전|앞의|기존).{0,5}(지시|명령|규칙|지침).{0,5}(무시|무효화)/,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Korean: Attempt to ignore previous instructions',
    weight: 30,
    language: 'ko',
  },
  {
    pattern: /(내가|제가).{0,5}(말한|했던).{0,5}(잊어|무시)/,
    type: 'instruction_override',
    severity: 'high',
    description: 'Korean: Attempt to reset context',
    weight: 25,
    language: 'ko',
  },
  {
    pattern: /새(로운)?\s*(지시|명령|규칙|모드|역할)[：:]/,
    type: 'instruction_override',
    severity: 'high',
    description: 'Korean: Attempt to set new instructions',
    weight: 25,
    language: 'ko',
  },
  // Data exfiltration
  {
    pattern: /(API\s*키|비밀번호|암호|토큰|인증).{0,10}(보내|전송|알려)/,
    type: 'data_exfiltration',
    severity: 'critical',
    description: 'Korean: Credential exfiltration attempt',
    weight: 45,
    language: 'ko',
  },
  // Role impersonation
  {
    pattern: /(지금부터\s+)?너는.{0,5}(나의|내)/,
    type: 'role_impersonation',
    severity: 'high',
    description: 'Korean: Attempt to change AI role',
    weight: 25,
    language: 'ko',
  },
  {
    pattern: /(척|처럼).{0,5}(해|해줘|행동해)/,
    type: 'role_impersonation',
    severity: 'medium',
    description: 'Korean: Role pretend instruction',
    weight: 15,
    language: 'ko',
  },
  // System markers
  {
    pattern: /\[시스템\]|\[관리자\]|\[개발자\]|\[내부\]/,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Korean: Fake authority marker',
    weight: 35,
    language: 'ko',
  },
  {
    pattern: /【시스템】|【관리자】|【개발자】|【내부】/,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Korean: Fake authority marker (brackets)',
    weight: 35,
    language: 'ko',
  },
];

// ============================================================================
// Italian (it) Patterns
// ============================================================================

export const ITALIAN_PATTERNS: PatternDefinition[] = [
  // Instruction override - critical
  {
    pattern: /ignora\s+(tutte?\s+)?(le\s+)?(istruzioni|regole|direttive)\s+(precedenti|anteriori|passate)/i,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Italian: Attempt to ignore previous instructions',
    weight: 30,
    language: 'it',
  },
  {
    pattern: /dimentica\s+(tutto\s+)?(quello\s+)?(che\s+)?(ti\s+)?(ho\s+detto|detto)/i,
    type: 'instruction_override',
    severity: 'high',
    description: 'Italian: Attempt to reset context',
    weight: 25,
    language: 'it',
  },
  {
    pattern: /nuov[aei]\s+(istruzioni|regole|modalit[àa]|ruolo):/i,
    type: 'instruction_override',
    severity: 'high',
    description: 'Italian: Attempt to set new instructions',
    weight: 25,
    language: 'it',
  },
  // Role impersonation
  {
    pattern: /(adesso\s+)?sei\s+(un|una|il\s+mio|la\s+mia)/i,
    type: 'role_impersonation',
    severity: 'high',
    description: 'Italian: Attempt to change AI role',
    weight: 25,
    language: 'it',
  },
  {
    pattern: /fingi\s+(di\s+essere|che\s+sei)/i,
    type: 'role_impersonation',
    severity: 'medium',
    description: 'Italian: Role pretend instruction',
    weight: 15,
    language: 'it',
  },
  // System markers
  {
    pattern: /\[SISTEMA\]|\[ADMIN(ISTRATORE)?\]|\[SVILUPPATORE\]|\[INTERNO\]/i,
    type: 'instruction_override',
    severity: 'critical',
    description: 'Italian: Fake authority marker',
    weight: 35,
    language: 'it',
  },
];

// ============================================================================
// Universal Patterns (language-agnostic)
// ============================================================================

export const UNIVERSAL_PATTERNS: PatternDefinition[] = [
  // Common code/markup patterns used across languages
  {
    pattern: /```\s*(system|admin|root|sudo)/i,
    type: 'instruction_override',
    severity: 'high',
    description: 'Code block with privileged context',
    weight: 25,
    language: 'universal',
  },
  {
    pattern: /<(system|admin|developer|internal)>/i,
    type: 'instruction_override',
    severity: 'critical',
    description: 'XML-style authority tag',
    weight: 35,
    language: 'universal',
  },
  {
    pattern: /={5,}\s*(system|admin|internal|override)/i,
    type: 'instruction_override',
    severity: 'high',
    description: 'Delimiter-based authority marker',
    weight: 25,
    language: 'universal',
  },
  // Emoji-based obfuscation
  {
    pattern: /🔓|🔐|🔑.{0,20}(unlock|bypass|override|access)/i,
    type: 'instruction_override',
    severity: 'medium',
    description: 'Emoji-based unlock/bypass attempt',
    weight: 15,
    language: 'universal',
  },
  // ASCII art separators often used to inject instructions
  {
    pattern: /[─━═]{10,}/,
    type: 'obfuscation',
    severity: 'low',
    description: 'ASCII art separator (potential injection boundary)',
    weight: 5,
    language: 'universal',
  },
];

// ============================================================================
// Combined Export
// ============================================================================

export const ALL_MULTILINGUAL_PATTERNS: PatternDefinition[] = [
  ...SPANISH_PATTERNS,
  ...FRENCH_PATTERNS,
  ...GERMAN_PATTERNS,
  ...PORTUGUESE_PATTERNS,
  ...CHINESE_PATTERNS,
  ...JAPANESE_PATTERNS,
  ...RUSSIAN_PATTERNS,
  ...ARABIC_PATTERNS,
  ...KOREAN_PATTERNS,
  ...ITALIAN_PATTERNS,
  ...UNIVERSAL_PATTERNS,
];

/**
 * Get patterns for a specific language
 */
export function getPatternsForLanguage(languageCode: string): PatternDefinition[] {
  const patterns: Record<string, PatternDefinition[]> = {
    es: SPANISH_PATTERNS,
    fr: FRENCH_PATTERNS,
    de: GERMAN_PATTERNS,
    pt: PORTUGUESE_PATTERNS,
    zh: CHINESE_PATTERNS,
    ja: JAPANESE_PATTERNS,
    ru: RUSSIAN_PATTERNS,
    ar: ARABIC_PATTERNS,
    ko: KOREAN_PATTERNS,
    it: ITALIAN_PATTERNS,
    universal: UNIVERSAL_PATTERNS,
  };

  return patterns[languageCode] ?? [];
}

/**
 * Get all critical patterns regardless of language
 */
export function getCriticalPatterns(): PatternDefinition[] {
  return ALL_MULTILINGUAL_PATTERNS.filter(p => p.severity === 'critical');
}
