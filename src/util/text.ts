/** Invisible / control Unicode ranges commonly used for hidden prompt injection. */
const INVISIBLE_RANGES: Array<[number, number]> = [
  [0x00ad, 0x00ad], // soft hyphen
  [0x034f, 0x034f], // combining grapheme joiner
  [0x115f, 0x1160], // hangul fillers
  [0x17b4, 0x17b5], // khmer inherent vowels
  [0x180b, 0x180e], // mongolian variation selectors / vowel separator
  [0x200b, 0x200f], // ZWSP, ZWNJ, ZWJ, LRM, RLM
  [0x202a, 0x202e], // bidi embedding / override
  [0x2060, 0x2064], // word joiner, invisible operators
  [0x2066, 0x2069], // bidi isolates
  [0x2800, 0x2800], // braille blank
  [0x3164, 0x3164], // hangul filler
  [0xfe00, 0xfe0f], // variation selectors
  [0xfeff, 0xfeff], // zero width no-break space
  [0xffa0, 0xffa0], // halfwidth hangul filler
  [0xe0000, 0xe007f], // Tags block — the classic invisible prompt-injection channel
  [0xe0100, 0xe01ef], // variation selectors supplement
];

export interface InvisibleChar {
  codepoint: number;
  hex: string;
  index: number;
}

export function findInvisibleChars(text: string): InvisibleChar[] {
  const found: InvisibleChar[] = [];
  let i = 0;
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    for (const [lo, hi] of INVISIBLE_RANGES) {
      if (cp >= lo && cp <= hi) {
        found.push({ codepoint: cp, hex: `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`, index: i });
        break;
      }
    }
    i += ch.length;
  }
  return found;
}

/** Strip single-line comments so code rules don't flag prose. Quote-aware: a // or #
 *  inside a string literal (e.g. "https://…") is NOT a comment. Block comments are left
 *  in place: payloads are frequently hidden inside them on purpose. */
export function stripLineComments(content: string, language: string): string {
  const marker = language === "python" || language === "shell" ? "#" : "//";
  return content
    .split("\n")
    .map((line) => {
      let quote: string | null = null;
      for (let i = 0; i < line.length; i++) {
        const ch = line[i]!;
        if (quote) {
          if (ch === "\\") i++;
          else if (ch === quote) quote = null;
          continue;
        }
        if (ch === '"' || ch === "'" || ch === "`") {
          quote = ch;
          continue;
        }
        if (line.startsWith(marker, i)) {
          // keep "marker at column 0" behavior identical; cut the rest
          return i === 0 ? line : line.slice(0, i);
        }
      }
      return line;
    })
    .join("\n");
}

export function truncate(s: string, max = 160): string {
  const oneLine = s.replace(/\s+/g, " ").trim();
  return oneLine.length <= max ? oneLine : oneLine.slice(0, max - 1) + "…";
}

/** Find the 1-based line number of a character offset. */
export function lineOf(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) {
    if (content[i] === "\n") line++;
  }
  return line;
}

export interface PatternMatch {
  pattern: RegExp;
  match: string;
  index: number;
}

export function firstMatch(text: string, patterns: RegExp[]): PatternMatch | undefined {
  for (const pattern of patterns) {
    const m = pattern.exec(text);
    if (m) return { pattern, match: m[0], index: m.index };
  }
  return undefined;
}

export function allMatches(text: string, patterns: RegExp[]): PatternMatch[] {
  const out: PatternMatch[] = [];
  for (const pattern of patterns) {
    const re = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g");
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      out.push({ pattern, match: m[0], index: m.index });
      if (m.index === re.lastIndex) re.lastIndex++;
    }
  }
  return out;
}

/** Classic Levenshtein distance, used for typosquat detection. */
export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  let prev = new Array<number>(b.length + 1);
  let curr = new Array<number>(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;
  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j]! + 1, curr[j - 1]! + 1, prev[j - 1]! + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[b.length]!;
}
