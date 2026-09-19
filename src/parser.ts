export interface EnvEntry {
  key: string;
  value: string;
  raw: string;
  comment?: string;
  isCommentOrEmpty: boolean;
}

export interface ParsedEnv {
  entries: EnvEntry[];
  map: Record<string, string>;
}

/**
 * Parses .env file content into structured entries, preserving comments and format.
 */
export function parseEnv(content: string): ParsedEnv {
  const lines = content.split(/\r?\n/);
  const entries: EnvEntry[] = [];
  const map: Record<string, string> = {};

  for (const raw of lines) {
    const trimmed = raw.trim();

    // Empty line or full-line comment
    if (!trimmed || trimmed.startsWith('#')) {
      entries.push({
        key: '',
        value: '',
        raw,
        comment: trimmed.startsWith('#') ? trimmed.slice(1).trim() : undefined,
        isCommentOrEmpty: true
      });
      continue;
    }

    // Match KEY=VALUE (supports optional `export ` prefix)
    const match = raw.match(/^\s*(?:export\s+)?([\w.-]+)\s*=\s*(.*)?$/);
    if (!match) {
      // Unrecognized line format, preserve as raw
      entries.push({
        key: '',
        value: '',
        raw,
        isCommentOrEmpty: true
      });
      continue;
    }

    const key = match[1];
    let valPart = match[2] !== undefined ? match[2].trim() : '';
    let inlineComment: string | undefined;

    // Handle quoted values
    if (valPart.startsWith('"')) {
      const endQuoteIdx = valPart.indexOf('"', 1);
      if (endQuoteIdx !== -1) {
        const remaining = valPart.slice(endQuoteIdx + 1).trim();
        if (remaining.startsWith('#')) {
          inlineComment = remaining.slice(1).trim();
        }
        valPart = valPart.slice(1, endQuoteIdx)
          .replace(/\\n/g, '\n')
          .replace(/\\r/g, '\r')
          .replace(/\\t/g, '\t');
      } else {
        valPart = valPart.slice(1);
      }
    } else if (valPart.startsWith("'")) {
      const endQuoteIdx = valPart.indexOf("'", 1);
      if (endQuoteIdx !== -1) {
        const remaining = valPart.slice(endQuoteIdx + 1).trim();
        if (remaining.startsWith('#')) {
          inlineComment = remaining.slice(1).trim();
        }
        valPart = valPart.slice(1, endQuoteIdx);
      } else {
        valPart = valPart.slice(1);
      }
    } else {
      // Unquoted: check for inline comment
      const commentIdx = valPart.indexOf(' #');
      if (commentIdx !== -1) {
        inlineComment = valPart.slice(commentIdx + 2).trim();
        valPart = valPart.slice(0, commentIdx).trim();
      }
    }

    entries.push({
      key,
      value: valPart,
      raw,
      comment: inlineComment,
      isCommentOrEmpty: false
    });
    map[key] = valPart;
  }

  return { entries, map };
}

/**
 * Formats a key-value record back into clean .env content.
 */
export function stringifyEnv(map: Record<string, string>): string {
  return Object.entries(map)
    .map(([key, value]) => {
      // Quote if contains spaces, newlines, or quotes
      if (value.includes(' ') || value.includes('\n') || value.includes('"') || value.includes('#')) {
        const escaped = value.replace(/"/g, '\\"').replace(/\n/g, '\\n');
        return `${key}="${escaped}"`;
      }
      return `${key}=${value}`;
    })
    .join('\n');
}
