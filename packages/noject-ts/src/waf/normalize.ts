// Shared normalization for the WAF engine — mirrors internal/waf/waf.go
// (Go gateway) so payload handling is consistent across the standalone
// TS library and the Go gateway it's meant to approximate.

// Minimal named-entity table covering the entities attackers actually use
// to hide WAF-relevant syntax (":" in "javascript:", "<"/">" in tags).
// Not a full HTML5 entity set — this isn't an HTML renderer, just enough
// to stop entity-encoding from hiding a literal token from regex matching.
const NAMED_ENTITIES: Record<string, string> = {
  colon: ':', semi: ';', lt: '<', gt: '>', quot: '"', apos: "'", amp: '&', sol: '/',
};

function decodeHtmlEntities(input: string): string {
  return input
    .replace(/&#x([0-9a-fA-F]+);?/g, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/&#(\d+);?/g, (_, dec) => String.fromCodePoint(parseInt(dec, 10)))
    .replace(/&([a-zA-Z]+);?/g, (m, name) => NAMED_ENTITIES[name.toLowerCase()] ?? m);
}

const SQL_VERSIONED_COMMENT = /\/\*!\d*([\s\S]*?)\*\//g;
const SQL_INLINE_COMMENT = /\/\*[\s\S]*?\*\//g;

// normalizeInput unescapes URL/HTML encoding to a fixed point and strips
// inline comment syntax, so signature matching sees the payload the way a
// downstream interpreter will — not the way the attacker typed it.
export function normalizeInput(raw: string): string {
  let decoded = raw;
  for (let i = 0; i < 5; i++) {
    let next: string;
    try {
      next = decodeURIComponent(decoded.replace(/\+/g, ' '));
    } catch {
      break;
    }
    if (next === decoded) break;
    decoded = next;
  }
  decoded = decodeHtmlEntities(decoded);
  decoded = decoded.replace(SQL_VERSIONED_COMMENT, ' $1 ');
  decoded = decoded.replace(SQL_INLINE_COMMENT, ' ');
  return decoded;
}
