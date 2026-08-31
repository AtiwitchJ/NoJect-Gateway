---
name: signature-evasion-defense
description: Use when writing or reviewing regex/signature rules for a WAF, input filter, or injection detector — SQLi, XSS, command injection, path traversal — or when a payload is reported as bypassing an existing rule.
---

# Signature Evasion Defense

## Overview

**Signature matching fails in two predictable ways: the payload is encoded so the pattern never sees it, or the pattern enumerates what is bad instead of what is structurally wrong.**

Both are fixable. Neither is fixed by adding more patterns.

## Rule 1: Normalize before matching, in the interpreter's direction

Match against the payload as the *downstream interpreter* will see it, not as the attacker typed it.

Every transform the downstream stack performs, the filter must perform first:

| Transform | Payload that bypassed here |
|---|---|
| Multi-pass URL decode | `%25252e%25252e%25252f` (triple-encoded `../`) |
| HTML entity decode | `javascript&colon;alert(1)` |
| SQL comment collapse | `UNION/**/SELECT` |
| Versioned comment unwrap | `/*!50000UNION*/` — **executes**, is not a no-op |
| Control-char strip | `<scr\x00ipt>` — parsers drop the NUL |
| Zero-width strip | `089-123<ZWSP>-4567` |

Decode to a **fixed point** (loop until stable, bounded), not a hardcoded number of passes.

**Counter-example — do not normalize what the interpreter does not.** `<scrıpt>` (Turkish dotless ı) is inert: browsers do not fold `ı`→`i`, so the tag never executes. Adding a rule for it is cargo cult that only adds false-positive surface. Normalize to match reality, not to look thorough.

## Rule 2: Invert allowlists — match syntax, not names

A list of dangerous binaries can never be complete. Measured here: `; ls`, `& id`, `\nid` all passed because `ls` was not listed and single `&` / newline were not even in the separator class.

The attacker chooses the binary. **They cannot omit the separator.**

```go
// Fragile: enumerate binaries — every unlisted one walks through
`(;|\|)\s*(cat|curl|wget|rm)`

// Durable: match the shell syntax itself
`(?:;|\|\|?|&&?|\r|\n)\s*/?[a-z][a-z0-9_.-]*\s+(?:-{1,2}[a-z0-9]|/[a-z]|[<>])`
```

Same principle elsewhere: match *any* `on*=` handler, not an enumerated list of the ~150 DOM events. Match `OR`/`AND` tautologies structurally, not the literal `1=1`.

## Rule 3: Scope strictness to the surface

Aggressive syntax rules are correct on surfaces where shell/SQL metacharacters have no legitimate use, and wrong where they do.

| Surface | Rule strength | Why |
|---|---|---|
| URL path, query, headers | Strict syntax-level | `;` and `\|` have no innocent reason to appear |
| Request body (JSON/prose) | Named patterns only | Prose and code contain `;`, `\|`, `&&` constantly |

Applying the strict rule to bodies produces a false-positive storm; applying only the weak rule to query strings leaves the real attack surface open. One rule set for both is wrong in one direction or the other.

## Quick Reference

| Symptom | Fix |
|---|---|
| Encoded payload passes | Add that decode step to normalization |
| Unlisted binary/handler/function passes | Invert to syntax-level matching |
| Rule blocks real traffic | Scope it to the surface where the syntax is never legitimate |
| Paraphrase passes | Signatures cannot fix this — escalate to a semantic tier |

## Red Flags

- Adding pattern #47 for a payload variant instead of asking why #46 missed it
- A denylist of "dangerous commands/functions/tags"
- Hardcoded decode-pass count (`unescape` twice)
- Same rule applied to query strings and request bodies
- Normalizing a transform the interpreter does not perform

## Real-World Impact

Inverting the command allowlist and adding normalization took the measured bypass rate on this WAF from 11/12 and 8/10 down to 0–1/10, with 0 false positives across an 18-case benign corpus.
