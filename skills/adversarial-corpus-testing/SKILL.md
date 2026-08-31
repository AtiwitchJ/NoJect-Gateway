---
name: adversarial-corpus-testing
description: Use when writing, reviewing, or trusting security test results for a detector, WAF, or filter — especially when a test suite reports a high block rate, when adding detection rules, or when asked "how good is our coverage?"
---

# Adversarial Corpus Testing

## Overview

**A detector tested only against payloads its own rules were written for will always score ~100%. That number measures nothing.**

Security tests must be written by someone trying to defeat the detector, not by the person who wrote the rules.

## The Trap (measured in this repo)

| Corpus | Result |
|---|---|
| `tests/security_score_test.go` (self-written) | 44/44 = **100%** |
| Independent red-team, round 1 | 11/12 **bypassed** |
| After fixes → self-written corpus | still **100%** |
| Independent red-team, round 2 (118 payloads) | **~50% bypassed** |
| After fixes → self-written corpus | still **100%** |

The self-written score never moved, through two rounds of real holes. It reported 100% while half of all real attacks walked through.

**Root cause:** every payload in the self-written corpus was written by reading the rules. It is a mirror, not a test.

## Rules

1. **Every detection rule change requires an adversarial payload that failed before it.** No payload, no rule — you cannot show the rule does anything.
2. **A benign corpus is mandatory alongside the attack corpus.** Blocking everything scores 100% on attacks. Only the pair is meaningful.
3. **Never report a block rate without also reporting the false-positive rate and the corpus source.** "100%" alone is not a result.
4. **Corpora are CI gates, not scripts someone runs manually.** A corpus nobody runs cannot detect regression.

## The false-positive corpus is not optional

Aggressive rules break real traffic, and that failure is invisible to an attack-only corpus. Measured here: a widened command-injection rule flagged `title=Rock %26 Roll` (decodes to `Rock & Roll` → `& Roll`) as a shell command. Caught only because a benign corpus existed.

A blocked customer is an outage. Ship the benign corpus in the same commit as the rule.

## Writing adversarial payloads

Do not invent variations of payloads you already block. Start from **evasion primitives** and apply them to a payload you know is caught:

| Primitive | Example |
|---|---|
| Encoding | base64, hex, ROT13, URL (multi-pass), HTML entity |
| Invisible chars | zero-width space, BOM, soft hyphen, RTL marks |
| Separators | `i g n o r e`, `i-g-n-o-r-e`, `UNION/**/SELECT` |
| Case/homoglyph | leetspeak, Cyrillic `і`, fullwidth digits |
| Language | the same instruction in Thai, Chinese, Japanese |
| Structure | trailing/leading junk, comment wrapping, nesting |
| Semantics | paraphrase with zero shared keywords |

The last row is the important one: if paraphrase bypasses, no additional pattern will fix it. That is the signal to escalate to a semantic tier, not to write rule #48.

## Red Flags

- "Our test suite passes 100%" — against which corpus, written by whom?
- Adding a rule without a payload that failed first
- An attack corpus with no benign counterpart
- Corpus lives in a script that CI never runs
- Reporting detection rate without false-positive rate

## Real-World Impact

Two consecutive "100%" reports in this repo concealed 11/12 and then ~50% bypass rates. The gap closed only when an independent corpus was run — and the self-written suite never once indicated a problem.
