# NoJect Skills

Two distinct sets. They are not interchangeable.

## `skills/sentinel/` — runtime knowledge for the Agentic AI Sentinel

**Loaded into the LLM judge's system prompt at runtime** by
`guard-engine/detectors/sentinel_skills.py`. Editing one of these files
changes how the Sentinel classifies traffic on the next request — no code
change, no redeploy of the judging harness.

| Skill | Threat category | Standard |
|---|---|---|
| [prompt-injection](sentinel/prompt-injection/SKILL.md) | `PROMPT_INJECTION` | AML.T0054 / LLM01 |
| [jailbreak](sentinel/jailbreak/SKILL.md) | `JAILBREAK` | AML.T0051 / LLM01 |
| [reconnaissance](sentinel/reconnaissance/SKILL.md) | `RECONNAISSANCE` | AML.T0043 / LLM07 |
| [data-exfiltration](sentinel/data-exfiltration/SKILL.md) | `DATA_EXFILTRATION` | LLM02 / LLM06 |
| [tool-hijacking](sentinel/tool-hijacking/SKILL.md) | `PROMPT_INJECTION` | LLM07 / AML.T0053 |

### Required structure

Each must have YAML frontmatter with `name`, `threat_category`, and
`standard_code`, and a body containing:

1. **What the attacker wants** — the objective, not a payload list
2. **Detection criteria** — what to flag
3. **Evasion techniques** — obfuscations to decode past
4. **Benign lookalikes — do NOT flag** — *mandatory*, enforced by
   `tests/test_sentinel_skills.py`
5. **Severity** — risk_score bands

`threat_category` must be a value the `InspectRequestResponse` schema
accepts, or callers receive a category they cannot handle. Enforced by test.

### Why the benign section is mandatory

A skill that lists only what to block drives the judge toward false
positives, and a guardrail that blocks real customers gets switched off —
which is a worse outcome than the attack it prevented. Every domain must
state what it must *not* flag.

### Adding or editing a skill

1. Write the adversarial payload that is currently misjudged
2. Confirm it is misjudged (`guard-engine/redteam_guard.py`, or a live call)
3. Edit the SKILL.md
4. Re-run: the payload is now judged correctly **and** the benign corpus
   still passes
5. `make test-py`

Do not add a rule without a payload that failed first — see
[adversarial-corpus-testing](adversarial-corpus-testing/SKILL.md).

## Developer-facing skills

Reference guides for agents and humans changing defensive code. Not loaded
at runtime.

| Skill | Use when |
|---|---|
| [adversarial-corpus-testing](adversarial-corpus-testing/SKILL.md) | Writing or trusting security test results |
| [signature-evasion-defense](signature-evasion-defense/SKILL.md) | Writing regex/signature rules for the WAF |
| [prompt-injection-layers](prompt-injection-layers/SKILL.md) | Choosing between keyword and model-based detection |

## The division of labour

Signatures are free and instant but blind to meaning; the judge understands
meaning but is slow and metered. They fail on **disjoint** sets of attacks —
measured in this repo, the keyword tier could not block paraphrase attacks
at all, while the skill-equipped judge blocked 4/4 of them and correctly
passed 4/4 benign lookalikes.

Run signatures on every request. Run the judge on LLM routes.
