"""
Threat-domain skill loader for the Agentic AI Sentinel.

The Sentinel's judging criteria live in skills/sentinel/<domain>/SKILL.md
rather than in a single hardcoded prompt string. Each file documents one
threat domain: what the attacker wants, detection criteria, the evasion
techniques to see through, the benign lookalikes that must NOT be flagged,
and a severity scale.

Why files instead of a constant:

- Threat knowledge changes far more often than the judging harness. A
  red-team finding should be a one-file edit reviewable on its own, not a
  patch to a Python string literal.
- Each domain can be evaluated independently against its own corpus.
- The same documents are readable by humans and by other agents working
  on the codebase.

Loaded once at construction and cached; SKILL.md files are read from disk,
not embedded, so operators can extend coverage without editing code.
"""

import logging
import re
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("noject.sentinel_skills")

# guard-engine/detectors/ -> repo root -> skills/sentinel
DEFAULT_SKILLS_DIR = (
    Path(__file__).resolve().parent.parent.parent / "skills" / "sentinel"
)

_FRONTMATTER = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.DOTALL)


class SentinelSkill:
    """One threat-domain skill document."""

    def __init__(self, name: str, metadata: Dict[str, str], body: str):
        self.name = name
        self.metadata = metadata
        self.body = body

    @property
    def threat_category(self) -> str:
        return self.metadata.get("threat_category", "NONE")

    @property
    def standard_code(self) -> str:
        return self.metadata.get("standard_code", "")


def _parse_skill(path: Path) -> Optional[SentinelSkill]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("Could not read sentinel skill %s: %s", path, exc)
        return None

    metadata: Dict[str, str] = {}
    body = raw
    match = _FRONTMATTER.match(raw)
    if match:
        for line in match.group(1).splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                metadata[key.strip()] = value.strip()
        body = raw[match.end():]

    name = metadata.get("name") or path.parent.name
    return SentinelSkill(name=name, metadata=metadata, body=body.strip())


def load_skills(skills_dir: Optional[Path] = None) -> List[SentinelSkill]:
    """Load every skills/sentinel/*/SKILL.md, sorted by directory name.

    Returns an empty list if the directory is absent — the Sentinel must
    still function (on its built-in baseline criteria) when skills are not
    deployed alongside it, e.g. in a slim container image.
    """
    directory = Path(skills_dir) if skills_dir else DEFAULT_SKILLS_DIR
    if not directory.is_dir():
        logger.warning(
            "Sentinel skills directory not found at %s; judging on baseline criteria only.",
            directory,
        )
        return []

    skills: List[SentinelSkill] = []
    for skill_file in sorted(directory.glob("*/SKILL.md")):
        skill = _parse_skill(skill_file)
        if skill:
            skills.append(skill)

    if not skills:
        logger.warning("No sentinel skills loaded from %s.", directory)
    return skills


def compose_threat_knowledge(skills: List[SentinelSkill]) -> str:
    """Render loaded skills into the threat-knowledge block of the judge prompt."""
    if not skills:
        return ""

    sections = [
        "You have been equipped with the following threat-domain knowledge.",
        "Apply it when classifying the candidate. Each domain lists both what to",
        "flag AND the benign lookalikes that must NOT be flagged — over-blocking",
        "is a real failure, not a safe default.",
        "",
    ]
    for skill in skills:
        sections.append(f"===== THREAT DOMAIN: {skill.name} =====")
        sections.append(skill.body)
        sections.append("")
    return "\n".join(sections)
