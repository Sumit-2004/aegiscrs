"""Untrusted-input defense (BUILD-BRIEF Phase 5): source comments and string
literals are attacker-writable free text, same as any other untrusted input
a real CRS ingests (invariant #5, plan §11.4). Before any source reaches the
model, this module extracts structured signal deterministically and redacts
anything that reads like an instruction aimed at the model itself.

Deliberately narrow: only comments/strings that actually match a known
imperative-injection shape get touched. A comment that says "/* maximum */"
sails through unchanged - stripping every comment on principle would bloat
diffs and change patch behaviour on entirely benign code, which is a worse
outcome than the risk it would be defending against.
"""
import re

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT = re.compile(r"//[^\n]*")
_STRING_LITERAL = re.compile(r'"(?:[^"\\]|\\.)*"')

# Imperative phrasing aimed at an LLM reading the "comment", not at a compiler
# or a human maintainer. Generic patterns, not tied to any one attack string.
_INJECTION_PATTERNS = {
    "ignore_instructions": re.compile(r"\bignore\s+(all|any|your|the|previous)\b.{0,20}\binstructions?\b", re.IGNORECASE),
    "disregard": re.compile(r"\bdisregard\b", re.IGNORECASE),
    "new_instructions": re.compile(r"\bnew\s+instructions?\b", re.IGNORECASE),
    "role_override": re.compile(r"\byou\s+are\s+now\b|\back\s+as\b", re.IGNORECASE),
    "role_prefix": re.compile(r"\b(system|assistant|user)\s*:", re.IGNORECASE),
    "approve_directive": re.compile(r"\bapprove\s+(this|any|the)\s+(patch|fix|change)\b", re.IGNORECASE),
}


def _find_injection_patterns(text: str) -> list[str]:
    return [name for name, rx in _INJECTION_PATTERNS.items() if rx.search(text)]


def sanitize_source(source: str) -> dict:
    """Return {"skeleton": <source with any flagged spans redacted>, "stripped": [...]}.

    `stripped` records exactly what was removed and why, for the evidence
    bundle - the bundle should be able to show a reviewer precisely what the
    model never saw, not just claim it was sanitized.
    """
    stripped = []

    def _redact(kind: str, placeholder: str):
        def _sub(match: re.Match) -> str:
            text = match.group(0)
            patterns = _find_injection_patterns(text)
            if not patterns:
                return text
            stripped.append({"kind": kind, "text": text, "injection_patterns": patterns})
            return placeholder
        return _sub

    skeleton = _BLOCK_COMMENT.sub(
        _redact("block_comment", "/* [redacted by AegisCRS signal_extractor: possible prompt injection] */"),
        source)
    skeleton = _LINE_COMMENT.sub(
        _redact("line_comment", "// [redacted by AegisCRS signal_extractor: possible prompt injection]"),
        skeleton)
    skeleton = _STRING_LITERAL.sub(
        _redact("string_literal", '"[redacted by AegisCRS signal_extractor]"'),
        skeleton)

    return {"skeleton": skeleton, "stripped": stripped}
