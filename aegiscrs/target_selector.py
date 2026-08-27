"""Candidate ranking and confidence routing (plan §11.5).

Two-stage on purpose. Every finding gets a *cheap* score from CWE impact and
static reachability — no model involved. Only the top few survivors are worth
spending an LLM triage call on, and their confidence then feeds the full
priority score. That ordering is the funnel's whole point: expensive analysis
runs on evidence-backed candidates, not on everything Semgrep emitted.
"""
from . import code_context

# Memory-corruption classes dominate; info-leak-only and unknown score lower.
_IMPACT_BY_CWE = {
    "CWE-787": 1.0,   # out-of-bounds write
    "CWE-121": 1.0,   # stack buffer overflow
    "CWE-122": 1.0,   # heap buffer overflow
    "CWE-120": 1.0,   # classic buffer copy without size check
    "CWE-416": 1.0,   # use after free
    "CWE-415": 0.9,   # double free
    "CWE-134": 0.9,   # format string
    "CWE-125": 0.85,  # out-of-bounds read
    "CWE-190": 0.7,   # integer overflow
    "CWE-476": 0.6,   # null deref
    "CWE-401": 0.4,   # memory leak
}


def impact_from_cwe(cwe: str | None) -> float:
    return _IMPACT_BY_CWE.get((cwe or "").upper(), 0.4)


def estimated_cost(function_source: str | None) -> float:
    """Resource-cost proxy from function size (plan §11.5: a proxy, not a profiler)."""
    if not function_source:
        return 1.0
    lines = len(function_source.splitlines())
    return max(0.5, min(3.0, lines / 40.0 + 0.5))


def priority(confidence: float, reachability: float, impact: float, cost: float) -> float:
    """plan §11.5: confidence * reachability * impact / estimated_resource_cost."""
    return (confidence * reachability * impact) / max(cost, 0.01)


def prescore(finding: dict, snapshot_dir: str, entry_point: str,
            call_graph: dict[str, set[str]] | None = None) -> dict:
    """Model-free first pass: impact x reachability / cost."""
    function = code_context.extract_function(finding["file"], finding.get("line", 1))
    impact = impact_from_cwe(finding.get("cwe"))
    reach = code_context.reachability_score(
        snapshot_dir, entry_point, finding.get("function", "unknown"), graph=call_graph)
    cost = estimated_cost(function["source"] if function else None)
    return {
        "finding": finding,
        "function": function,
        "impact": impact,
        "reachability": reach,
        "cost": cost,
        "prescore": priority(1.0, reach, impact, cost),
    }


def rank(findings: list[dict], snapshot_dir: str, entry_point: str, top_n: int) -> list[dict]:
    """Cheap-score every finding, return the top_n worth an LLM triage call.

    Builds the call graph once for the whole batch - see reachability_score's
    docstring for why that matters once `snapshot_dir` is a real codebase.
    """
    call_graph = code_context.build_call_graph(snapshot_dir)
    scored = [prescore(f, snapshot_dir, entry_point, call_graph) for f in findings]
    scored.sort(key=lambda c: c["prescore"], reverse=True)
    return scored[:top_n]


def route(confidence: float) -> str:
    """Confidence-gated funnel thresholds agreed in plan §11.5."""
    if confidence < 0.4:
        return "discard"
    if confidence <= 0.75:
        return "fuzz"
    return "direct_pov"
