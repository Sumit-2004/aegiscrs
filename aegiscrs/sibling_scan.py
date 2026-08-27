"""Sibling-bug sweep (selection-strategy differentiator: "the target tells us
where else it's weak").

Semgrep already scans every path in `static_analysis_paths`, not just the one
function that ends up confirmed - `target_selector.rank` just keeps the top_n
and silently discards the rest once one candidate is picked. On a real legacy
C codebase, a confirmed instance of "unchecked length used as a copy size" or
"use after free on this ownership pattern" is rarely unique: the same authors
usually wrote the same mistake more than once. This module makes that discard
pile visible instead of throwing it away.

Deliberately not a new capability: no new Semgrep run, no model call, no new
scoring model. It re-applies the exact same deterministic prescore
(impact x reachability / cost) the primary candidate was ranked with, to every
other finding that shares the confirmed bug's rule id. The model never sees
this list and never ranks it - it's the funnel's own math, applied twice.
"""
from . import code_context, target_selector


def find_siblings(all_findings: list[dict], confirmed_finding: dict, snapshot_dir: str,
                  entry_point: str, call_graph: dict[str, set[str]] | None = None) -> list[dict]:
    """Other findings sharing the confirmed bug's Semgrep rule id, ranked by prescore.

    These are reported as unpatched candidates, never auto-patched - the funnel
    only ever confirms and fixes the one selected finding per campaign. Surfacing
    siblings is a triage aid for a human reviewer, not a second accept/reject loop.
    """
    siblings = [
        f for f in all_findings
        if f.get("category") == confirmed_finding.get("category")
        and f.get("id") != confirmed_finding.get("id")
    ]
    if not siblings:
        return []

    if call_graph is None:
        call_graph = code_context.build_call_graph(snapshot_dir)

    scored = [target_selector.prescore(f, snapshot_dir, entry_point, call_graph) for f in siblings]
    scored.sort(key=lambda c: c["prescore"], reverse=True)
    return [
        {
            "finding_id": s["finding"]["id"],
            "file": s["finding"]["file"],
            "line": s["finding"]["line"],
            "function": s["finding"].get("function", "unknown"),
            "cwe": s["finding"]["cwe"],
            "category": s["finding"]["category"],
            "reachability": s["reachability"],
            "impact": s["impact"],
            "prescore": s["prescore"],
            "status": "unpatched-candidate",
        }
        for s in scored
    ]
