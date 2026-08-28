"""C source structure helpers (plan §11.4 context assembly, §11.5 reachability).

Deliberately a heuristic scanner, not a real parser: the CRS only needs enough
structure to (a) hand the model one whole function instead of a +/-15-line
window, and (b) answer "is this function reachable from the fuzz entry point".
Both degrade safely — extract_function returns None and reachability returns an
explicit 'unknown' score rather than guessing.
"""
import re
from pathlib import Path

_FUNC_SIG = re.compile(r"^\s*[\w\*\s]+\s+\**(\w+)\s*\([^;]*\)\s*\{?\s*$")
# K&R-style split signature, common throughout libpng and other older C code:
#   void /* PRIVATE */
#   png_handle_iCCP(png_structrp png_ptr, ...)
#   {
# Neither line matches _FUNC_SIG alone - the type has no name+parens on its
# line, and the name+parens line has no type prefix on *its* line.
_FUNC_NAME_ONLY = re.compile(r"^\s*\**(\w+)\s*\([^;]*\)\s*\{?\s*$")
_TYPE_ONLY_LINE = re.compile(r"^\s*[\w\*]+(?:\s+[\w\*]+)*(?:\s*/\*.*?\*/\s*)?$")
# `extern "C"` (any libFuzzer harness's LLVMFuzzerTestOneInput, plus any C
# API exported from C++) has a bare "\"C\"" that [\w\*\s] can't match through,
# so it's stripped before the signature regexes ever see the line.
_EXTERN_C_PREFIX = re.compile(r'^(\s*)extern\s*"C"\s*')
_CALL_LIKE = re.compile(r"\b(\w+)\s*\(")
_KEYWORDS = {"if", "while", "for", "switch", "return", "sizeof", "else", "do",
            # `defined(X)` is a preprocessor operator, not a call - it shows up
            # constantly as its own line on a continued `#if A || \` conditional
            # and would otherwise look exactly like a one-line function signature.
            "defined"}
_C_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"}


_CALL_OPEN = re.compile(r"^\s*\**(\w+)\s*\(")


def _wrapped_params_signature_at(lines: list[str], i: int) -> tuple[int, str] | None:
    """K&R-split signature whose parameter list itself wraps onto further
    lines, e.g. libpng's own style:
        static void
        png_do_quantize(png_row_infop row_info, png_bytep row,
            png_const_bytep palette_lookup, png_const_bytep quantize_lookup)
        {
    _FUNC_NAME_ONLY only matches when "(...)" closes on line i itself; this
    covers the (also common in this codebase) case where it doesn't, which
    otherwise makes the scan skip straight past the real function start and
    misattribute to whatever earlier signature it does recognize.
    """
    text = _EXTERN_C_PREFIX.sub(r"\1", lines[i])
    m = _CALL_OPEN.match(text)
    if not m or m.group(1) in _KEYWORDS:
        return None
    if text.count("(") <= text.count(")"):
        return None  # closes on this line - already handled elsewhere
    depth = text.count("(") - text.count(")")
    j = i + 1
    while j < len(lines) and j < i + 12 and depth > 0:
        depth += lines[j].count("(") - lines[j].count(")")
        j += 1
    if depth != 0 or i == 0:
        return None
    prev = _EXTERN_C_PREFIX.sub(r"\1", lines[i - 1])
    if prev.strip() and _TYPE_ONLY_LINE.match(prev):
        return i - 1, m.group(1)
    return None


def _signature_at(lines: list[str], i: int) -> tuple[int, str] | None:
    """If a function signature ends at line i, return (start_idx, name)."""
    text = _EXTERN_C_PREFIX.sub(r"\1", lines[i])
    match = _FUNC_SIG.match(text)
    if match and match.group(1) not in _KEYWORDS:
        return i, match.group(1)
    name_only = _FUNC_NAME_ONLY.match(text)
    if name_only and name_only.group(1) not in _KEYWORDS and i > 0:
        prev = _EXTERN_C_PREFIX.sub(r"\1", lines[i - 1])
        if prev.strip() and _TYPE_ONLY_LINE.match(prev):
            return i - 1, name_only.group(1)
    return _wrapped_params_signature_at(lines, i)


def _find_signature_line(lines: list[str], line: int) -> tuple[int, str] | None:
    """Scan upward from `line` (1-indexed) for the enclosing function signature.

    Returns (start_idx, name) - start_idx is the return-type line for the
    split K&R style, so a replacement function fully covers the original.
    """
    for i in range(min(line, len(lines)) - 1, -1, -1):
        found = _signature_at(lines, i)
        if found:
            return found
    return None


def _match_brace(lines: list[str], start_idx: int) -> int | None:
    """Return the index of the line closing the first '{' at/after start_idx.

    Tracks string/char literals and both comment styles so braces inside them
    don't skew the depth count.
    """
    depth = 0
    seen_open = False
    in_block_comment = False
    for i in range(start_idx, len(lines)):
        line = lines[i]
        in_str = in_chr = escaped = False
        j = 0
        while j < len(line):
            ch = line[j]
            nxt = line[j + 1] if j + 1 < len(line) else ""
            if in_block_comment:
                if ch == "*" and nxt == "/":
                    in_block_comment = False
                    j += 1
            elif in_str or in_chr:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif in_str and ch == '"':
                    in_str = False
                elif in_chr and ch == "'":
                    in_chr = False
            elif ch == "/" and nxt == "*":
                in_block_comment = True
                j += 1
            elif ch == "/" and nxt == "/":
                break  # rest of the line is a comment
            elif ch == '"':
                in_str = True
            elif ch == "'":
                in_chr = True
            elif ch == "{":
                depth += 1
                seen_open = True
            elif ch == "}":
                depth -= 1
                if seen_open and depth == 0:
                    return i
            j += 1
    return None


def extract_function(file_path: str, line: int) -> dict | None:
    """The whole function enclosing `line`, as exact source plus its line span."""
    try:
        lines = Path(file_path).read_text().splitlines()
    except OSError:
        return None

    found = _find_signature_line(lines, line)
    if found is None:
        return None
    sig_idx, name = found

    brace_idx = next((j for j in range(sig_idx, min(sig_idx + 5, len(lines))) if "{" in lines[j]), None)
    if brace_idx is None:
        return None

    end_idx = _match_brace(lines, brace_idx)
    if end_idx is None:
        return None

    return {
        "name": name,
        "start_line": sig_idx + 1,      # 1-indexed, inclusive
        "end_line": end_idx + 1,        # 1-indexed, inclusive
        "source": "\n".join(lines[sig_idx:end_idx + 1]),
    }


def _iter_sources(root: str):
    for path in sorted(Path(root).rglob("*")):
        if path.is_file() and path.suffix in _C_SUFFIXES:
            yield path


def build_call_graph(root: str) -> dict[str, set[str]]:
    """Map each defined function to the defined functions its body mentions.

    Name-based and therefore over-approximate (a name in a comment counts). That
    is the safe direction here: over-approximating reachability keeps a real
    candidate in the funnel, it never silently drops one.
    """
    bodies: dict[str, str] = {}
    for path in _iter_sources(root):
        try:
            lines = path.read_text().splitlines()
        except OSError:
            continue
        for i in range(len(lines)):
            found = _signature_at(lines, i)
            if found is None:
                continue
            sig_idx, name = found
            brace_idx = next((j for j in range(sig_idx, min(sig_idx + 5, len(lines))) if "{" in lines[j]), None)
            if brace_idx is None:
                continue
            end_idx = _match_brace(lines, brace_idx)
            if end_idx is None:
                continue
            bodies[name] = "\n".join(lines[brace_idx:end_idx + 1])

    # One regex pass per body (identifiers immediately followed by '(') instead of
    # one search per (function, other-function) pair - O(n) instead of O(n^2) in
    # the number of functions, which matters once this is hundreds of real
    # functions rather than the handful in a toy target.
    defined = set(bodies)
    graph: dict[str, set[str]] = {}
    for name, body in bodies.items():
        called_names = set(_CALL_LIKE.findall(body))
        called_names.discard(name)
        graph[name] = called_names & defined
    return graph


def reachability_score(root: str, entry: str, target: str,
                       graph: dict[str, set[str]] | None = None) -> float:
    """1.0 reachable from the fuzz entry point, 0.15 provably not, 0.5 unknown.

    'Unknown' (entry or target absent from the graph) must not score 0 — that
    would let a parser limitation silently discard a real finding.

    Building the call graph means scanning every source file under `root`, so
    callers scoring multiple findings against the same root should build it
    once with build_call_graph() and pass it in here rather than let each
    call rebuild it - on a real codebase (as opposed to the tiny demo target)
    that's the difference between one scan and one scan per finding.
    """
    if not target or target == "unknown":
        return 0.5
    if graph is None:
        graph = build_call_graph(root)
    if entry not in graph or target not in graph:
        return 0.5
    if entry == target:
        return 1.0

    seen = {entry}
    queue = [entry]
    while queue:
        current = queue.pop()
        for callee in graph.get(current, ()):
            if callee == target:
                return 1.0
            if callee not in seen:
                seen.add(callee)
                queue.append(callee)
    return 0.15
