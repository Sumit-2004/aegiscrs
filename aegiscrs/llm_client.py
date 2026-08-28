import json
import os
import re

# litellm otherwise fetches its model-pricing map from GitHub on first use - a real
# network call this offline-by-default project must never make, regardless of whether
# a run happens to need pricing info. Must be set before litellm's import in _complete().
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

MOCK_MODE = os.environ.get("MOCK_LLM", "1") == "1"

_MOCK_FIXED_FUNCTION = """int parse_packet(const unsigned char *data, size_t size, char *out, size_t out_cap) {
    if (size < 1) {
        return -1;
    }
    unsigned char len = data[0];
    if (size < (size_t)len + 1) {
        return -1;
    }
    if ((size_t)len > out_cap) {
        return -1;
    }
    memcpy(out, data + 1, len);
    return (int)len;
}"""

_LIBPNG_ICCP_BUG = "read_length = sizeof(keyword); /* maximum */"
_LIBPNG_ICCP_FIX = "read_length = max_keyword_wbytes; /* maximum */"

# BUILD-BRIEF Phase 6: second target, different CWE class (use-after-free,
# CWE-416, vs. Phase 3/4's stack overflow). Also the staged rejection demo -
# MOCK_LLM_OVERFIT=1 drafts a patch that special-cases the exact PoV bytes
# instead of fixing the root cause, for patch_robustness.py to catch.
_UAF_MARKER = "process_session"
_UAF_BUG = """} else if (op == 1) {
            free(s);
            /* BUG: s is left dangling instead of being reset to NULL, so the
               s != NULL guard below still passes after this point. */
        }"""
_UAF_FIX = """} else if (op == 1) {
            free(s);
            s = NULL;
        }"""
_UAF_SIGNATURE = "void process_session(const unsigned char *data, size_t size) {"


def _uaf_overfit_guard(pov_bytes: bytes) -> str:
    """An exact match on the real, actually-discovered PoV - not a guessed
    shape. libFuzzer doesn't reliably find the same minimal crasher byte-for-
    byte between runs, so anything less than the real bytes would make this
    demo fragile. Any single-byte difference (a bit flip, a truncation, an
    appended byte) fails this condition and falls through to the still-buggy
    code beneath it - that's what patch_robustness.py's generic mutations are
    expected to catch.
    """
    conditions = " && ".join(
        [f"size == {len(pov_bytes)}"] + [f"data[{i}] == {b}" for i, b in enumerate(pov_bytes)])
    return f"{_UAF_SIGNATURE}\n    if ({conditions}) {{\n        return;\n    }}"

# BUILD-BRIEF Phase 4 mock harnesses. Deliberately NOT a copy of any harness
# already shipped with a target (that would just be "restore the deleted
# file", not synthesis) - independently written, plain-C entry points that
# still drive far enough into each target's real API to reach the bug.
_MOCK_LIBPNG_HARNESS = """#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <setjmp.h>
#include "png.h"

typedef struct { const uint8_t *data; size_t left; } aegis_read_state;

static void aegis_read_fn(png_structp png_ptr, png_bytep out, size_t n) {
    aegis_read_state *st = (aegis_read_state *)png_get_io_ptr(png_ptr);
    if (n > st->left) {
        png_error(png_ptr, "eof");
    }
    memcpy(out, st->data, n);
    st->data += n;
    st->left -= n;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8 || png_sig_cmp((png_bytep)(png_const_bytep)data, 0, 8)) {
        return 0;
    }

    png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr) {
        return 0;
    }
    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_read_struct(&png_ptr, NULL, NULL);
        return 0;
    }

    if (setjmp(png_jmpbuf(png_ptr))) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return 0;
    }

    aegis_read_state st = { data + 8, size - 8 };
    png_set_read_fn(png_ptr, &st, aegis_read_fn);
    png_set_sig_bytes(png_ptr, 8);

    png_read_info(png_ptr, info_ptr);

    png_uint_32 width, height;
    int bit_depth, color_type, interlace, compression, filter;
    if (png_get_IHDR(png_ptr, info_ptr, &width, &height, &bit_depth, &color_type,
                      &interlace, &compression, &filter)) {
        png_bytep row = (png_bytep)png_malloc(png_ptr, png_get_rowbytes(png_ptr, info_ptr));
        for (png_uint_32 y = 0; y < height; y++) {
            png_read_row(png_ptr, row, NULL);
        }
        png_free(png_ptr, row);
    }

    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    return 0;
}
"""

_MOCK_DEMO_HARNESS = """#include <stdint.h>
#include <stddef.h>
#include "vulnerable/parser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char out[16];
    parse_packet(data, size, out, sizeof(out));
    return 0;
}
"""


def _complete(prompt: str) -> str:
    import litellm

    api_base = os.environ.get("AEGIS_LLM_API_BASE")
    if not api_base:
        # Placeholder guard, not a real integration gap: AegisCRS never installs or
        # bundles a model. The real model runs on whatever machine executes this
        # (BUILD-BRIEF Phase 1) - point AEGIS_LLM_API_BASE at a local OpenAI-compatible
        # endpoint, e.g. Ollama's http://localhost:11434/v1 after
        # `ollama pull qwen2.5-coder:7b-instruct`. See config/MODEL_SETUP.md.
        raise RuntimeError(
            "MOCK_LLM=0 but AEGIS_LLM_API_BASE is not set - no local model endpoint "
            "configured. See config/MODEL_SETUP.md for the one-time setup on this "
            "machine (Ollama install + model pull + env vars). AegisCRS itself never "
            "downloads or runs a model."
        )
    # litellm needs a provider prefix to route to a custom OpenAI-compatible
    # endpoint (bare model names raise "LLM Provider NOT provided"), and Ollama's
    # endpoint requires the model field to match an actually-pulled model name.
    model = os.environ.get("AEGIS_LLM_MODEL", "qwen2.5-coder:7b-instruct-q4_K_M")
    # Ollama's OpenAI-compatible endpoint defaults to a 4096-token context window,
    # which a several-hundred-line function (plus prompt overhead) can exceed on its
    # own - the request then gets front-truncated, silently dropping earlier prompt
    # content. 8192 covers every function in this repo's targets with headroom; raise
    # it further (VRAM permitting) before pointing this at a codebase with larger
    # functions than that.
    num_ctx = int(os.environ.get("AEGIS_LLM_NUM_CTX", "8192"))
    response = litellm.completion(
        model=f"openai/{model}",
        messages=[{"role": "user", "content": prompt}],
        api_base=api_base,
        api_key=os.environ.get("AEGIS_LLM_API_KEY", "unused"),
        extra_body={"options": {"num_ctx": num_ctx}},
    )
    return response["choices"][0]["message"]["content"]


def triage(finding: dict, function_source: str) -> dict:
    if MOCK_MODE:
        return {
            "confidence": 0.9,
            "root_cause": (
                f"{finding.get('function', '?')} copies an attacker-controlled length byte "
                "into a fixed-size buffer without checking it against the destination "
                "capacity (mock triage — no live model configured, see plan §5.1)."
            ),
            "cwe": finding.get("cwe", "CWE-787"),
        }
    return _parse_triage_response(_complete(_triage_prompt(finding, function_source)), finding)


def draft_function_fix(finding: dict, function_source: str, crash_report: str,
                       attempt: int = 1, previous_attempt: dict | None = None,
                       pov_bytes: bytes | None = None) -> dict:
    """Return a whole corrected function, NOT a diff (plan §11.8).

    The harness computes the unified diff itself via patch_generator.build_diff,
    so the model is never asked to produce hunk headers or line arithmetic — the
    thing small quantized models get wrong most often. A patch that fails to
    apply is then a real defect, not a formatting artifact.

    `attempt`/`previous_attempt` back the bounded retry loop (BUILD-BRIEF Phase 2):
    on retries the model is re-prompted with the specific reason its last function
    was rejected, never asked to grade its own previous attempt.
    """
    if MOCK_MODE:
        fail_until = int(os.environ.get("MOCK_LLM_FAIL_ATTEMPTS", "0"))
        if attempt <= fail_until:
            # Deterministic, opt-in failure for exercising the retry loop without a
            # live model: returns the function unchanged, which build_diff rejects.
            return {
                "function_source": function_source,
                "explanation": (
                    f"(mock forced failure: attempt {attempt} of {fail_until}, "
                    "see MOCK_LLM_FAIL_ATTEMPTS / BUILD-BRIEF Phase 2)"
                ),
                "expected_property": "",
            }
        if _LIBPNG_ICCP_BUG in function_source:
            # BUILD-BRIEF Phase 3: same one-line fix AIxCC's own good_patch.diff
            # applies. Derived from whatever function_source the orchestrator
            # actually extracted (not a hardcoded copy of the function), so this
            # still exercises the real diff-construction path end to end.
            return {
                "function_source": function_source.replace(_LIBPNG_ICCP_BUG, _LIBPNG_ICCP_FIX, 1),
                "explanation": (
                    "sizeof(keyword) is a byte count, but keyword_length indexes keyword "
                    "as an array of 2-byte elements; use the element count "
                    "(max_keyword_wbytes) instead (mock patch — no live model configured, "
                    "see plan §5.1)."
                ),
                "expected_property": "keyword_length never indexes past keyword's 41 valid elements.",
            }
        if _UAF_MARKER in function_source:
            if os.environ.get("MOCK_LLM_OVERFIT") == "1" and pov_bytes:
                # BUILD-BRIEF Phase 6 staged rejection demo: special-cases the
                # exact PoV bytes instead of fixing the root cause. Any variant
                # that isn't byte-for-byte identical still crashes -
                # patch_robustness.py's generic mutations (e.g. append one
                # byte) are expected to catch this and the gate to reject it.
                guard = _uaf_overfit_guard(pov_bytes)
                return {
                    "function_source": function_source.replace(_UAF_SIGNATURE, guard, 1),
                    "explanation": (
                        "(mock OVERFIT patch for the Phase 6 rejection demo - special-cases "
                        "the reported crashing input instead of fixing the free()/NULL bug, "
                        "see MOCK_LLM_OVERFIT)"
                    ),
                    "expected_property": "the exact reported input no longer crashes.",
                }
            return {
                "function_source": function_source.replace(_UAF_BUG, _UAF_FIX, 1),
                "explanation": (
                    "free(s) in the close branch never resets s to NULL, so the s != NULL "
                    "guard on the write path still passes after the session is freed; set "
                    "s = NULL right after freeing it (mock patch — no live model configured, "
                    "see plan §5.1)."
                ),
                "expected_property": "no read or write of s after it has been freed.",
            }
        return {
            "function_source": _MOCK_FIXED_FUNCTION,
            "explanation": (
                "Reject packets whose declared length exceeds the caller-provided output "
                "capacity before copying (mock patch — no live model configured, see plan §5.1)."
            ),
            "expected_property": "No write past the end of `out` regardless of the length byte.",
        }
    prompt = _patch_prompt(finding, function_source, crash_report, previous_attempt)
    return _parse_function_response(_complete(prompt))


def draft_harness(candidate: dict, includes: list[str], previous_error: str | None = None) -> str:
    """Draft an LLVMFuzzerTestOneInput in C (BUILD-BRIEF Phase 4).

    Returns raw source text, not a dict - harness_synth.py writes it straight
    to disk and lets the compiler decide if it was any good. `candidate` is a
    hint (a buffer+length-shaped declaration found in the target's headers),
    not a contract: a real model, like a human, may reasonably use broader
    knowledge of the target's API instead of literally wrapping that one
    function, same as the mock branches below do.
    """
    if MOCK_MODE:
        header_hint = " ".join(includes) + " " + candidate.get("header", "") + " " + candidate.get("name", "")
        if "png" in header_hint.lower():
            return _MOCK_LIBPNG_HARNESS
        if "parser" in header_hint.lower() or candidate.get("name") == "parse_packet":
            return _MOCK_DEMO_HARNESS
        # Unknown target: best-effort generic wrapper around the one candidate
        # found. Honest fallback, not guaranteed to compile or reach anything -
        # a real model would need actual target knowledge here too.
        return (
            f'#include <stddef.h>\n#include <stdint.h>\n#include "{candidate.get("header", "target.h")}"\n\n'
            f'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{\n'
            f'    {candidate.get("name", "target_entry")}(data, size);\n'
            f'    return 0;\n}}\n'
        )
    return _complete(_harness_prompt(candidate, includes, previous_error))


def propose_boundary_hypothesis(finding: dict, patch_diff: str, pov_bytes: bytes) -> dict:
    """plan §11.11 tier 1: the model names input dimensions/boundaries to check,
    it never produces raw bytes itself — that's the deterministic mutator's job."""
    if MOCK_MODE:
        return {
            "offset": 0,
            "boundary_values": [14, 15, 16, 17, 18, 0, 255],
            "rationale": (
                "byte 0 is the length prefix compared against out_cap in the new guard "
                "(mock hypothesis — no live model configured, see plan §5.1)."
            ),
        }
    return _parse_boundary_response(_complete(_boundary_prompt(finding, patch_diff, pov_bytes)))


def _triage_prompt(finding: dict, function_source: str) -> str:
    # The format instruction is repeated *after* the function source, not just before
    # it: a small model's instruction-following degrades over a long code block (a
    # multi-hundred-line function can run several thousand tokens), and an instruction
    # placed only at the start reliably gets dropped in favor of the model's default
    # "explain this code" behavior once enough code has gone by. Recency placement
    # fixes this in practice (confirmed against zlib's ~650-line inflate()).
    return (
        "You are a security triage assistant. You are given ONE static-analysis finding "
        "and the source of the function containing the flagged line."
        "\n\nFinding:\n" + json.dumps(finding, indent=2) +
        "\n\nFunction:\n" + function_source +
        '\n\nRespond with ONLY a JSON object of the form {"confidence": <0..1>, '
        '"root_cause": "<one paragraph>", "cwe": "<CWE-id>"}. Output nothing before or '
        "after the JSON object.\n"
    )


def _patch_prompt(finding: dict, function_source: str, crash_report: str,
                  previous_attempt: dict | None = None) -> str:
    retry_block = ""
    if previous_attempt:
        retry_block = (
            "\n\nYour previous attempt was rejected: " + previous_attempt["failure_reason"] +
            "\n\nYour previous attempt:\n```c\n" + previous_attempt["function_source"] + "\n```\n"
            "Produce a corrected function that fixes this specific problem while still fixing "
            "the original vulnerability described below.\n"
        )
    # Instructions repeated after the function source, not just before it - same
    # reasoning as _triage_prompt: a long function pushes an instruction-only-at-the-
    # start out of effective attention for a small model.
    return (
        "You are a security patch assistant. Below is one whole C function containing a "
        "vulnerability, plus the sanitizer report from a confirmed crash."
        + retry_block +
        "\n\nFinding:\n" + json.dumps(finding, indent=2) +
        "\n\nVulnerable function:\n```c\n" + function_source + "\n```\n\n"
        "Crash report:\n" + crash_report + "\n\n"
        "Return the COMPLETE corrected function - the entire function from its return type "
        "through its closing brace - inside a single ```c fence. Output nothing else.\n\n"
        "Rules: make the smallest change that fixes the root cause. Keep the signature, the "
        "name, and all existing behaviour for valid inputs identical. Do not add comments "
        "about the fix. Do not weaken or remove any existing check. Do not write a diff, a "
        "patch, or line numbers - return plain function source."
    )


def _harness_prompt(candidate: dict, includes: list[str], previous_error: str | None) -> str:
    retry_block = ""
    if previous_error:
        retry_block = "\n\nYour previous attempt failed:\n" + previous_error + "\nFix this specific problem.\n"
    return (
        "You are a fuzzing engineer. Write a single C (or C++) source file defining "
        "`LLVMFuzzerTestOneInput` (libFuzzer's entry point) for the target library below. "
        "Use the target's real public API to parse the input bytes as deeply as realistically "
        "possible - do not just call one function and return. Output ONLY the source code, "
        "no explanation, no markdown fences.\n\n"
        f"Available headers to #include: {', '.join(includes)}\n\n"
        "A representative buffer+length-shaped entry point found in the headers "
        "(a hint, not a requirement - use whatever real API calls are appropriate):\n"
        f"  {candidate.get('return_type', '')} {candidate.get('name', '')}({candidate.get('params', '')});\n"
        + retry_block
    )


def _boundary_prompt(finding: dict, patch_diff: str, pov_bytes: bytes) -> str:
    return (
        "You are a security test-design assistant. A patch was just applied for the "
        "finding below. You do NOT produce test inputs yourself - you only name which "
        "byte offset the fix's boundary condition depends on and which boundary values "
        "are worth checking near it. Respond ONLY with JSON of the form "
        '{"offset": <int>, "boundary_values": [<int>, ...], "rationale": "<one sentence>"}.'
        "\n\nFinding:\n" + json.dumps(finding, indent=2) +
        "\n\nPatch diff:\n" + patch_diff +
        "\n\nOriginal crashing input (hex): " + pov_bytes.hex() + "\n"
    )


def _parse_triage_response(text: str, finding: dict) -> dict:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    return {"confidence": 0.0, "root_cause": "unparseable model response", "cwe": finding.get("cwe", "CWE-unknown")}


def _parse_function_response(text: str) -> dict:
    match = re.search(r"```(?:[cC]|cpp)?\n(.*?)```", text, re.DOTALL)
    function_source = match.group(1) if match else text
    return {"function_source": function_source.strip(), "explanation": text, "expected_property": ""}


def _parse_boundary_response(text: str) -> dict:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    return {"offset": 0, "boundary_values": [], "rationale": "unparseable model response"}
