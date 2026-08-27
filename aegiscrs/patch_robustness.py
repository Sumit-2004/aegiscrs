from pathlib import Path

from . import fuzzer, llm_client, pov_validator, variant_mutator


def check(patched_binary: str, finding: dict, patch_diff: str, original_pov_path: str,
          work_dir: str, variant_count: int = 6, fuzz_reseed_seconds: int = 15,
          isolation: dict | None = None) -> dict:
    """plan §11.11: does the patch generalize, or does it just dodge the one reported PoV?
    Decision is always a real binary crashing or not — the LLM only proposes what to try."""
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    original_pov = Path(original_pov_path).read_bytes()

    hypothesis = llm_client.propose_boundary_hypothesis(finding, patch_diff, original_pov)
    variants = variant_mutator.generate_variants(original_pov, hypothesis, count=variant_count)

    tested = []
    any_break = False
    for i, variant in enumerate(variants):
        variant_path = work_dir / f"variant_{i:02d}.bin"
        variant_path.write_bytes(variant["bytes"])
        crashed = pov_validator.reproduces(patched_binary, str(variant_path), isolation)
        tested.append({
            "source": variant["source"],
            "description": variant["description"],
            "bytes_hex": variant["bytes"].hex(),
            "crashed": crashed,
        })
        any_break = any_break or crashed

    fuzz_reseed = None
    if not any_break:
        corpus_dir = work_dir / "reseed_corpus"
        corpus_dir.mkdir(parents=True, exist_ok=True)
        (corpus_dir / "seed_original.bin").write_bytes(original_pov)
        for i, variant in enumerate(variants):
            (corpus_dir / f"seed_variant_{i:02d}.bin").write_bytes(variant["bytes"])
        artifact_prefix = str(work_dir / "reseed_crash_")
        fuzz_reseed = fuzzer.run_campaign(patched_binary, str(corpus_dir), fuzz_reseed_seconds,
                                          artifact_prefix, isolation)
        any_break = any_break or fuzz_reseed["found_crash"]

    return {
        "hypothesis": hypothesis,
        "variants": tested,
        "fuzz_reseed": fuzz_reseed,
        "generalizes": not any_break,
    }
