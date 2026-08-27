def generate_variants(original_pov: bytes, hypothesis: dict, count: int = 6) -> list[dict]:
    """plan §11.11 tier 2: turns the LLM's boundary hypothesis into concrete byte
    variants, plus a generic mutation pass that doesn't depend on the LLM at all."""
    offset = hypothesis.get("offset", 0)
    boundary_values = hypothesis.get("boundary_values", [])[:count]

    variants = []
    if offset < len(original_pov):
        for value in boundary_values:
            mutated = bytearray(original_pov)
            mutated[offset] = value & 0xFF
            variants.append({
                "bytes": bytes(mutated),
                "source": "llm-hypothesis",
                "description": f"byte[{offset}] = {value}",
            })

    remaining = max(0, count - len(variants))
    variants.extend(_generic_mutations(original_pov, offset)[:remaining])
    return variants


def _generic_mutations(original_pov: bytes, offset: int) -> list[dict]:
    if not original_pov:
        return []
    idx = min(offset, len(original_pov) - 1)
    mutations = []
    for bit in (0, 7):
        mutated = bytearray(original_pov)
        mutated[idx] ^= 1 << bit
        mutations.append({
            "bytes": bytes(mutated),
            "source": "generic-mutation",
            "description": f"bit-flip offset {idx} bit {bit}",
        })
    mutations.append({
        "bytes": original_pov + b"\x00",
        "source": "generic-mutation",
        "description": "append null byte",
    })
    if len(original_pov) > 1:
        mutations.append({
            "bytes": original_pov[:-1],
            "source": "generic-mutation",
            "description": "truncate last byte",
        })
    return mutations
