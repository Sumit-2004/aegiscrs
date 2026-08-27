# Local model setup (BUILD-BRIEF Phase 1)

AegisCRS never installs, downloads, or bundles a model itself — that's
deliberate (invariant §2.3: offline by default, nothing fetched at run time).
This is a placeholder for whoever runs the real demo to fill in on their own
machine. Do this once, on the machine that will actually run the pipeline
with `MOCK_LLM=0`:

1. Install Ollama: https://ollama.com/download (Linux/WSL2).
2. Pull the model:
   ```
   ollama pull qwen2.5-coder:7b-instruct-q4_K_M
   ```
   Target hardware: 8 GB VRAM laptop GPU (e.g. RTX 5050 Ti class), 16 GB
   system RAM, Ryzen 9 HX. Q4_K_M weights for this model are ~4.7 GB, which
   leaves headroom on an 8 GB card for KV cache at the context lengths
   AegisCRS actually sends (a function + surrounding context + prompt
   template, well under 8K tokens) — it does not need the ~12 GB this doc
   previously assumed. Do not go up to a 14B-class model on 8 GB VRAM: Q4_K_M
   at 14B is ~9 GB of weights alone, which forces CPU-layer offload and risks
   demo timeouts.

   **[UNCONFIRMED — verify on the actual laptop before Phase 1 sign-off]**
   the above is a sizing estimate, not a measured result. Once run for real,
   replace this note with the actual `ollama ps` VRAM figure and real
   per-request latency, per the "never claim unmeasured numbers" rule
   (BUILD-BRIEF invariant / selection-strategy §9).

   Confirm it serves an OpenAI-compatible endpoint:
   ```
   curl http://localhost:11434/v1/models
   ```
3. Point AegisCRS at it:
   ```
   export MOCK_LLM=0
   export AEGIS_LLM_API_BASE=http://localhost:11434/v1
   export AEGIS_LLM_API_KEY=unused
   ```
   If Ollama runs on Windows and AegisCRS runs inside WSL2, use the Windows
   host's IP instead of `localhost` (`ip route | grep default` from WSL2
   gives it).
4. Run the pipeline as usual:
   ```
   python -m aegiscrs.orchestrate config/target.example.yaml
   ```

If `AEGIS_LLM_API_BASE` is unset while `MOCK_LLM=0`, `llm_client.py` fails
immediately with a message pointing back here — it does not silently fall
back to the mock or guess an endpoint.

Until this is done, leave `MOCK_LLM=1` (the default) and the pipeline runs
end-to-end against the fixed mock triage/patch/hypothesis responses in
`llm_client.py`, which is what every current test and demo run uses.
