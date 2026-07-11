"""The model-independent agent harness.

One harness, many providers. We use LiteLLM as the transport (Anthropic, OpenAI,
Gemini, Bedrock, Azure, vLLM, Ollama, ... behind one call) and `instructor` for
structured output (JSON Schema + validate-and-repair) so every agent returns a typed
Pydantic object the same way on every model — including weaker/local models that lack
a native JSON mode. The agent code never sees a provider-specific detail; the model is
chosen per agent from config (see config.py)."""
from __future__ import annotations

from typing import Type, TypeVar

from pydantic import BaseModel

from .config import Config, load_config

T = TypeVar("T", bound=BaseModel)


class Harness:
    def __init__(self, config_path: str | None = None):
        self.cfg: Config = load_config(config_path)
        # Imported lazily so `--help`, config loading, and tests don't require the
        # LLM stack (or API keys) to be installed/set.
        import instructor
        import litellm
        from litellm import completion

        # Model-independence: silently drop params a given model rejects (e.g. some
        # reasoning models only allow temperature=1) instead of erroring.
        litellm.drop_params = True
        self._client = instructor.from_litellm(completion)

    def run(self, agent: str, system: str, user: str, response_model: Type[T], **overrides) -> T:
        ac = self.cfg.for_agent(agent)
        return self._client.chat.completions.create(
            model=overrides.get("model", ac.model),
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            response_model=response_model,
            temperature=overrides.get("temperature", ac.temperature),
            max_retries=ac.max_retries,
            timeout=overrides.get("timeout", ac.timeout),  # B6: per-call wall-clock cap
        )

    def warmup(self) -> None:
        """B6: warm instructor's mode-registry (its lazy first-call init isn't thread-safe) with a
        single throwaway call, so the parallel discover/verify fan-out doesn't race it. Best-effort:
        a failure here (no key, offline) shouldn't abort the run — the first real call will surface it."""
        from pydantic import BaseModel

        class _Ping(BaseModel):
            ok: bool

        try:
            self.run("_warmup", "Reply with ok=true.", "ok", _Ping, timeout=30)
        except Exception:  # noqa: BLE001
            pass
