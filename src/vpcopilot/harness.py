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

# Config `mode` string -> instructor.Mode attribute name. instructor's default (no mode) is
# tool-calling, which frontier models do well; some local models emit malformed tool calls and
# need a JSON mode instead (json = response_format json_object; md_json = ask-for-markdown-JSON,
# the most universally compatible fallback since it needs no server-side structured-output support).
_MODES = {
    "tools": "TOOLS",
    "json": "JSON",
    "md_json": "MD_JSON",
    "json_schema": "JSON_SCHEMA",
    "tools_strict": "TOOLS_STRICT",
}


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
        mode = self._resolve_mode(instructor)
        self._client = (
            instructor.from_litellm(completion, mode=mode) if mode is not None
            else instructor.from_litellm(completion)
        )

    def _resolve_mode(self, instructor):
        name = (self.cfg.mode or "").strip().lower()
        if not name:
            return None
        key = _MODES.get(name)
        if key is None:
            raise ValueError(
                f"unknown instructor mode {self.cfg.mode!r}; choose one of {sorted(_MODES)}"
            )
        return getattr(instructor.Mode, key)

    def run(self, agent: str, system: str, user: str, response_model: Type[T], **overrides) -> T:
        ac = self.cfg.for_agent(agent)
        extra = {}
        if ac.api_base:  # OpenAI-compatible endpoint override (local Ollama/vLLM) — per-call, not global
            extra["api_base"] = ac.api_base
        if ac.api_key:
            extra["api_key"] = ac.api_key
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
            **extra,
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
