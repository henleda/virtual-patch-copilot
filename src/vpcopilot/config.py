"""Per-agent model registry. This is the heart of model-independence: every agent's
model (and sampling/retry params) is chosen here, so a customer swaps Claude / OpenAI /
Gemini / Ollama per-agent or globally by editing config/agents.yaml — no code change."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml

DEFAULT_MODEL = "anthropic/claude-opus-4-8"


@dataclass
class AgentConfig:
    model: str
    temperature: float | None = 0.1  # None (yaml `temperature: null`) = omit it (some models reject it)
    max_retries: int = 3
    timeout: int = 120  # B6: per-LLM-call wall-clock cap (seconds) so one hung call can't stall a scan
    # OpenAI-compatible endpoint override (e.g. a local Ollama/vLLM server at http://host:11434/v1).
    # Set per-config, NOT via a global OPENAI_API_BASE env var, so pointing one model config at a local
    # server can't silently redirect another config's real OpenAI calls to it.
    api_base: str | None = None
    api_key: str | None = None  # dummy for local servers (e.g. "ollama"); keeps them off the global key


@dataclass
class Config:
    defaults: AgentConfig
    agents: dict[str, AgentConfig]
    # instructor structured-output mode (tools|json|md_json|json_schema). None → instructor's default
    # (tool-calling). Some local models can't do reliable tool-calling and need json/md_json instead.
    mode: str | None = None

    def for_agent(self, name: str) -> AgentConfig:
        return self.agents.get(name, self.defaults)


def _agent_from(d: dict, fallback: AgentConfig) -> AgentConfig:
    return AgentConfig(
        model=d.get("model", fallback.model),
        temperature=d.get("temperature", fallback.temperature),
        max_retries=d.get("max_retries", fallback.max_retries),
        timeout=d.get("timeout", fallback.timeout),
        api_base=d.get("api_base", fallback.api_base),
        api_key=d.get("api_key", fallback.api_key),
    )


def load_config(path: str | None = None) -> Config:
    path = Path(path or os.environ.get("VPCOPILOT_CONFIG", "config/agents.yaml"))
    data = yaml.safe_load(path.read_text()) if path.exists() else {}
    data = data or {}
    d = data.get("defaults", {})
    defaults = AgentConfig(
        model=d.get("model", DEFAULT_MODEL),
        temperature=d.get("temperature", 0.1),
        max_retries=d.get("max_retries", 3),
        timeout=d.get("timeout", 120),
        api_base=d.get("api_base"),
        api_key=d.get("api_key"),
    )
    agents = {
        name: _agent_from(a or {}, defaults)
        for name, a in (data.get("agents") or {}).items()
    }
    # `mode` may sit under defaults: or at the top level; defaults wins if both are set.
    mode = d.get("mode") or data.get("mode")
    return Config(defaults=defaults, agents=agents, mode=mode)
