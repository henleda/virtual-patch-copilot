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
    temperature: float = 0.1
    max_retries: int = 3


@dataclass
class Config:
    defaults: AgentConfig
    agents: dict[str, AgentConfig]

    def for_agent(self, name: str) -> AgentConfig:
        return self.agents.get(name, self.defaults)


def _agent_from(d: dict, fallback: AgentConfig) -> AgentConfig:
    return AgentConfig(
        model=d.get("model", fallback.model),
        temperature=d.get("temperature", fallback.temperature),
        max_retries=d.get("max_retries", fallback.max_retries),
    )


def load_config(path: str | None = None) -> Config:
    path = Path(path or os.environ.get("VPCOPILOT_CONFIG", "config/agents.yaml"))
    data = yaml.safe_load(path.read_text()) if path.exists() else {}
    d = (data or {}).get("defaults", {})
    defaults = AgentConfig(
        model=d.get("model", DEFAULT_MODEL),
        temperature=d.get("temperature", 0.1),
        max_retries=d.get("max_retries", 3),
    )
    agents = {
        name: _agent_from(a or {}, defaults)
        for name, a in ((data or {}).get("agents") or {}).items()
    }
    return Config(defaults=defaults, agents=agents)
