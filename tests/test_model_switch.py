"""Live in-console model switcher: list configured model configs and switch the active one
(config + agents + out-dir) with no relaunch."""
from fastapi.testclient import TestClient

from vpcopilot.console import app as A


def _client():
    return TestClient(A.app)


def test_lists_configured_models():
    m = _client().get("/api/models").json()
    tags = {c["tag"]: c["model"] for c in m["configs"]}
    assert "claude" in tags and tags["claude"].startswith("anthropic/")
    assert "openai" in tags and tags["openai"].startswith("openai/")


def test_switch_changes_config_agents_and_outdir():
    c = _client()
    r = c.post("/api/model", json={"tag": "openai"}).json()
    assert r["active"] == "openai" and r["out"] == "out-openai"
    assert c.get("/api/agents").json()["default_model"].startswith("openai/")
    # and the read endpoints now target the switched out dir
    assert c.get("/api/models").json()["out"] == "out-openai"
    # switch back
    r = c.post("/api/model", json={"tag": "claude"}).json()
    assert r["active"] == "claude" and r["out"] == "out-claude"
    assert c.get("/api/agents").json()["default_model"].startswith("anthropic/")


def test_unknown_model_is_rejected():
    assert _client().post("/api/model", json={"tag": "nope"}).status_code == 404


def test_config_tag_derivation():
    assert A._config_tag("config/agents.openai.yaml", "openai/gpt-4.1") == "openai"
    assert A._config_tag("config/agents.dgx.yaml", "ollama/llama3.3") == "dgx"
    assert A._config_tag("config/agents.yaml", "anthropic/claude-opus-4-8") == "claude"
    assert A._config_tag("config/agents.yaml", "openai/gpt-4o") == "openai"
