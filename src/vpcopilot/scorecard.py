"""G4 — the published model scorecard.

`vpcopilot bench --all-configs` runs the same scan and the same answer key through every
`config/agents*.yaml` and writes one committed `benchmarks/RESULTS.md`. That table is the evidence
for the headline claim: swap the model in config, change no code, and the pipeline still works.

Two things this deliberately does NOT do.

It does not claim reproducibility. The roadmap's acceptance asked that re-running with the same seed
reproduce the score; that is not achievable across these four providers — Anthropic accepts no seed
at all, and none of them guarantee determinism even with one. The table states the run date and
says scores move between runs, which is the honest version of that criterion.

It does not report token cost. Nothing in `harness.py` counts tokens, and the decision of
2026-07-27 was that a cost column is not worth threading through every agent call."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

# Column order is the reading order of a model comparison: did it find the vulns, was what it
# reported real, did it route them correctly, what did it cost in time.
COLUMNS = [
    ("recall", "discovery recall", lambda s: f"{s.get('found', 0)}/{s.get('expected', 0)}"
     f" = {s.get('discovery_recall', 0):.2f}"),
    ("precision", "verify precision", lambda s: f"{s.get('verify_precision', 0):.2f}"
     f" ({s.get('verified', 0) - s.get('noise', 0)}/{s.get('verified', 0)})"),
    ("triage", "triage accuracy", lambda s: f"{s.get('triage_correct', 0)}/{s.get('found', 0)}"
     f" = {s.get('triage_accuracy', 0):.2f}"),
    ("bonus", "bonus finds", lambda s: f"{s.get('bonus_found', 0)}/{s.get('bonus_total', 0)}"),
    ("noise", "noise", lambda s: str(s.get("noise", 0))),
    ("dupes", "dupes dropped", lambda s: str(s.get("duplicates_dropped", 0))),
    ("wall", "wall time", lambda s: f"{s.get('wall_time_s', 0):.0f}s"),
]


def build_results(results: dict, *, target: str, key: str, seed: int | None = None) -> str:
    """One row per config. A config whose run errored still gets a row carrying the error — a table
    that silently omits the provider that crashed reads as if it was never tried."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    head = [
        "# Model scorecard",
        "",
        f"Same code, same prompts, same answer key — only `config/agents.yaml` changed. Target: "
        f"**{target}** · key: `{key}` · recorded {ts}.",
        "",
        "Regenerate with:",
        "",
        "```sh",
        f"vpcopilot bench <repo> --all-configs --key {key}",
        "```",
        "",
    ]
    if not results:
        return "\n".join(head + ["_No configs scored — no `config/agents*.yaml` produced a run._", ""])

    header = "| config | model | " + " | ".join(label for _, label, _ in COLUMNS) + " |"
    sep = "|---" * (len(COLUMNS) + 2) + "|"
    rows = []
    for tag in sorted(results):
        r = results[tag]
        model = f"`{r.get('model', '?')}`"
        if r.get("error"):
            rows.append(f"| `{tag}` | {model} | " +
                        " | ".join(["—"] * (len(COLUMNS) - 1)) +
                        f" | **failed:** {r['error']} |")
            continue
        s = r.get("score") or {}
        rows.append(f"| `{tag}` | {model} | " + " | ".join(fn(s) for _, _, fn in COLUMNS) + " |")

    notes = [
        "",
        "## Reading this table",
        "",
        "- **discovery recall** — of the vulns the answer key labels, how many were found.",
        "- **verify precision** — of everything the run reported, how much was real. Recall and "
        "precision move independently: a run can find every labelled vuln and still bury them in "
        "false positives.",
        "- **triage accuracy** — of the vulns found, how many were routed to an acceptable control.",
        "- **bonus finds** — real vulns beyond the core key, credited rather than counted as noise.",
        "- **dupes dropped** — duplicate findings for one vuln, collapsed so one vuln yields one "
        "band-aid and one code-fix PR.",
        "",
        "## What this table is not",
        "",
        f"- **Not reproducible run to run.** {'A seed of ' + str(seed) + ' was requested, but ' if seed is not None else ''}"
        "two of these providers accept no seed at all and none guarantee determinism, so scores "
        "vary between runs. Treat a small difference as noise; re-run before reading anything into "
        "one. The run date above is part of the result.",
        "- **Not a cost comparison.** Token cost is not measured — nothing in the harness counts "
        "tokens, and a cost column was judged not worth threading through every agent call.",
        "- **Not a general model ranking.** It is one target, one answer key, one prompt set. It "
        "says which model drives *this* pipeline well.",
        "",
    ]
    return "\n".join(head + [header, sep] + rows + notes)


def write_results(results: dict, *, target: str, key: str, seed: int | None = None,
                  dest_dir: str = "benchmarks") -> str:
    d = Path(dest_dir)
    d.mkdir(parents=True, exist_ok=True)
    p = d / "RESULTS.md"
    p.write_text(build_results(results, target=target, key=key, seed=seed))
    return str(p)


def run_all_configs(repo: str, *, key: str = "bench/answer_key.yaml", config_dir: str = "config",
                    out_prefix: str = "out", min_confidence: float = 0.5, concurrency: int = 8,
                    seed: int | None = None, rescore: bool = False,
                    log=print) -> dict:
    """Score every `config/agents*.yaml` against one target, into `out-<tag>` per config.

    A config that fails is recorded and the sweep continues: one dead provider must not cost you
    the other three runs' worth of tokens. `rescore=True` scores the existing out dirs without
    re-scanning — the cheap path for iterating on the table itself."""
    from .bench import run_bench
    from .config import load_config

    results: dict = {}
    for cfg in sorted(Path(config_dir).glob("agents*.yaml")):
        parts = cfg.name.split(".")
        tag = parts[1] if len(parts) == 3 and parts[0] == "agents" else "default"
        try:
            model = load_config(str(cfg)).defaults.model
        except Exception as e:  # noqa: BLE001
            results[tag] = {"model": "?", "error": f"unreadable config: {e}"}
            log(f"  {tag}: unreadable config — {e}")
            continue
        if tag == "default":  # agents.yaml -> name it by its provider, as the console does
            tag = {"anthropic": "claude", "openai": "openai", "ollama": "dgx",
                   "gemini": "gemini"}.get(model.split("/")[0], model.split("/")[0])
        out_dir = f"{out_prefix}-{tag}"
        log(f"[{tag}] {model} -> {out_dir}")
        try:
            res = run_bench(repo, key, out_dir=out_dir, config_path=str(cfg), scan=not rescore,
                            min_confidence=min_confidence, concurrency=concurrency, log=log)
            results[tag] = {"model": model, "score": res["score"], "out_dir": out_dir}
            s = res["score"]
            log(f"  {tag}: recall {s['discovery_recall']:.2f} · precision "
                f"{s['verify_precision']:.2f} · triage {s['triage_accuracy']:.2f}")
        except Exception as e:  # noqa: BLE001 — one dead provider must not abort the sweep
            results[tag] = {"model": model, "error": str(e)[:200], "out_dir": out_dir}
            log(f"  ⚠ {tag}: {e}")
    return results
