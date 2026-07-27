# Model scorecard

Same code, same prompts, same answer key — only `config/agents.yaml` changed. Target: **Nimbus vuln-lab (9 labeled vulns)** · key: `bench/answer_key.yaml` · recorded 2026-07-27.

Regenerate with:

```sh
vpcopilot bench <repo> --all-configs --key bench/answer_key.yaml
```

| config | model | discovery recall | verify precision | triage accuracy | bonus finds | noise | policies (unusable) | dupes dropped | wall time |
|---|---|---|---|---|---|---|---|---|---|
| `claude` | `anthropic/claude-opus-4-8` | 9/9 = 1.00 | 1.00 (10/10) | 8/9 = 0.89 | 1/6 | 0 | 9 (0) | 0 | 195s |
| `gemini` | `gemini/gemini-3.1-pro-preview` | 6/9 = 0.67 | 1.00 (6/6) | 6/6 = 1.00 | 0/6 | 0 | 6 (**3**) | 0 | 394s |
| `openai` | `openai/gpt-4.1` | 8/9 = 0.89 | 1.00 (8/8) | 8/8 = 1.00 | 0/6 | 0 | 7 (0) | 0 | 53s |

## Reading this table

- **discovery recall** — of the vulns the answer key labels, how many were found.
- **verify precision** — of everything the run reported, how much was real. Recall and precision move independently: a run can find every labelled vuln and still bury them in false positives.
- **triage accuracy** — of the vulns found, how many were routed to an acceptable control.
- **bonus finds** — real vulns beyond the core key, credited rather than counted as noise.
- **dupes dropped** — duplicate findings for one vuln, collapsed so one vuln yields one band-aid and one code-fix PR.
- **policies (unusable)** — band-aids generated, and how many the deterministic linter rejects before any live round-trip: an empty spec, no DENY rule, or an OpenAPI fragment missing its envelope. Recall, precision and triage can all be perfect while the artifact is unusable, so this column exists to stop the table flattering a model that routed correctly and then emitted nothing.

## What this table is not

- **Not reproducible run to run.** Two of these providers accept no seed at all and none guarantee determinism, so scores vary between runs. Treat a small difference as noise; re-run before reading anything into one. The run date above is part of the result.
- **Not a cost comparison.** Token cost is not measured — nothing in the harness counts tokens, and a cost column was judged not worth threading through every agent call.
- **Not a general model ranking.** It is one target, one answer key, one prompt set. It says which model drives *this* pipeline well.
- **Not the full config set.** `dgx` was not run and is absent from the table — unreachable from the machine that produced it, which is a different thing from a model that scored badly.
