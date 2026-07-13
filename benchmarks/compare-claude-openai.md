# Model comparison

| metric | claude | openai |
|---|---|---|
| model | anthropic/claude-opus-4-8 | openai/gpt-4.1 |
| candidates | 92 | 69 |
| verified | 40 | 64 |
| policies generated | 15 | 14 |
| live-validated | 13 | 9 |
| blocked (real exploit) | 9 | 5 |
| block rate | 69% | 56% |
| applied (behavioral) | 3 | 1 |
| self-healed | 0 | 1 |
| avg attempts | 1.0 | 1.44 |
| code-fix PRs | 0 | 0 |


_Caveats: OpenAI ran at min-confidence 0.7 vs Claude's 0.5 (gpt-4.1 still verified MORE, so the
credulousness gap is if anything understated); the operator mitigated a different count each run
(13 vs 9), so block-rate is over different samples. Same crAPI target, same harness, code-fixes off._
