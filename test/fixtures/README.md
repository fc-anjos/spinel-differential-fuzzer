# Fuzzer self-test fixtures

These are **the fuzzer's own self-test fixtures** — three minimized repros that
this differential fuzzer found and shrank against Spinel at commit
`6bdd2adb5db56d2e3c4dadd2cb887288f12f61cc` (the pinned `vendor/spinel`
submodule). Each `*.rb` is a valid CRuby program whose output the Spinel AOT
compiler diverges from; the matching `*.rb.expected` is the reference CRuby
stdout.

They live here so the fuzzer repo can exercise its own oracle/promoter end to
end without depending on Spinel's test tree. They are **not** Spinel's
regression suite — the canonical regressions live upstream in Spinel's
`test/known_fail/`. Treat these as illustrative shrink outputs.

| fixture | category |
| --- | --- |
| `enumerator_to_a_segfault.rb` | build/codegen divergence (missing output) |
| `float_format_uninitialized.rb` | numeric formatting divergence |
| `string_split_single_space_variable.rb` | String#split divergence |

To turn a fresh minimized repro into an upstream Spinel known-fail fixture, use
the promoter: `ruby tools/fuzz/promote.rb <repro.rb>`.
