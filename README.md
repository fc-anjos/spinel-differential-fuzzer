# spinel-differential-fuzzer

A **Spinel-vs-CRuby differential + sanitizer fuzzer**. It generates valid Ruby
programs, runs them through both the [Spinel](https://github.com/matz/spinel)
AOT compiler and a reference CRuby interpreter, and flags any divergence in
behavior — wrong output, wrong exit status, mismatched exceptions, crashes, or
memory-safety violations caught by ASan/UBSan.

It is Spinel-specific: it knows Spinel's driver (`spinel -E`), its C emission
and exact compile/link recipe, and its pipeline binaries (`spinel_parse`,
`spinel_analyze.rb`, `spinel_codegen.rb`). There is no backend abstraction; the
oracle and runner target Spinel directly.

Spinel itself is vendored as a **git submodule** at `vendor/spinel`, pinned to
the exact commit the harvested bugs reproduce against
(`6bdd2adb5db56d2e3c4dadd2cb887288f12f61cc`).

## What it does

- **Type-directed generation** (`tools/fuzz/generator.rb`, `tools/fuzz/gen/*`):
  builds programs that are valid by construction across families — numeric,
  strings, collections, enumerable, methods, exceptions, declarations and
  control flow.
- **Hardened subprocess runner** (`tools/fuzz/runner.rb`): wall-clock + RLIMIT
  bounds, process-group kills, and parallel sharding via `--jobs`.
- **Differential + sanitizer oracle** (`tools/fuzz/oracle.rb`):
  1. *Differential lane* — compares normalized stdout, exit status, exception
     class+message, and crash-signal classification between CRuby and Spinel.
     Cases where the reference itself fails are skipped to keep the oracle sound.
  2. *Sanitizer lane* — emits C, compiles an ASan+UBSan-instrumented binary
     using Spinel's exact include/link recipe, runs it, and treats any sanitizer
     report as a failure even when stdout matches.
- **Triage + shrinker** (`tools/fuzz/triage.rb`): failure signature/dedup, a
  delta-debugging shrinker (the reproduce predicate is injected from the
  orchestrator), a reproducibility manifest, and a regression-corpus writer.
- **Run classifiers** (`tools/fuzz/classify_run.rb`, `tools/fuzz/cross_opt.rb`):
  summarize saved run artifacts and compare Spinel behavior across `-O0/-O2/-O3`
  without duplicating the main oracle's gap filter.
- **Upstream repro exporter** (`tools/fuzz/promote.rb`): turns a minimized repro
  into an upstream-ready `.rb` + `.expected` pair under `tmp/upstream-repros/`.

Pure Ruby stdlib only — no gems.

## Quickstart

```sh
# 1. Fetch the pinned Spinel submodule
git submodule update --init --recursive

# 2. Build the Spinel toolchain (fetches prism/rbs sources, then compiles)
make -C vendor/spinel deps
make -C vendor/spinel all

# 3. Run the fuzzer (defaults locate vendor/spinel/spinel automatically)
ruby tools/fuzz_spinel.rb --cases 200 --seed 1 --jobs 4

# Fast smoke, no sanitizer lane:
ruby tools/fuzz_spinel.rb --cases 20 --seed 1 --jobs 2 --no-sanitize --allow-failures
```

By default the fuzzer resolves the Spinel driver to `vendor/spinel/spinel` and
the toolchain root (for `spinel_parse` / `spinel_analyze.rb` /
`spinel_codegen.rb`) to `vendor/spinel`. Override with `--spinel PATH` and
`--root DIR` (or the `SPINEL_ROOT` env var) for an out-of-tree Spinel checkout.

### Useful flags

| flag | meaning |
| --- | --- |
| `--cases N` | number of generated cases |
| `--seed N` | top-level RNG seed (reproducible) |
| `--jobs N` | parallel worker shards |
| `--no-sanitize` | skip the ASan/UBSan lane (faster) |
| `--shrink` | auto-minimize each unique failure |
| `--continue` | resume from `progress.json`, dedup across runs |
| `--int-overflow raise\|wrap\|promote` | integer overflow mode |
| `--families LIST` / `--exclude-family NAME` | restrict generation |
| `--templates` | legacy template families instead of typed generation |
| `--allow-failures` | smoke/CI mode: keep artifacts and exit 0 even if bugs are found |

Run `ruby tools/fuzz_spinel.rb --help` for the full list.

## Classifying and Exporting Repros

```sh
ruby tools/fuzz/classify_run.rb tmp/fuzz/seed-1
ruby tools/fuzz/promote.rb tmp/fuzz/seed-1/<case>/min.rb
```

`classify_run.rb` reads saved `meta.json` artifacts and buckets them as
supported divergences, markerless build failures, robustness failures,
degradation gaps, intentional divergences, or reference skips. `promote.rb` only
exports a minimized repro plus CRuby expected output; whether Spinel wants that
as a known-fail test, a normal regression after a fix, or issue-only evidence
should be decided with upstream maintainers.

The default `--supported-only` filter records raw survivor metadata as
`supported_divergence`; the classifier turns those survivors into the
reviewer-facing buckets above.

For optimizer-specific checks, run the cross-opt lane:

```sh
ruby tools/fuzz/cross_opt.rb --cases 200 --seed 1
```

## Self-test fixtures

`test/fixtures/` holds three minimized repros this fuzzer found and shrank — its
own self-test fixtures, not Spinel's regression suite. See
`test/fixtures/README.md`.

## Module self-tests

Each fuzzer module is runnable standalone for its built-in self-test:

```sh
ruby tools/fuzz/runner.rb
ruby tools/fuzz/generator.rb
ruby tools/fuzz/oracle.rb
ruby tools/fuzz/triage.rb
```

## License

MIT. See [LICENSE](LICENSE).
