# frozen_string_literal: true

# capabilities.rb — the single source of truth for the Spinel differential
# fuzzer's capability / gap-marker model.
#
# WHY THIS EXISTS
# ---------------
# The fuzzer must be configurable so it can (a) document what Spinel does NOT
# support and (b) GROW as Spinel grows. This module holds, in one frozen place,
# the three pieces oracle.rb keys off:
#
#   1. DEGRADATION_MARKERS — the per-run stderr gap signal. This is the REAL,
#      one-directional authority for the question "did Spinel tell you it
#      degraded?". If Spinel printed one of these the moment it gave up, the
#      divergence is a known gap, not a supported-territory finding.
#
#   2. INTENTIONAL — the documented not-a-bug divergences (source signatures +
#      a human-readable list), lifted from Spinel's own
#      vendor/spinel/test/known_fail/NOT-BUGS.md. A divergence traceable to one
#      of these is never a bug.
#
#   3. SUPPORTED — a declarative, MAINTAINED seed map of the Ruby vocabulary
#      Spinel exercises in its own test suite + README. This is the "grows as
#      Spinel grows" surface.
#
# ON SOUNDNESS (we settled this)
# ------------------------------
# Support is NOT soundly derivable and NOT compositional: you cannot prove a
# program is "in the supported surface" by structurally checking it against
# SUPPORTED, because supported constructs can diverge in combination (the whole
# point of the campaign — see reports/supported-divergence-findings.md). So:
#
#   * SUPPORTED is a documentation/seed list ONLY. It is a maintained artifact,
#     re-derived by hand from test/*.rb + README when Spinel adds features. It
#     is NOT a soundness oracle and must never be used to *prove* a case is a
#     bug.
#   * DEGRADATION_MARKERS (the per-run stderr check) IS the real authority, and
#     it is one-directional: a marker => known gap (discard); NO marker +
#     divergence => supported-territory finding (keep). Absence of a marker is
#     the only signal we trust to mean "Spinel was confident".
#
# Pure stdlib. No YAML/JSON deps — frozen Ruby literals, matching the codebase's
# idiom (oracle.rb, runner.rb, generator.rb are all plain require_relative Ruby).
module Capabilities
  module_function

  # ===========================================================================
  # 1. DEGRADATION MARKERS — the per-run gap signal (the real authority).
  # ===========================================================================
  #
  # Two stability tiers. The union (primary + secondary) is what oracle.rb's
  # GapFilter matches against normalized (CRLF->LF) stderr, case-insensitively.
  #
  #   :primary   — STABLE, INTENTIONAL literal strings sourced directly from the
  #                Spinel compiler's own `$stderr.puts` degradation/give-up
  #                sites. These are the markers Spinel deliberately prints when
  #                it gives up and emits the historical no-op `0` (or
  #                widens / falls through / fails to converge). Pinned to the
  #                literal text in spinel_codegen.rb / spinel_analyze.rb, so they
  #                move only when Spinel changes its own warning text — the most
  #                stable thing we can pin the gap signal to.
  #
  #                Sourced (line refs against vendor/spinel, 2026-06-09):
  #                  codegen 6356  "cannot resolve call to '...' on ... (emitting 0)"
  #                  codegen 6389  "uninitialized constant '...' (emitting 0)"
  #                  codegen 34832 "...; emitting 0 (this is wrong — ...)"
  #                  codegen 6134/6151 "Array set-op '...' ... (falling through)"
  #                  codegen 15131/36661 "Spinel: cannot compile ... (unsupported Ruby syntax)"
  #                  codegen 16538 "... is not yet supported ...; falling back to bare super"
  #                  codegen 13926 "`def method_missing' is not dispatched in spinel ..."
  #                  analyze 20921 "param-array type inference did not converge after 4 iterations ... widened to poly"
  #                  analyze 22380 "infer_lambda_param_types did not converge after 256 iterations"
  #                  analyze 29038 "scan_bigint_propagate did not converge after 256 iterations"
  #                  analyze  8922 "global aliasing of regexp special globals is not supported ..."
  #
  #   :secondary — LOOSER, heuristic natural-language phrases (the original
  #                inline DEGRADATION_MARKER set). Lower stability: they are not
  #                pinned to a single literal call site, they catch
  #                paraphrases / future warnings / the long tail of "... is not
  #                supported" / "not implemented" lines that Spinel prints from
  #                many sites. Kept so the union remains a SUPERSET of the old
  #                inline regex (nothing the old oracle matched is dropped).
  #
  # Each entry is a literal substring (NOT a regex) matched case-insensitively.
  DEGRADATION_MARKERS = {
    # --- PRIMARY (stable; pinned to literal compiler warning text) -----------
    primary: [
      "cannot resolve call",        # codegen 6356 — the canonical give-up
      "(emitting 0)",               # codegen 6356/6389 — emit-0 fallback tag
      "; emitting 0",               # codegen 34832 — missing-required-arg emit-0
      "unsupported Ruby syntax",    # codegen 15131/36661 — cannot compile node
      "cannot compile",             # codegen 15131/36661 — companion to above
      "falling through",            # codegen 6134/6151 — Array set-op give-up
      "falling back to bare super", # codegen 16538 — prepended super { } gap
      "did not converge",           # analyze 20921/22380/29038 — fixpoint give-up
      "widened to poly",            # analyze 20921 — param-array convergence loss
      "not dispatched in spinel"    # codegen 13926 — method_missing gap
    ].freeze,

    # --- SECONDARY (looser; heuristic paraphrase tier) -----------------------
    secondary: [
      "cannot resolve",          # broader than "cannot resolve call"
      "emitting zero",           # paraphrase of "(emitting 0)"
      "is not supported",        # e.g. analyze 8922 regexp-global aliasing, long tail
      "is unsupported",
      "not yet supported",       # e.g. codegen 16538 family
      "not yet implemented",
      "not implemented",
      "falling back",            # broader than "falling back to bare super"
      "last-def-wins",           # redefine warning (historical marker)
      # NOTE: the two anchored regex alternatives from the original inline
      # DEGRADATION_MARKER ( /^unhandled\b/ and /^warning:.*\bunresolved\b/ )
      # are preserved verbatim by oracle.rb as SECONDARY_REGEXPS so their
      # line-anchored / word-boundary semantics are not lost in a substring
      # union. See SECONDARY_REGEXPS below.
    ].freeze
  }.freeze

  # Anchored / word-boundary alternatives carried over verbatim from the
  # original inline DEGRADATION_MARKER so the union stays a strict SUPERSET of
  # the old matcher (these cannot be expressed as plain case-insensitive
  # substrings without losing their anchors). oracle.rb ORs these in.
  SECONDARY_REGEXPS = [
    /^unhandled\b/i,
    /^warning:.*\bunresolved\b/i
  ].freeze

  # ===========================================================================
  # 2. INTENTIONAL — documented not-a-bug divergences.
  # ===========================================================================
  #
  # Lifted from vendor/spinel/test/known_fail/NOT-BUGS.md. A divergence
  # traceable to one of these constructs is an :intentional_incompat, never a
  # bug. SIGNATURES are deliberately narrower than DESCRIPTIONS: they are source
  # filters used while fuzzing, so broad patterns such as `.inspect` would hide
  # real bugs. Broader documented gaps are excluded at generation time instead.
  INTENTIONAL = {
    # Conservative source-signature regexes. Fire ONLY on strong, specific
    # signals so they never mask a real supported divergence.
    signatures: [
      # Integer#** / pow with a negative exponent (raises by design).
      /\*\*\s*-\d/,
      /\.pow\(\s*[^,]*,?\s*-\d/,
      # grapheme clusters — requires Unicode tables Spinel does not ship.
      /grapheme_clusters?/
      # flip-flop / regexp match-global aliasing are rejected at compile time
      # (they surface as degradation markers / compile errors), and the
      # generator excludes them, so no extra source signature is needed here.
    ].freeze,

    # Human-readable not-a-bug list (source: NOT-BUGS.md). Drives UNSUPPORTED.md.
    descriptions: [
      "Integer#** / Integer#pow with a NEGATIVE exponent — CRuby returns a " \
        "Rational; Spinel has no Rational, so it raises RangeError (negative " \
        "exponent) rather than truncating to 0. Float#** is unaffected.",
      "String#grapheme_clusters / #each_grapheme_cluster — needs Unicode " \
        "grapheme-break tables Spinel deliberately does not ship. Use chars / " \
        "each_char / codepoints / bytes.",
      "Aliasing the regexp match globals (alias … $&, $`, $', $+, $~) — " \
        "rejected at compile time; require \"English\" does not compile. " \
        "Direct reads of the globals work; only aliasing is unsupported.",
      "Flip-flop operator (a Range used as a condition) — fails to compile " \
        "rather than running with hidden per-site state.",
      "Float#round/#ceil/#floor/#truncate with a NON-LITERAL ndigits — keeps " \
        "the static Float return type where CRuby would pick Integer at " \
        "runtime. Values are numerically equal; only #class / default string " \
        "form differ. (A literal ndigits is fully compatible.)",
      "Hash#inspect / Range#inspect / Struct#inspect, and p / inspect / to_s " \
        "on Hash/Range/Struct — inspect for these is not yet implemented " \
        "(documented gap). Excluded from generation.",
      "User-class instance inside a poly value renders the placeholder " \
        "\"#<Object>\" (no runtime class-name table yet) — by design."
    ].freeze,

    # Out-of-subset features (README "Limitations"): excluded from generation;
    # listed for completeness in the doc.
    out_of_subset: [
      "eval / instance_eval / class_eval",
      "send / method_missing / dynamic define_method (metaprogramming)",
      "Thread / Mutex (Fiber is the supported concurrency primitive)",
      "Non-UTF-8/ASCII encoding tricks",
      "Deeply-nested lambda calculus (nested -> { } with [] calls)"
    ].freeze
  }.freeze

  # ===========================================================================
  # 3. SUPPORTED — maintained seed map of the supported Ruby vocabulary.
  # ===========================================================================
  #
  # SEED, NOT ORACLE. Re-derive by hand when Spinel adds features:
  #   * scan vendor/spinel/test/*.rb (822 feature fixtures as of 2026-06-09)
  #     for newly-exercised constructs, and
  #   * read the README "Supported Ruby Features" section.
  # Then add the new vocabulary to the relevant category below. Do NOT use this
  # map to prove a program is in-surface (see "ON SOUNDNESS" at top of file):
  # supported constructs can diverge in combination.
  #
  # Each category lists the canonical method/keyword vocabulary Spinel's own
  # tests + README assert as working.
  SUPPORTED = {
    core: [
      "class", "inheritance", "super", "include (mixin)", "attr_accessor",
      "attr_reader", "attr_writer", "Struct.new", "alias", "alias_method",
      "module constants", "open classes for built-in types", "def", "self"
    ].freeze,

    control_flow: [
      "if", "elsif", "else", "unless", "case/when", "case/in (pattern match)",
      "while", "until", "loop", "for..in (range and array)", "break", "next",
      "return", "catch/throw", "&. (safe navigation)", "begin/rescue (as expr)",
      "ternary"
    ].freeze,

    blocks_enumerable: [
      "yield", "block_given?", "&block", "proc {}", "Proc.new", "lambda -> x {}",
      "method(:name)", "each", "each_with_index", "map", "select", "reject",
      "reduce", "sort_by", "any?", "all?", "none?", "times", "upto", "downto",
      "grep", "min_by", "max_by", "minmax", "chunk", "slice_when", "product",
      "combination", "flatten", "transpose", "to_h"
    ].freeze,

    exceptions: [
      "begin", "rescue", "ensure", "retry", "raise", "custom exception classes",
      "begin/rescue/else"
    ].freeze,

    integers: [
      "+", "-", "*", "/", "%", "**", "comparisons", "bit ops", "times", "upto",
      "downto", "to_s(radix)", "abs", "Bigint (auto-promoted)",
      "div-by-zero raises"
    ].freeze,

    floats: [
      "+", "-", "*", "/", "**", "round", "ceil", "floor", "truncate (literal ndigits)",
      "comparisons", "to_i", "to_s", "Float#** (incl. negative exponent)"
    ].freeze,

    strings: [
      "immutable + mutable (sp_String)", "<< (auto-promote to mutable)", "+",
      "interpolation", "tr", "ljust", "rjust", "center", "split(sep)",
      "char index compare s[i] == \"c\"", "chained concat (a+b+c+d)", "to_sym",
      "chars", "each_char", "codepoints", "bytes", "upcase", "downcase",
      "capitalize", "% / format", "pack / unpack"
    ].freeze,

    arrays: [
      "literal", "[] index (incl. negative, OOB)", "push (multi-arg)", "<<",
      "map", "map!", "select", "select!", "reject", "compact", "flatten",
      "transpose", "first", "last", "clear", "fill", "product", "combination",
      "pattern match (array)", "to_h", "sort!", "frozen mutate raises",
      "object_id", "grep", "slice!", "slice_before", "slice_after", "to_s (=inspect)"
    ].freeze,

    hashes: [
      "literal { } ", "symbol-keyed {a: 1} (sp_SymIntHash)", "[] get/set",
      "each", "fetch", "keys", "values", "merge"
    ].freeze,

    ranges: [
      "literal a..b", "literal a...b", "each", "for..in (range)", "to_a",
      "cover?", "include?"
    ].freeze,

    symbols: [
      "literal :name (interned)", "String#to_sym", ":a != \"a\" (distinct type)",
      "symbol-keyed hashes"
    ].freeze,

    structs: [
      "Struct.new(:a, :b)", "field readers/writers", "value-type promotion",
      "compile-time method synthesis"
      # NOTE: Struct#inspect is INTENTIONALLY unsupported (see INTENTIONAL).
    ].freeze,

    regexp: [
      "built-in NFA engine (no external dep)", "=~", "$1-$9", "match?",
      "gsub(/re/, str)", "sub(/re/, str)", "scan(/re/)", "split(/re/)"
    ].freeze,

    inspect_p: [
      "Object#inspect (primitives: Integer, Float, String, Symbol, Boolean, nil)",
      "typed array inspect (int_array, float_array, str_array, sym_array)",
      "poly_array inspect ([1, \"x\", :y])", "scalar poly value inspect",
      "Array#to_s (= Array#inspect)", "Kernel#p", "obj.inspect", "obj.to_s",
      '"#{obj.inspect}" interpolation'
      # NOTE: Hash/Range/Struct#inspect are INTENTIONALLY unsupported.
    ].freeze,

    globals: [
      "$name compiled to static C variables", "type-mismatch detection",
      "direct reads of regexp match globals ($1-$9, $&, ...)"
    ].freeze,

    concurrency: [
      "Fiber.new", "Fiber#resume", "Fiber.yield (with value passing)",
      "Fiber[:k] / Fiber[:k] = v", "Fiber.current[:k]"
    ].freeze,

    io: [
      "puts", "print", "printf", "p", "gets", "ARGV", "ENV[]",
      "File.read", "File.write", "File.open (with blocks)", "StringIO",
      "system()", "backtick"
    ].freeze,

    ffi: [
      "ffi_func", "ffi_lib", "ffi_const", "ffi_buffer", "ffi_read_*",
      "scalars / strings / opaque :ptr / integer consts / byte buffers / struct-field reads"
    ].freeze,

    types: [
      "Integer", "Float", "String", "Array", "Hash", "Range", "Time",
      "StringIO", "File", "Regexp", "Bigint (auto-promoted)", "Fiber",
      "polymorphic values (tagged unions)", "nullable object types (T?)"
    ].freeze
  }.freeze

  # Convenience accessors -----------------------------------------------------

  # The full union of degradation markers (primary + secondary substrings),
  # used by oracle.rb to build its case-insensitive matcher.
  def degradation_marker_substrings
    DEGRADATION_MARKERS[:primary] + DEGRADATION_MARKERS[:secondary]
  end

  # Count of supported-vocabulary categories (for reporting).
  def supported_category_count
    SUPPORTED.keys.length
  end

  # ===========================================================================
  # 4. SPINELGEMS INTEROP — additive verdict mapping (OriPekelman/spinelgems).
  # ===========================================================================
  #
  # spinelgems is a gem-compatibility ledger whose differential harness assigns a
  # flat verdict enum — rejected / clean / risky / loaded / verified
  # (lib/bundler/spinel/ledger.rb:17-39) — plus a `reasons` axis (`miscompile`,
  # `unresolved:<call>`, `build-or-run-error`, …). See
  # spinel-diff-fuzz-notes/spinelgems-alignment.md for the full ground truth.
  #
  # This map lets us ALSO speak their vocabulary for interop, WITHOUT renaming or
  # replacing our internal gap_class symbols (which stay the authority). It maps
  # each of our oracle.rb gap_class symbols to the spinelgems {verdict, reason}
  # pair we would emit for it:
  #
  #   :supported_divergence -> rejected / miscompile
  #       Exact match: clean stderr, exit 0, stdout diverges from CRuby — the same
  #       "compiles + runs but output is wrong" case spinelgems' Verifier records
  #       as ["rejected", ["miscompile", "diff:…"]] (verifier.rb:118-122).
  #   :degradation_gap      -> rejected / unresolved
  #       Approximate: Spinel printed an emitting-0 / give-up marker; spinelgems'
  #       Probe turns that warning family into rejected + unresolved:<call>
  #       (probe.rb:116-118; rubric `unsupported`, verifier.rb:84).
  #   :intentional_incompat -> nil (NO equivalent)
  #       spinelgems has no documented-not-a-bug bucket; everything that diverges
  #       is `rejected`. We intentionally emit NO finding for these — surfacing one
  #       would be a false positive in their `rejected` bucket.
  #
  # Each non-nil value is {verdict:, reason:} using their string vocabulary.
  SPINELGEMS_VERDICT = {
    supported_divergence: { verdict: "rejected", reason: "miscompile" }.freeze,
    degradation_gap:      { verdict: "rejected", reason: "unresolved" }.freeze,
    intentional_incompat: nil
  }.freeze

  # Map one of our gap_class symbols to the spinelgems {verdict:, reason:} pair,
  # or nil when there is no spinelgems equivalent / no finding should be emitted
  # (:intentional_incompat, or any symbol we don't map). Additive: this never
  # changes how oracle.rb classifies — it only translates an existing verdict for
  # interop output.
  def spinelgems_verdict(gap_class)
    return nil if gap_class.nil?

    SPINELGEMS_VERDICT.fetch(gap_class.to_sym, nil)
  end
end

# ---------------------------------------------------------------------------
# Self-test (guarded; does not run on require). Covers the spinelgems interop
# mapping — pure data, no Spinel build needed.
# ---------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  failures = []
  assert = lambda do |cond, msg|
    if cond
      print "."
    else
      print "F"
      failures << msg
    end
  end

  # supported_divergence -> rejected/miscompile (the exact-match case).
  v = Capabilities.spinelgems_verdict(:supported_divergence)
  assert.call(v == { verdict: "rejected", reason: "miscompile" },
              "spinelgems_verdict(:supported_divergence) -> rejected/miscompile (#{v.inspect})")

  # degradation_gap -> rejected/unresolved (the approximate case).
  v = Capabilities.spinelgems_verdict(:degradation_gap)
  assert.call(v == { verdict: "rejected", reason: "unresolved" },
              "spinelgems_verdict(:degradation_gap) -> rejected/unresolved (#{v.inspect})")

  # intentional_incompat -> nil (no spinelgems equivalent; not a finding).
  assert.call(Capabilities.spinelgems_verdict(:intentional_incompat).nil?,
              "spinelgems_verdict(:intentional_incompat) -> nil")

  # nil gap_class (pass / reference-failed) -> nil.
  assert.call(Capabilities.spinelgems_verdict(nil).nil?,
              "spinelgems_verdict(nil) -> nil")

  # Unknown symbol -> nil (never raises; additive + safe).
  assert.call(Capabilities.spinelgems_verdict(:not_a_real_class).nil?,
              "spinelgems_verdict(unknown) -> nil")

  # Accepts a string too (records persist gap_class as a string in meta.json).
  v = Capabilities.spinelgems_verdict("supported_divergence")
  assert.call(v == { verdict: "rejected", reason: "miscompile" },
              "spinelgems_verdict(\"supported_divergence\") string form (#{v.inspect})")

  # Every emitted verdict string is in the spinelgems enum.
  enum = %w[rejected clean risky loaded verified].freeze
  ok = Capabilities::SPINELGEMS_VERDICT.values.compact.all? { |h| enum.include?(h[:verdict]) }
  assert.call(ok, "all mapped verdicts are valid spinelgems enum values")

  puts
  if failures.empty?
    puts "capabilities self-test: ALL PASS"
    exit 0
  else
    puts "capabilities self-test FAILURES:"
    failures.each { |f| puts "  - #{f}" }
    exit 1
  end
end
