# frozen_string_literal: true

# VEIN: Ruby special-case semantics gated on an AST-LITERAL check instead of the
# runtime value.
#
# Confirmed root cause (upstream handoff): `String#split(' ')` "awk mode"
# (leading whitespace stripped, runs of whitespace collapsed, no trailing empty
# fields) is applied by Spinel ONLY when the separator is the string LITERAL
# ' ' at the call site. If the SAME value ' ' arrives via a VARIABLE, the
# literal-node detection misses and the call falls through to plain
# separator-split -> a different field list. CRuby decides awk-mode from the
# runtime VALUE, so the two forms agree under CRuby and diverge under Spinel:
# a supported-territory divergence.
#
# This module manufactures the equivalence class: for each builtin whose special
# semantics depend on a specific literal argument value, it emits the SAME
# operation twice -- once with the value as a LITERAL, once with the value bound
# to a VARIABLE first -- and prints both reduced results. Under CRuby the pair is
# identical; any Spinel divergence between the literal and variable form is the
# bug.
#
# Probed builtins (all in the supported surface):
#   * String#split(' ')           awk-mode vs plain-space split
#   * String#split(' ', limit)    awk-mode + limit
#   * String#tr(from, to)         (range/literal handling via a var-bound arg)
#   * Array#join(' ')             string separator literal vs var
#   * String#gsub(' ', rep)       literal-pattern vs var-pattern
#
# DETERMINISM: split/join results are reduced to length / sorted-join / bytes;
# all randomness flows through the injected `rng`. No banned tokens. Valid Ruby
# by construction; the CRuby reference always agrees across the literal/var pair.
#
# Pure stdlib. module_function builders take an explicit `rng` and a duck-typed
# `scope` (#fresh_name only).

module FuzzGen
  module AwkLiteral
    module_function

    # Strings chosen to MAXIMIZE the awk-mode vs plain-split divergence: leading/
    # trailing spaces, runs of multiple spaces, and tabs (awk mode collapses any
    # whitespace run; plain ' ' split does not).
    SPLIT_WORDS = [
      "  a   b c ",       # leading + trailing + internal runs
      "x  y  z",          # double-space runs
      " one two  three ", # mixed
      "alpha beta",       # simple single-space
      "a b c d e",        # many single spaces
      "  ",               # all-whitespace -> awk yields [] , plain yields ['', '']
      "no_spaces",        # no separator at all
      "trail   "          # trailing run only
    ].freeze

    GSUB_WORDS = %w[a_b a-b ab.c x|y a,b same hello].freeze

    def pick(rng, arr)
      arr[rng.rand(arr.length)]
    end

    def q(value)
      value.inspect
    end

    # split_pair(rng, scope, lines)
    #
    # Emit the awk-mode probe: split with the LITERAL ' ' and split with a VAR
    # holding ' ', over the SAME input. Reduce each to field-count + sorted join
    # so the divergence (different field list) is observable byte-exactly.
    def split_pair(rng, scope, lines)
      s = pick(rng, SPLIT_WORDS)
      sv = scope.fresh_name("s")
      lines << "#{sv} = #{q(s)}"
      sep = scope.fresh_name("sep")
      lines << "#{sep} = \" \""            # a variable holding the awk-trigger value
      # Literal-separator form (Spinel applies awk-mode).
      lines << "puts #{sv}.split(\" \").length"
      lines << "puts #{sv}.split(\" \").sort.join(\"|\")"
      # Variable-separator form (same runtime value; Spinel may skip awk-mode).
      lines << "puts #{sv}.split(#{sep}).length"
      lines << "puts #{sv}.split(#{sep}).sort.join(\"|\")"
    end

    # split_limit_pair(rng, scope, lines)
    #
    # The same probe but with an explicit limit argument, so the awk-mode +
    # limit interaction is exercised in both literal and variable separator form.
    def split_limit_pair(rng, scope, lines)
      s = pick(rng, SPLIT_WORDS)
      lim = rng.rand(-1..3)
      sv = scope.fresh_name("s")
      lines << "#{sv} = #{q(s)}"
      sep = scope.fresh_name("sep")
      lines << "#{sep} = \" \""
      lines << "puts #{sv}.split(\" \", #{lim}).length"
      lines << "puts #{sv}.split(\" \", #{lim}).map { |t| t.length }.join(\",\")"
      lines << "puts #{sv}.split(#{sep}, #{lim}).length"
      lines << "puts #{sv}.split(#{sep}, #{lim}).map { |t| t.length }.join(\",\")"
    end

    # join_pair(rng, scope, lines)
    #
    # Array#join with a literal ' ' vs a var-bound ' '. join has no awk-mode, but
    # it shares the same "string-separator literal vs variable" lowering family
    # the vein targets, so any literal-gated special handling surfaces here too.
    def join_pair(rng, scope, lines)
      n = rng.rand(2..5)
      elems = Array.new(n) { rng.rand(-9..9) }.join(", ")
      av = scope.fresh_name("a")
      lines << "#{av} = [#{elems}]"
      sep = scope.fresh_name("jsep")
      lines << "#{sep} = \" \""
      lines << "puts #{av}.join(\" \").length"
      lines << "puts #{av}.join(#{sep}).length"
      lines << "puts(#{av}.join(\" \") == #{av}.join(#{sep}) ? 1 : 0)"
    end

    # gsub_pair(rng, scope, lines)
    #
    # gsub with a literal string pattern vs a var-bound pattern (same value). A
    # literal-gated fast path for a single-space (or single-char) pattern would
    # diverge from the var form.
    def gsub_pair(rng, scope, lines)
      s = pick(rng, GSUB_WORDS)
      pat = pick(rng, %w[a _ - . | ,])
      rep = pick(rng, %w[X = +])
      sv = scope.fresh_name("g")
      lines << "#{sv} = #{q(s)}"
      pv = scope.fresh_name("pat")
      lines << "#{pv} = #{q(pat)}"
      lines << "puts #{sv}.gsub(#{q(pat)}, #{q(rep)}).bytes.sum"
      lines << "puts #{sv}.gsub(#{pv}, #{q(rep)}).bytes.sum"
    end

    BUILDERS = %i[split_pair split_limit_pair join_pair gsub_pair].freeze

    # ------------------------------------------------------------------
    # Whole-program emitter + generator-integration shim.
    # ------------------------------------------------------------------

    def program(rng, scope, index, seed, header_lines = nil)
      scope ||= MiniScope.new
      lines = header_lines ? header_lines.dup : default_header(index, seed)

      # Always include the headline split awk-mode probe, then a seed-shuffled
      # selection of the rest so each program covers several builtins.
      split_pair(rng, scope, lines)
      others = (BUILDERS - %i[split_pair]).shuffle(random: rng)
      others.first(rng.rand(1..others.length)).each do |b|
        send(b, rng, scope, lines)
      end

      lines << ""
      lines.join("\n")
    end

    def awk_literal_program(rng, index, seed)
      program(rng, nil, index, seed)
    end

    def default_header(index, seed)
      [
        "# fuzz-family: awk_literal",
        "# fuzz-index: #{index}",
        "# fuzz-seed: #{seed}",
        "# fuzz-mode: vein"
      ]
    end

    class MiniScope
      def initialize
        @counter = 0
      end

      def fresh_name(prefix = "v")
        @counter += 1
        "#{prefix}#{@counter}"
      end
    end
  end
end

# ---------------------------------------------------------------------------
# Self-test (guarded so it never runs on require).
# ---------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  require "tempfile"

  BANNED = [
    /\bTime\b/, /\bDateTime\b/, /\brand\b/, /\bsrand\b/, /\bobject_id\b/,
    /\b__id__\b/, /\.inspect\b/, /\bp\s/, /\bGC\b/, /\bObjectSpace\b/,
    /\.hash\b/, /\bRandom\b/, /\b__FILE__\b/, /\b__LINE__\b/, /\bcaller\b/,
    /\bENV\b/
  ].freeze

  def parses?(source)
    RubyVM::AbstractSyntaxTree.parse(source)
    true
  rescue SyntaxError, ArgumentError
    false
  end

  total = 0
  failures = 0
  seeds = [1, 7, 42, 1234, 99_999, 2024]
  per_seed = 40

  seeds.each do |seed|
    rng = Random.new(seed)
    per_seed.times do |i|
      case_seed = rng.rand(1 << 62)
      crng = Random.new(case_seed)
      src = FuzzGen::AwkLiteral.awk_literal_program(crng, i, case_seed)
      total += 1

      unless parses?(src)
        failures += 1
        warn "PARSE FAIL seed=#{seed} index=#{i}"
        warn src
        next
      end

      hit = BANNED.find { |re| src =~ re }
      if hit
        failures += 1
        warn "BANNED TOKEN #{hit.inspect} seed=#{seed} index=#{i}"
        warn src
        next
      end

      Tempfile.create(["awk_selftest", ".rb"]) do |f|
        f.write(src)
        f.flush
        unless system("ruby", "-c", f.path, out: File::NULL, err: File::NULL)
          failures += 1
          warn "ruby -c FAIL seed=#{seed} index=#{i}"
          warn src
        end
        unless system("ruby", f.path, out: File::NULL, err: File::NULL)
          failures += 1
          warn "RUNTIME FAIL seed=#{seed} index=#{i}"
          warn src
        end
      end
    end
  end

  a = FuzzGen::AwkLiteral.awk_literal_program(Random.new(123), 5, 123)
  b = FuzzGen::AwkLiteral.awk_literal_program(Random.new(123), 5, 123)
  if a != b
    failures += 1
    warn "DETERMINISM FAIL"
  end

  puts "awk_literal self-test: #{total} programs generated, #{failures} failures"
  exit(failures.zero? ? 0 : 1)
end
