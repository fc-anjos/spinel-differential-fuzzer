# frozen_string_literal: true

# VEIN: float conversion specifier (%g / %e / %f) in String#% / Kernel#format
# reads UNINITIALIZED STACK MEMORY instead of the supplied float operand.
#
# Confirmed root cause (upstream handoff): the format-lowering does not correctly
# wire the float operand into the C printf argument slot, so a garbage stack
# value is formatted (deterministic 643 vs 93 in the original repro). The bug is
# in the operand-marshalling for float specifiers, so it is sensitive to:
#   * which float specifier is used (%g / %e / %f and width/precision variants)
#   * whether the float arrives POSITIONALLY (format(fmt, x)) or via an ARRAY
#     (fmt % [x])
#   * MIXED int+float templates (the int slot wired correctly while the float
#     slot is not, or vice versa, exercising slot indexing)
#
# This module formats float operands through every specifier x marshalling x
# mixed-arity combination and prints the result. Crucially, the printed bytes
# must be DETERMINISTIC under CRuby: %g/%e/%f over a fixed float literal with a
# fixed precision produce identical bytes on every platform, so any divergence is
# Spinel formatting a wrong slot -- a supported-territory divergence.
#
# We deliberately do NOT reduce to .bytes.sum here (unlike strings.rb): the
# headline bug yields a STRUCTURALLY different number, and printing the formatted
# string directly makes the 643-vs-93 style divergence maximally legible. The
# floats and precisions are chosen so the formatted output is byte-stable across
# platforms (no trailing-zero / exponent-width ambiguity for the chosen values).
#
# DETERMINISM: all randomness flows through the injected `rng`. Floats are fixed,
# short, exactly-representable literals; precisions are explicit. No banned
# tokens. Valid Ruby by construction; the CRuby reference is byte-stable.
#
# Pure stdlib. module_function builders take an explicit `rng` and a duck-typed
# `scope` (#fresh_name only).

module FuzzGen
  module FloatFormat
    module_function

    # Floats with short, exactly-representable decimal expansions so %f/%e/%g
    # produce identical bytes on every libc. (No 0.1-style values whose binary
    # rounding could differ in the last printed digit.)
    FLOATS = %w[
      0.0 1.0 -1.0 0.5 -0.5 2.5 -2.5 1.25 -1.25 3.75 -3.75
      10.0 -10.0 100.0 0.25 -0.25 8.5 -8.5 16.0 0.125
    ].freeze

    # Float specifiers with explicit precision/width so the formatted bytes are
    # platform-stable. %g without precision can vary; we always pin precision.
    FLOAT_FORMATS = %w[
      %.6f %.2f %.0f %+.3f %10.4f %-10.4f %08.3f
      %.6e %.2e %+.4e
      %.6g %.3g
    ].freeze

    INT_FORMATS = %w[%d %5d %-5d %05d %+d %x %o].freeze

    def pick(rng, arr)
      arr[rng.rand(arr.length)]
    end

    def q(value)
      value.inspect
    end

    # positional_form(rng, scope, lines)
    #
    # format("<fmt>", <float>) -- the float arrives positionally. Emit both a
    # literal-operand form and a variable-operand form (the marshalling path may
    # differ between the two, and the variable form is the harder slot to wire).
    def positional_form(rng, scope, lines)
      fmt = pick(rng, FLOAT_FORMATS)
      f = pick(rng, FLOATS)
      v = scope.fresh_name("f")
      lines << "#{v} = #{f}"
      lines << "puts format(#{q(fmt)}, #{f})"
      lines << "puts format(#{q(fmt)}, #{v})"
    end

    # array_form(rng, scope, lines)
    #
    # "<fmt>" % [<float>] -- the float arrives in an array. Same value, different
    # marshalling path.
    def array_form(rng, scope, lines)
      fmt = pick(rng, FLOAT_FORMATS)
      f = pick(rng, FLOATS)
      v = scope.fresh_name("f")
      lines << "#{v} = #{f}"
      lines << "puts(#{q(fmt)} % [#{f}])"
      lines << "puts(#{q(fmt)} % #{v})"   # scalar % single operand
      lines << "puts(#{q(fmt)} % [#{v}])"
    end

    # mixed_form(rng, scope, lines)
    #
    # A template mixing int and float specifiers in one call so the SLOT INDEXING
    # is exercised: the int slot wired one way, the float slot another. Multiple
    # orderings (int-then-float, float-then-int, float-int-float) probe whether a
    # mis-wired float slot reads the neighbouring int's bytes or a garbage stack
    # value.
    def mixed_form(rng, scope, lines)
      ifmt = pick(rng, INT_FORMATS)
      ffmt = pick(rng, FLOAT_FORMATS)
      i = rng.rand(-99..99)
      f = pick(rng, FLOATS)
      case rng.rand(3)
      when 0
        tmpl = "#{ifmt}|#{ffmt}"
        lines << "puts format(#{q(tmpl)}, #{i}, #{f})"
        lines << "puts(#{q(tmpl)} % [#{i}, #{f}])"
      when 1
        tmpl = "#{ffmt}|#{ifmt}"
        lines << "puts format(#{q(tmpl)}, #{f}, #{i})"
        lines << "puts(#{q(tmpl)} % [#{f}, #{i}])"
      else
        f2 = pick(rng, FLOATS)
        tmpl = "#{ffmt}/#{ifmt}/#{ffmt}"
        lines << "puts format(#{q(tmpl)}, #{f}, #{i}, #{f2})"
        lines << "puts(#{q(tmpl)} % [#{f}, #{i}, #{f2}])"
      end
    end

    # arith_operand_form(rng, scope, lines)
    #
    # The float operand is the RESULT of an arithmetic expression (not a bare
    # literal), so the operand sits in a computed register/stack slot at the call
    # -- the exact condition under which a mis-wired marshalling reads the wrong
    # slot. Reduced print stays byte-stable: the arithmetic yields one of our
    # exact-representable values.
    def arith_operand_form(rng, scope, lines)
      ffmt = pick(rng, %w[%.6f %.2f %.6e %.6g])
      a = pick(rng, FLOATS)
      b = pick(rng, %w[2.0 4.0 0.5 1.0])
      expr = "(#{a} * #{b})"
      lines << "puts format(#{q(ffmt)}, #{expr})"
      lines << "puts(#{q(ffmt)} % [#{expr}])"
    end

    BUILDERS = %i[positional_form array_form mixed_form arith_operand_form].freeze

    # ------------------------------------------------------------------
    # Whole-program emitter + generator-integration shim.
    # ------------------------------------------------------------------

    def program(rng, scope, index, seed, header_lines = nil)
      scope ||= MiniScope.new
      lines = header_lines ? header_lines.dup : default_header(index, seed)

      # Cover the positional and array marshalling paths at least once, then add
      # mixed + arithmetic-operand forms (seed-driven count) for slot-indexing.
      positional_form(rng, scope, lines)
      array_form(rng, scope, lines)
      rest = %i[mixed_form arith_operand_form].shuffle(random: rng)
      rest.each { |b| send(b, rng, scope, lines) if rng.rand(3) != 0 }
      mixed_form(rng, scope, lines) # always include at least one mixed template

      lines << ""
      lines.join("\n")
    end

    def float_format_program(rng, index, seed)
      program(rng, nil, index, seed)
    end

    def default_header(index, seed)
      [
        "# fuzz-family: float_format",
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
      src = FuzzGen::FloatFormat.float_format_program(crng, i, case_seed)
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

      # The CRuby reference must be byte-stable across two runs (no repr drift).
      Tempfile.create(["fmt_selftest", ".rb"]) do |f|
        f.write(src)
        f.flush
        unless system("ruby", "-c", f.path, out: File::NULL, err: File::NULL)
          failures += 1
          warn "ruby -c FAIL seed=#{seed} index=#{i}"
          warn src
        end
        out1 = `ruby #{f.path} 2>&1`
        ok1 = $?.success?
        out2 = `ruby #{f.path} 2>&1`
        unless ok1 && $?.success?
          failures += 1
          warn "RUNTIME FAIL seed=#{seed} index=#{i}"
          warn src
          warn out1
        end
        unless out1 == out2
          failures += 1
          warn "EXEC DETERMINISM FAIL seed=#{seed} index=#{i}"
        end
      end
    end
  end

  a = FuzzGen::FloatFormat.float_format_program(Random.new(123), 5, 123)
  b = FuzzGen::FloatFormat.float_format_program(Random.new(123), 5, 123)
  if a != b
    failures += 1
    warn "DETERMINISM FAIL"
  end

  puts "float_format self-test: #{total} programs generated, #{failures} failures"
  exit(failures.zero? ? 0 : 1)
end
