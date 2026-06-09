# frozen_string_literal: true

# Feature-generator module for the Spinel fuzzer: the NUMERIC dimension.
#
# Targets the float / mixed-int-float / integer-overflow boundary:
#
#   * Spinel infers a distinct `float` type (spinel_analyze.rb ~line 3592/3838)
#     and a `float_array` (~line 4225). Float arithmetic is supported, but
#     mixed int/float promotion and rounding (banker's rounding / .round
#     half-to-even) are classic divergence sites.
#   * Spinel has THREE int-overflow ABIs selected by SPINEL_INT_OVERFLOW
#     (spinel_codegen.rb line 60: raise | wrap | promote; promote widens int
#     slots to sp_Bigint via sp_bigint_new_int). The SAME boundary literal
#     therefore exercises three different lowering paths. BOUNDARY_INTS straddle
#     2**31 (32-bit slot edge) and 2**63 (64-bit edge) so wrap-mode wraps where
#     CRuby promotes to Bignum, and promote-mode routes through sp_bigint_new_int.
#   * Negative-operand modulo differs between C `%` (sign-of-dividend) and Ruby
#     `%` (sign-of-divisor) — a perennial AOT compiler bug.
#
# DETERMINISM / VALID-CRUBY CONTRACT (mirrors tools/fuzz/generator.rb):
#   * All randomness flows through an injected `rng` (a Random). No Time/rand/
#     object_id/inspect/hash/GC/p — those are BANNED_TOKENS and scanned out.
#   * Floats are printed via `format('%.6f', x)` so platform float-repr drift
#     never leaks; integers/bignums print exactly.
#   * Divisors and moduli are kept LITERAL NONZERO so the reference CRuby run is
#     always well-defined; any observed diff is spinel's fault, not a shared
#     error. We never construct NaN/Infinity (no 0.0/0.0, no Float::INFINITY
#     arithmetic that domain-errors on .to_i), so CRuby stays clean.
#   * Overflow arithmetic adds/subtracts/multiplies a SMALL literal against a
#     boundary int so the result is a well-defined Bignum under CRuby in every
#     overflow mode's reference.
#
# Pure Ruby stdlib. Defines module FuzzGen::Numeric with module_function
# builders, each taking an explicit `rng` and (where relevant) a `scope`.

module FuzzGen
  module Numeric
    module_function

    # ----------------------------------------------------------------------
    # Scope adapter.
    #
    # generator.rb's Scope exposes any?(type)/pick(type,rng)/names(type), and
    # the integration widens Scope::TYPES to include :float. We never assume the
    # extended keys exist: every access is guarded so this module also works
    # against an un-widened scope (or a nil scope) for standalone self-testing.
    # ----------------------------------------------------------------------

    def scope_any?(scope, type)
      return false if scope.nil?

      scope.any?(type)
    rescue KeyError, NoMethodError
      false
    end

    def scope_pick(scope, type, rng)
      scope.pick(type, rng)
    rescue KeyError, NoMethodError
      nil
    end

    # ----------------------------------------------------------------------
    # Literal helpers.
    # ----------------------------------------------------------------------

    # A small float literal with an exact, short decimal representation so the
    # CRuby reference value is unambiguous and `%.6f` printing is stable.
    FLOAT_LITERALS = [
      "0.0", "1.0", "-1.0", "0.5", "-0.5", "2.5", "-2.5", "1.5", "-1.5",
      "0.25", "-0.25", "3.75", "-3.75", "10.0", "-10.0", "100.5", "-100.5",
      # half-integers and quarter-integers stress banker's rounding (.round
      # half-to-even): 0.5 -> 0, 1.5 -> 2, 2.5 -> 2, 3.5 -> 4 under Ruby.
      "0.5", "1.5", "2.5", "3.5", "4.5", "-0.5", "-1.5", "-2.5", "-3.5"
    ].freeze

    def float_literal(rng)
      FLOAT_LITERALS[rng.rand(FLOAT_LITERALS.length)]
    end

    # Small nonzero int literal usable as a divisor/factor without overflowing
    # CRuby into anything surprising. Always nonzero.
    def small_nonzero(rng)
      n = 0
      n = rng.rand(-7..7) while n.zero?
      n
    end

    # Deterministic, RNG-injected element pick. Avoids monkeypatching Array (so
    # the host generator.rb is untouched) and never touches Kernel#rand.
    def pick_one(list, rng)
      list[rng.rand(list.length)]
    end

    # Small nonzero POSITIVE int (for repeated multiply factors / shifts).
    def small_pos(rng)
      rng.rand(1..7)
    end

    # ----------------------------------------------------------------------
    # BOUNDARY_INTS — chosen to straddle the 32-bit (2**31) and 64-bit (2**63)
    # int-slot edges so wrap / promote / raise overflow modes diverge.
    # ----------------------------------------------------------------------
    BOUNDARY_INTS = [
      2**31 - 1, 2**31, -2**31,
      2**63 - 1, 2**63, -2**63, 2**63 - 2,
      0, 1, -1
    ].freeze

    # Emit a boundary int as a source literal. Large magnitudes are emitted as
    # explicit `(2**31)` style power expressions where that reads cleaner, but a
    # plain decimal literal is always valid CRuby too; we use decimal literals
    # so the lexer (and spinel's literal path) sees a single IntegerNode.
    def boundary_int_literal(rng)
      BOUNDARY_INTS[rng.rand(BOUNDARY_INTS.length)].to_s
    end

    # ----------------------------------------------------------------------
    # float_expr — float literals, var refs, +/-/*//, float<->int promotion,
    # .floor/.ceil/.round/.abs/.to_i, Float comparisons.
    #
    # Returns a String that evaluates to a Float (or, for the .to_i / comparison
    # leaves, an Integer / boolean — those are still valid float-dimension
    # exprs and the program emitter prints them type-appropriately). To keep the
    # contract simple, float_expr ALWAYS yields a Float-valued expression; the
    # integer/boolean-producing methods are reachable via mixed_arith_expr and
    # the dedicated chained-call leaf which re-floats with `.to_f` / `* 1.0`.
    # ----------------------------------------------------------------------
    FLOAT_BINOPS = %w[+ - *].freeze

    def float_expr(rng, scope, depth)
      if depth <= 0
        if scope_any?(scope, :float) && rng.rand(2).zero?
          return scope_pick(scope, :float, rng)
        end

        return float_literal(rng)
      end

      case rng.rand(7)
      when 0
        float_literal(rng)
      when 1
        scope_any?(scope, :float) ? scope_pick(scope, :float, rng) : float_literal(rng)
      when 2
        op = FLOAT_BINOPS[rng.rand(FLOAT_BINOPS.length)]
        "(#{float_expr(rng, scope, depth - 1)} #{op} #{float_expr(rng, scope, depth - 1)})"
      when 3
        # Guarded float division: rhs literal nonzero float so it is always
        # well-defined (no 0.0 divisor => no Infinity/NaN). Float / nonzero-int
        # is finite too.
        denom = small_nonzero(rng)
        "(#{float_expr(rng, scope, depth - 1)} / #{denom}.0)"
      when 4
        # Unary rounding family. .floor/.ceil/.round/.abs all return well-defined
        # values for any finite float; we re-float the integer-returning ones
        # with `.to_f` so float_expr's result type stays Float. `.round`
        # specifically stresses banker's rounding (half-to-even).
        inner = float_expr(rng, scope, depth - 1)
        meth = pick_one(%w[floor ceil round abs], rng)
        if meth == "abs"
          "(#{inner}.abs)"
        else
          "(#{inner}.#{meth}.to_f)"
        end
      when 5
        # int->float promotion: an integer literal/var lifted via `.to_f` then
        # combined with a float subtree.
        op = FLOAT_BINOPS[rng.rand(FLOAT_BINOPS.length)]
        "(#{small_nonzero(rng)}.to_f #{op} #{float_expr(rng, scope, depth - 1)})"
      else
        # fdiv keeps a Float result for any nonzero literal divisor.
        "(#{float_expr(rng, scope, depth - 1)}.fdiv(#{small_nonzero(rng)}))"
      end
    end

    # ----------------------------------------------------------------------
    # mixed_arith_expr — int op float forcing promotion. Result is a Float.
    #   e.g. (3 + 2.5), (x.to_f / n), (i * 1.5)
    # ----------------------------------------------------------------------
    def mixed_arith_expr(rng, scope, depth)
      depth = 0 if depth.nil? || depth.negative?

      int_leaf =
        if scope_any?(scope, :int) && rng.rand(2).zero?
          scope_pick(scope, :int, rng)
        else
          rng.rand(-20..20).to_s
        end
      float_leaf = float_expr(rng, scope, [depth - 1, 0].max)

      case rng.rand(5)
      when 0
        op = FLOAT_BINOPS[rng.rand(FLOAT_BINOPS.length)]
        "(#{int_leaf} #{op} #{float_leaf})"
      when 1
        op = FLOAT_BINOPS[rng.rand(FLOAT_BINOPS.length)]
        "(#{float_leaf} #{op} #{int_leaf})"
      when 2
        # `.to_f` promotion then division by a nonzero literal int (no zero div).
        "((#{int_leaf}).to_f / #{small_nonzero(rng)})"
      when 3
        # int * float literal (classic promotion site).
        "((#{int_leaf}) * #{float_literal(rng)})"
      else
        # float divided by nonzero int, then re-mixed.
        "((#{float_leaf}) / #{small_nonzero(rng)} + #{int_leaf})"
      end
    end

    # ----------------------------------------------------------------------
    # overflow_arith_expr — a boundary int +/-/* a small literal so the result
    # CROSSES the 2**31 / 2**63 edge under wrap-mode, while CRuby stays a
    # well-defined Bignum. Returns an Integer-valued expression.
    #
    # Guard rationale: CRuby has arbitrary-precision integers, so
    # `(2**63) + 5`, `(2**31 - 1) * 3`, `(-2**63) - 7` are all exact Bignums
    # with no exceptions — the reference run is always clean. Under spinel's
    # wrap-mode the same expression wraps the fixed-width slot (divergence); the
    # promote-mode routes through sp_bigint_new_int (different path); raise-mode
    # raises (divergence). Every cell is a candidate diff.
    # ----------------------------------------------------------------------
    def overflow_arith_expr(rng, scope)
      base = boundary_int_literal(rng)

      case rng.rand(6)
      when 0
        "(#{base} + #{small_pos(rng)})"
      when 1
        "(#{base} - #{small_pos(rng)})"
      when 2
        # Multiply by a small factor: (2**31-1)*N decisively crosses 2**31, and
        # (2**63-1)*N crosses 2**63 — both well past the fixed-width edge.
        "(#{base} * #{small_pos(rng) + 1})"
      when 3
        # Boundary + boundary: pushes a 64-bit edge sum into Bignum territory.
        "(#{base} + #{boundary_int_literal(rng)})"
      when 4
        # int var (if any) added to a boundary literal — promotes the whole
        # expression to the boundary's path.
        v = scope_any?(scope, :int) ? scope_pick(scope, :int, rng) : rng.rand(1..9).to_s
        "(#{base} + #{v})"
      else
        # Subtract a boundary from a small literal: (5 - (-2**63)) is a large
        # positive Bignum; (5 - 2**63) a large negative one.
        "(#{small_pos(rng)} - #{base})"
      end
    end

    # ----------------------------------------------------------------------
    # div_mod_edge_expr — negative dividend modulo, divmod, fdiv, integer/float
    # division. Divisor is ALWAYS a literal nonzero, so CRuby never raises
    # ZeroDivisionError; any diff is spinel mis-lowering the C `%`/`/` semantics.
    #
    # The headline target: Ruby `%` takes the sign of the DIVISOR
    #   (-7 % 3) == 2,  (7 % -3) == -2
    # whereas C `%` takes the sign of the DIVIDEND — a perennial AOT bug.
    # Integer `/` floors toward -inf in Ruby; C truncates toward zero.
    #
    # Returns a String. The kind of value (int / float / pair) is encoded so the
    # program emitter prints it correctly; here we always reduce to a printable
    # scalar form so callers can `puts` it directly.
    # ----------------------------------------------------------------------
    def div_mod_edge_expr(rng, scope)
      # Dividend: lean toward NEGATIVE values to exercise sign-of-divisor.
      dividend =
        if scope_any?(scope, :int) && rng.rand(3).zero?
          scope_pick(scope, :int, rng)
        else
          "(#{rng.rand(-40..40)})"
        end
      divisor = nonzero_divisor(rng)

      case rng.rand(6)
      when 0
        # Ruby modulo (sign-of-divisor). divisor may be negative literal.
        "(#{dividend} % #{divisor})"
      when 1
        # Floored integer division.
        "(#{dividend} / #{divisor})"
      when 2
        # divmod returns [q, r]; reduce to a stable scalar (q*1000 + r-ish would
        # overflow readability, so join the pair deterministically).
        "(#{dividend}.divmod(#{divisor}).join(\",\"))"
      when 3
        # remainder differs from % for negative operands (sign-of-dividend);
        # printing both via this and the % case surfaces the divergence pair.
        "(#{dividend}.remainder(#{divisor}))"
      when 4
        # fdiv -> Float; printed via %.6f by the emitter.
        "(#{dividend}.fdiv(#{divisor}))"
      else
        # Mixed integer/float division: dividend.to_f / nonzero int.
        "((#{dividend}).to_f / #{divisor})"
      end
    end

    # A nonzero divisor literal; deliberately includes negatives to drive the
    # sign-of-divisor modulo divergence. Never zero.
    def nonzero_divisor(rng)
      choices = [-7, -5, -3, -2, 2, 3, 4, 5, 7]
      choices[rng.rand(choices.length)]
    end

    # Classifier so the program emitter prints each div_mod form correctly:
    # divmod -> a "q,r" string; fdiv / .to_f -> a Float; otherwise an Integer.
    # We re-derive intent by inspecting the emitted string for the marker calls.
    def div_mod_print(name, expr_src, lines)
      if expr_src.include?(".divmod(")
        lines << "#{name} = #{expr_src}"
        lines << "puts #{name}"
      elsif expr_src.include?(".fdiv(") || expr_src.include?(".to_f")
        lines << "#{name} = #{expr_src}"
        lines << "puts format('%.6f', #{name})"
      else
        lines << "#{name} = #{expr_src}"
        lines << "puts #{name}"
      end
    end

    # ----------------------------------------------------------------------
    # numeric_program — whole-program emitter. Builds a handful of float vars,
    # mixed-arith vars, overflow exprs, and div/mod edges, then prints them all
    # deterministically (floats via %.6f, bignums/ints exactly, divmod pairs as
    # joined strings).
    #
    # `header_lines` is an array of comment lines (the caller's header(...)). If
    # nil, a minimal self-contained header is emitted so the module is runnable
    # standalone in its own self-test.
    # ----------------------------------------------------------------------
    def numeric_program(rng, index, seed, scope: nil, header_lines: nil, max_depth: 4)
      scope ||= LocalScope.new
      lines = header_lines ? header_lines.dup : default_header(index, seed)

      max_depth = [Integer(max_depth), 1].max

      # 1) Float bindings (seed the scope so later exprs can reference them).
      rng.rand(1..3).times do
        name = scope.fresh_name("f")
        lines << "#{name} = #{float_expr(rng, scope, rng.rand(1..max_depth))}"
        scope.add(:float, name)
      end

      # 2) A couple of int bindings to feed mixed/overflow/div-mod exprs.
      rng.rand(1..2).times do
        name = scope.fresh_name("i")
        lines << "#{name} = #{rng.rand(-30..30)}"
        scope.add(:int, name)
      end

      # 3) Print all float vars via fixed-format to dodge repr drift.
      scope.names(:float).each do |n|
        lines << "puts format('%.6f', #{n})"
      end

      # 4) Mixed-arith results (Float-valued).
      rng.rand(1..3).times do
        m = scope.fresh_name("m")
        lines << "#{m} = #{mixed_arith_expr(rng, scope, rng.rand(1..max_depth))}"
        lines << "puts format('%.6f', #{m})"
        scope.add(:float, m)
      end

      # 5) Overflow-boundary integer expressions (Integer/Bignum-valued; print
      #    exactly — these are the wrap-vs-promote-vs-raise divergence sites).
      rng.rand(2..4).times do
        o = scope.fresh_name("o")
        lines << "#{o} = #{overflow_arith_expr(rng, scope)}"
        lines << "puts #{o}"
        scope.add(:int, o)
      end

      # 6) A standalone boundary literal printed directly (exercises the literal
      #    lowering path under each overflow mode without any arithmetic).
      lines << "puts #{boundary_int_literal(rng)}"

      # 7) Division / modulo edges (negative dividend, sign-of-divisor, divmod,
      #    fdiv). Printed type-appropriately.
      rng.rand(2..4).times do |k|
        d = scope.fresh_name("d")
        expr = div_mod_edge_expr(rng, scope)
        div_mod_print(d, expr, lines)
      end

      # 8) Float comparisons (Float <=> / < / ==) — booleans printed as-is.
      rng.rand(1..2).times do
        op = pick_one(%w[< <= > >= == !=], rng)
        a = float_expr(rng, scope, rng.rand(1..max_depth))
        b = float_expr(rng, scope, rng.rand(1..max_depth))
        lines << "puts(#{a} #{op} #{b})"
      end

      # 9) A float -> int conversion chain (.floor/.ceil/.round/.to_i),
      #    printed as an exact integer (the rounding-mode divergence site).
      conv = pick_one(%w[floor ceil round to_i], rng)
      lines << "puts (#{float_expr(rng, scope, rng.rand(1..max_depth))}).#{conv}"

      lines << ""
      lines.join("\n")
    end

    # ----------------------------------------------------------------------
    # Standalone fallbacks (only used when no host Scope/header is injected).
    # ----------------------------------------------------------------------

    def default_header(index, seed)
      [
        "# fuzz-family: numeric",
        "# fuzz-index: #{index}",
        "# fuzz-seed: #{seed}",
        "# fuzz-mode: standalone"
      ]
    end

    # A minimal Scope shim mirroring generator.rb's Scope API (any?/pick/names/
    # add/fresh_name) for the :int and :float types this module needs. The real
    # run injects generator.rb's (widened) Scope instead.
    class LocalScope
      def initialize
        @vars = { int: [], float: [], bool: [], str: [], array: [] }
        @counter = 0
      end

      def fresh_name(prefix = "v")
        @counter += 1
        "#{prefix}#{@counter}"
      end

      def add(type, name)
        (@vars[type] ||= []) << name
        name
      end

      def names(type)
        @vars.fetch(type, [])
      end

      def any?(type)
        !names(type).empty?
      end

      def pick(type, rng)
        list = names(type)
        return nil if list.empty?

        list[rng.rand(list.length)]
      end
    end
  end
end

# ---------------------------------------------------------------------------
# Self-test (guarded so it never runs on require).
# ---------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  require "tempfile"

  # Local copy of the generator's banned-token list (kept in sync); these must
  # never appear in emitted source.
  BANNED_TOKENS = [
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

  seeds = [1, 7, 42, 1234, 99_999, 2024, 13, 777]
  per_seed = 40
  total = 0
  failures = 0
  samples = []

  seeds.each do |seed|
    rng = Random.new(seed)
    per_seed.times do |i|
      src = FuzzGen::Numeric.numeric_program(rng, i, seed)
      total += 1
      samples << [seed, i, src]

      unless parses?(src)
        failures += 1
        warn "PARSE FAIL seed=#{seed} index=#{i}"
        warn src
        next
      end

      hit = BANNED_TOKENS.find { |re| src =~ re }
      next unless hit

      failures += 1
      warn "BANNED TOKEN #{hit.inspect} seed=#{seed} index=#{i}"
      warn src
    end
  end

  # Determinism: same (seed,index sequence) reproduces identical source.
  a_rng = Random.new(42)
  b_rng = Random.new(42)
  3.times do |i|
    a = FuzzGen::Numeric.numeric_program(a_rng, i, 42)
    b = FuzzGen::Numeric.numeric_program(b_rng, i, 42)
    unless a == b
      failures += 1
      warn "DETERMINISM FAIL at index=#{i}"
    end
  end

  # Cross-check every sample under a real `ruby -c` AND actually RUN one to
  # prove the reference CRuby execution is clean (no ZeroDivisionError,
  # FloatDomainError, etc.). Running validates the overflow/div-mod guards.
  ruby_c_failures = 0
  run_failures = 0
  samples.each_with_index do |(seed, idx, src), n|
    Tempfile.create(["numeric_selftest", ".rb"]) do |f|
      f.write(src)
      f.flush
      ok = system("ruby", "-c", f.path, out: File::NULL, err: File::NULL)
      unless ok
        ruby_c_failures += 1
        warn "ruby -c FAIL seed=#{seed} index=#{idx}"
        warn src
      end
      # Execute a subset (every 17th) to keep the self-test fast while still
      # proving the reference run is exception-free under all three modes.
      next unless (n % 17).zero?

      %w[raise wrap promote].each do |mode|
        ran = system({ "SPINEL_INT_OVERFLOW" => mode }, "ruby", f.path,
                     out: File::NULL, err: File::NULL)
        unless ran
          # NOTE: SPINEL_INT_OVERFLOW only affects spinel, not CRuby; we set it
          # for parity but CRuby ignores it. A failure here means our emitted
          # CRuby reference is not clean — a real bug in the generator.
          run_failures += 1
          warn "ruby RUN FAIL (mode=#{mode}) seed=#{seed} index=#{idx}"
          warn src
        end
      end
    end
  end

  failures += ruby_c_failures + run_failures

  puts "numeric self-test: #{total} programs, #{ruby_c_failures} ruby-c failures, " \
       "#{run_failures} run failures, #{failures} total failures"
  exit(failures.zero? ? 0 : 1)
end
