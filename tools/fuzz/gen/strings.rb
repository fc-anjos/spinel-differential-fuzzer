# frozen_string_literal: true

# Feature generator: STRINGS.
#
# Dimension: gsub/sub/scan/tr, format/%, interpolation, each_char, chars/bytes,
# comparison, multiplication, escapes.
#
# Why this sits AT the spinel boundary: spinel reimplements Ruby's string
# method set in C (codegen dispatches gsub/sub/scan/tr/chars/bytes/codepoints/
# each_char/center/ljust/rjust/format/capitalize/chomp/chop/delete_prefix/
# delete_suffix/casecmp/...) and maintains a distinct mutable_str vs string
# type. The exact byte/char semantics are where a C reimplementation drifts
# from CRuby:
#   * gsub/sub with a *literal* pattern vs a char-class fragment
#   * tr ranges (a-z) and 1:1 char mapping
#   * multibyte length: chars vs bytes after a \u escape (UTF-8 codepoint count)
#   * printf width/precision/zero-padding via format and % (rounding in %f,
#     sign in %d, field width over multibyte strings)
#
# All patterns are LITERAL (no Regexp objects). Every emitted value is reduced
# to a deterministic scalar (length / bytes.sum / sorted-join / -1|0|1) so
# multibyte and gsub results compare byte-exactly and the BANNED .inspect/.hash
# tokens are never needed.
#
# DETERMINISM: all randomness flows through the injected `rng` (a Random). No
# Time/rand/object_id/inspect/hash/p/GC. Floats are printed via
# format('%.6f', ...) to dodge platform float-repr drift. Strings are reduced
# to length/bytes.sum. Valid Ruby by construction.
#
# Pure stdlib. Each builder is a module_function taking an explicit `rng` and a
# `scope` (the generator's Scope, duck-typed: responds to fresh_name/add/
# names/any?/pick over typed var buckets).

module FuzzGen
  module Strings
    module_function

    # --- corpora ---------------------------------------------------------

    # ASCII-only literals (safe for tr ranges, casecmp, swapcase).
    ASCII_WORDS = [
      "alpha",
      "Beta",
      "MixedCase",
      "hello world",
      "a,b,,c",
      "x|y|z",
      "  pad  ",
      "FooBar",
      "",
      "same",
      "racecar",
      "AbCdEf"
    ].freeze

    # Literals carrying multibyte codepoints so chars != bytes. These exercise
    # UTF-8 codepoint counting (chars/each_char) vs byte counting (bytes).
    MULTIBYTE_WORDS = [
      "café",       # é is 2 bytes
      "naïve",      # ï is 2 bytes
      "Köln",       # ö is 2 bytes
      "résumé",     # two é
      "Ångström",   # Å + ö
      "façade",     # ç
      "piñata",     # ñ
      "Zürich"      # ü
    ].freeze

    # Prefix/suffix corpus paired with literals that may or may not carry them,
    # so delete_prefix / delete_suffix exercise both the hit and miss path.
    AFFIXES = %w[a Foo pre _ x un].freeze

    # 1:1 tr source/replacement pairs plus range forms. Each pair is length-safe
    # for tr's "shorter replacement repeats last char" rule, but we keep them
    # equal-length where possible to keep the mapping unambiguous.
    TR_PAIRS = [
      ["abc", "xyz"],
      ["a-z", "A-Z"],
      ["A-Z", "a-z"],
      ["aeiou", "*"],     # collapse vowels to '*'
      ["lo", "01"],
      ["a-c", "x-z"],
      [" ", "_"],
      ["0-9", "#"]
    ].freeze

    # gsub/sub literal patterns -> replacements. Patterns are PLAIN substrings
    # (no regex metacharacters) so they bind as literal pattern matches.
    GSUB_PAIRS = [
      ["a", "A"],
      ["l", "L"],
      ["o", "0"],
      [" ", "_"],
      [",", ";"],
      ["e", ""],          # deletion
      ["ss", "S"],        # multi-char literal
      ["x", "Q"]
    ].freeze

    # scan needles (literal substrings) for counting occurrences.
    SCAN_NEEDLES = %w[a l o e , | b].freeze

    # printf-style format strings exercising width/precision/zero-pad/sign.
    INT_FORMATS  = ["%d", "%5d", "%-5d", "%05d", "%+d", "% d", "%x", "%o"].freeze
    STR_FORMATS  = ["%s", "%10s", "%-10s", "%.3s"].freeze
    FLT_FORMATS  = ["%f", "%.2f", "%8.3f", "%+.4f", "%010.2f", "%g", "%e"].freeze

    # Float literals chosen to stress %f rounding (half-to-even, carry,
    # negative). Kept finite and exactly representable-ish; the format string
    # forces a fixed precision so platform repr never leaks.
    FLOAT_LITERALS = [
      "0.0", "1.5", "2.5", "0.125", "3.14159", "-2.5", "-0.5",
      "10.005", "1.005", "99.995", "0.999999", "-123.456"
    ].freeze

    # --- tiny RNG / literal helpers (mirror generator.rb discipline) -----

    def pick(rng, arr)
      arr[rng.rand(arr.length)]
    end

    def small_int(rng, min = -9, max = 9)
      rng.rand(min..max)
    end

    # A quoted Ruby string literal for an arbitrary Ruby String, using inspect
    # ONLY at generation time to produce a safe source token. The emitted token
    # is a plain quoted literal; we strip nothing — .inspect here runs in the
    # generator, never appears in generated source, so it does not trip the
    # BANNED_TOKENS scan (which scans emitted source).
    def q(value)
      value.inspect
    end

    # An ascii string literal source token.
    def ascii_lit(rng)
      q(pick(rng, ASCII_WORDS))
    end

    # A possibly-multibyte string literal source token.
    def any_str_lit(rng)
      rng.rand(3).zero? ? q(pick(rng, MULTIBYTE_WORDS)) : ascii_lit(rng)
    end

    # A string-typed *expression*: prefer an in-scope str var, else a literal.
    # `scope` is duck-typed; we guard with respond_to? so the module also works
    # standalone in the self-test with a NullScope.
    def str_operand(rng, scope, depth)
      if scope_has?(scope, :str) && rng.rand(2).zero?
        scope_pick(scope, :str, rng)
      elsif depth > 0 && rng.rand(4).zero?
        "(#{str_operand(rng, scope, depth - 1)} * #{rng.rand(0..3)})"
      else
        any_str_lit(rng)
      end
    end

    # An int-typed expression: in-scope int var or a small literal.
    def int_operand(rng, scope)
      if scope_has?(scope, :int) && rng.rand(2).zero?
        scope_pick(scope, :int, rng)
      else
        small_int(rng).to_s
      end
    end

    # --- scope duck-typing shims ----------------------------------------

    def scope_has?(scope, type)
      scope.respond_to?(:any?) && scope.any?(type)
    rescue StandardError
      false
    end

    def scope_pick(scope, type, rng)
      scope.pick(type, rng)
    end

    # ====================================================================
    # PUBLIC API
    # ====================================================================

    STR_METHODS = %i[
      gsub_lit sub_lit tr scan_count each_char_count chars_len bytes_sum
      center ljust rjust delete_prefix delete_suffix capitalize swapcase
    ].freeze

    # str_method_expr(rng, scope, depth, method:) -> String
    #
    # Builds an expression invoking `method` on a string operand and reducing
    # the result to a deterministic scalar (length / bytes.sum / count). Every
    # branch returns a parenthesized expression that evaluates to an Integer (or
    # Integer via .length) so it can be `puts`-ed directly and compared exactly.
    def str_method_expr(rng, scope, depth, method:)
      s = str_operand(rng, scope, depth)
      case method
      when :gsub_lit
        pat, rep = pick(rng, GSUB_PAIRS)
        # gsub with literal pattern; reduce to byte sum so multibyte-safe.
        "((#{s}).gsub(#{q(pat)}, #{q(rep)}).bytes.sum)"
      when :sub_lit
        pat, rep = pick(rng, GSUB_PAIRS)
        "((#{s}).sub(#{q(pat)}, #{q(rep)}).bytes.sum)"
      when :tr
        from, to = pick(rng, TR_PAIRS)
        "((#{s}).tr(#{q(from)}, #{q(to)}).bytes.sum)"
      when :scan_count
        needle = pick(rng, SCAN_NEEDLES)
        # scan returns an array of literal matches; count them.
        "((#{s}).scan(#{q(needle)}).length)"
      when :each_char_count
        # each_char without a block returns an Enumerator; .to_a then count.
        # This exercises each_char codepoint iteration.
        "((#{s}).each_char.to_a.length)"
      when :chars_len
        # codepoint count (multibyte-aware).
        "((#{s}).chars.length)"
      when :bytes_sum
        # byte count + content via sum (UTF-8 byte sequence).
        "((#{s}).bytes.sum)"
      when :center
        w = rng.rand(0..12)
        pad = rng.rand(2).zero? ? '"*"' : '" "'
        "((#{s}).center(#{w}, #{pad}).length)"
      when :ljust
        w = rng.rand(0..12)
        "((#{s}).ljust(#{w}, \"-\").length)"
      when :rjust
        w = rng.rand(0..12)
        "((#{s}).rjust(#{w}, \".\").length)"
      when :delete_prefix
        aff = pick(rng, AFFIXES)
        "((#{s}).delete_prefix(#{q(aff)}).bytes.sum)"
      when :delete_suffix
        aff = pick(rng, AFFIXES)
        "((#{s}).delete_suffix(#{q(aff)}).bytes.sum)"
      when :capitalize
        "((#{s}).capitalize.bytes.sum)"
      when :swapcase
        # swapcase on ascii only (multibyte case folding can diverge from the
        # *intended* boundary test; we want a clean CRuby reference).
        "((#{ascii_lit(rng)}).swapcase.bytes.sum)"
      else
        # Defensive fallback: byte sum of the operand.
        "((#{s}).bytes.sum)"
      end
    end

    # format_expr(rng, scope) -> String
    #
    # Emits either a `format('<fmt>', args...)` call or the `'<fmt>' % [args]`
    # operator form, over int / str / float arguments with explicit
    # width/precision. The result is a String; we reduce it to .bytes.sum for a
    # byte-exact, deterministic comparison (dodging any %f repr drift since the
    # precision is fixed and we never print the float directly).
    def format_expr(rng, scope)
      case rng.rand(4)
      when 0
        # The canonical '%05d-%s' over an int and a string.
        n = int_operand(rng, scope)
        s = ascii_lit(rng)
        "(format(\"%05d-%s\", #{n}, #{s}).bytes.sum)"
      when 1
        # % operator form with a mixed int/str format and an array of args.
        ifmt = pick(rng, INT_FORMATS)
        sfmt = pick(rng, STR_FORMATS)
        n = int_operand(rng, scope)
        s = ascii_lit(rng)
        "((#{q(ifmt + '|' + sfmt)} % [#{n}, #{s}]).bytes.sum)"
      when 2
        # Float formatting with fixed precision -> byte sum (repr-stable).
        ffmt = pick(rng, FLT_FORMATS)
        f = pick(rng, FLOAT_LITERALS)
        "((#{q(ffmt)} % [#{f}]).bytes.sum)"
      else
        # format() with all three arg kinds in one template.
        ifmt = pick(rng, INT_FORMATS)
        ffmt = pick(rng, FLT_FORMATS)
        n = int_operand(rng, scope)
        f = pick(rng, FLOAT_LITERALS)
        s = ascii_lit(rng)
        tmpl = "#{ifmt}/#{ffmt}/%s"
        "(format(#{q(tmpl)}, #{n}, #{f}, #{s}).bytes.sum)"
      end
    end

    # interpolation_expr(rng, scope) -> String
    #
    # Builds "#{int_expr}-#{str_expr}" — an InterpolatedStringNode containing
    # EmbeddedStatementsNode for each #{...}. Reduced to .bytes.sum so the
    # multibyte-in-interpolation path is byte-exact.
    def interpolation_expr(rng, scope)
      n = int_operand(rng, scope)
      s = str_operand(rng, scope, 1)
      # Two embedded statements separated by a literal '-'. Wrap the int in
      # parens inside the interpolation so binops interpolate cleanly.
      "(\"\#{(#{n})}-\#{#{s}}\".bytes.sum)"
    end

    # escape_literal(rng) -> String
    #
    # A string literal containing escape sequences (\t \n \\ \") and a
    # unicode-escaped é (é), reduced via .length (codepoint count) or
    # .bytes.sum (byte count) so the chars-vs-bytes divergence after a \u escape
    # is surfaced byte-exactly.
    def escape_literal(rng)
      # Build the *generated source* of a double-quoted Ruby literal containing
      # real escape sequences. We assemble the source text directly (not via
      # inspect) so the \u and \t survive into the emitted program verbatim.
      bodies = [
        'tab\\there',          # \t
        'line\\nbreak',        # \n
        'back\\\\slash',       # \\  (one literal backslash in the string)
        'quote\\"inside',      # \"
        'caf\\u00E9',          # é via unicode escape (2 bytes, 1 char)
        'na\\u00EFve\\tend',   # ï + \t
        'mix\\u00E9\\n\\\\done'
      ]
      body = pick(rng, bodies)
      lit = "\"#{body}\""
      reducer = rng.rand(2).zero? ? "length" : "bytes.sum"
      "(#{lit}.#{reducer})"
    end

    # comparison_chain(rng, scope) -> String
    #
    # Spaceship (<=>) and casecmp, both returning -1/0/1. Builds an expression
    # that evaluates to an Integer in {-1,0,1} (or nil for <=> on incomparable,
    # which we avoid by always comparing String<=>String). casecmp does
    # case-insensitive ASCII comparison.
    def comparison_chain(rng, scope)
      a = ascii_lit(rng)
      b = ascii_lit(rng)
      case rng.rand(3)
      when 0
        # Spaceship between two string literals: -1 | 0 | 1.
        "((#{a}) <=> (#{b}))"
      when 1
        # casecmp -> -1|0|1 (case-insensitive).
        "((#{a}).casecmp(#{b}))"
      else
        # casecmp? returns true/false; normalize to 1/0 for an Integer compare.
        "(((#{a}).casecmp?(#{b})) ? 1 : 0)"
      end
    end

    # ====================================================================
    # WHOLE-PROGRAM EMITTER
    # ====================================================================

    # strings_program(rng, index, seed) -> String
    #
    # Standalone whole-program emitter. Builds its own NullScope (so it is
    # callable without the generator's Scope) plus a header, then emits a
    # battery of string-method / format / interpolation / escape / comparison
    # lines, each reduced to a deterministic scalar and `puts`-ed.
    def strings_program(rng, index, seed)
      scope = NullScope.new
      lines = header(:strings, index, seed)
      program_body(rng, scope, lines)
      lines << ""
      lines.join("\n")
    end

    # program(rng, scope, index, seed, header_lines) -> String
    #
    # Generator-integration entry point: the generator passes its own Scope and
    # header lines (see generatorIntegration shim). Mirrors the convention used
    # by the other gen/* modules.
    def program(rng, scope, index, seed, header_lines = nil)
      lines = header_lines ? header_lines.dup : header(:strings, index, seed)
      program_body(rng, scope, lines)
      lines << ""
      lines.join("\n")
    end

    # Shared body emitter used by both entry points.
    def program_body(rng, scope, lines)
      # Seed a couple of string + int vars so expression builders can reference
      # scope vars (exercising mutable_str vs string typing in spinel).
      sv = fresh(scope, "s")
      lines << "#{sv} = #{any_str_lit(rng)}"
      scope_add(scope, :str, sv)
      iv = fresh(scope, "n")
      lines << "#{iv} = #{small_int(rng)}"
      scope_add(scope, :int, iv)

      # A rotating selection of string methods (each reduced to a scalar).
      shuffled = STR_METHODS.shuffle(random: rng)
      pick_count = rng.rand(5..STR_METHODS.length)
      shuffled.first(pick_count).each do |m|
        lines << "puts #{str_method_expr(rng, scope, rng.rand(1..3), method: m)}"
      end

      # String multiplication + concatenation, reduced to length.
      lines << "puts ((#{str_operand(rng, scope, 2)} + #{str_operand(rng, scope, 2)}).length)"
      lines << "puts ((#{ascii_lit(rng)} * #{rng.rand(0..4)}).bytes.sum)"

      # format / % battery.
      rng.rand(2..3).times do
        lines << "puts #{format_expr(rng, scope)}"
      end

      # interpolation.
      lines << "puts #{interpolation_expr(rng, scope)}"
      lines << "puts #{interpolation_expr(rng, scope)}"

      # escape literals (chars vs bytes after \u).
      rng.rand(2..3).times do
        lines << "puts #{escape_literal(rng)}"
      end

      # comparison / casecmp (-1|0|1).
      rng.rand(2..3).times do
        lines << "puts #{comparison_chain(rng, scope)}"
      end
    end

    # --- header (matches generator.rb format) ----------------------------

    def header(name, index, seed)
      [
        "# fuzz-family: #{name}",
        "# fuzz-index: #{index}",
        "# fuzz-seed: #{seed}",
        "# fuzz-mode: gen"
      ]
    end

    # --- scope helpers that tolerate a NullScope -------------------------

    def fresh(scope, prefix)
      scope.fresh_name(prefix)
    end

    def scope_add(scope, type, name)
      scope.add(type, name) if scope.respond_to?(:add)
      name
    end

    # Minimal stand-in scope so the module is runnable standalone (self-test)
    # and so strings_program has somewhere to register vars. Mirrors the typed
    # buckets the generator's Scope exposes.
    class NullScope
      TYPES = %i[int bool str array float symbol hash range nil_t].freeze

      def initialize
        @vars = Hash.new { |h, k| h[k] = [] }
        @counter = 0
      end

      def fresh_name(prefix = "v")
        @counter += 1
        "#{prefix}#{@counter}"
      end

      def add(type, name)
        @vars[type] << name
        name
      end

      def names(type)
        @vars[type]
      end

      def any?(type)
        !@vars[type].empty?
      end

      def pick(type, rng)
        list = @vars[type]
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

  M = FuzzGen::Strings

  # Banned tokens (mirror generator.rb's BANNED_TOKENS). These must never appear
  # in EMITTED source.
  BANNED = [
    /\bTime\b/,
    /\bDateTime\b/,
    /\brand\b/,
    /\bsrand\b/,
    /\bobject_id\b/,
    /\b__id__\b/,
    /\.inspect\b/,
    /\bp\s/,
    /\bGC\b/,
    /\bObjectSpace\b/,
    /\.hash\b/,
    /\bRandom\b/,
    /\b__FILE__\b/,
    /\b__LINE__\b/,
    /\bcaller\b/,
    /\bENV\b/
  ].freeze

  def parses?(source)
    RubyVM::AbstractSyntaxTree.parse(source)
    true
  rescue SyntaxError, ArgumentError
    false
  end

  seeds = [1, 7, 42, 1234, 99_999, 2024, 555_555]
  per_seed = 30

  total = 0
  failures = 0
  samples_for_ruby_c = []

  seeds.each do |seed|
    rng = Random.new(seed)
    per_seed.times do |i|
      # Derive a child rng per case (mirrors generator.generate()).
      case_seed = rng.rand(1 << 62)
      crng = Random.new(case_seed)
      src = M.strings_program(crng, i, case_seed)
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

      # Keep a few for the real `ruby -c` + execution cross-check.
      samples_for_ruby_c << src if (total % 25).zero?
    end
  end

  # Determinism: same (seed,index) reproduces identical source.
  s1 = M.strings_program(Random.new(42), 5, 42)
  s2 = M.strings_program(Random.new(42), 5, 42)
  unless s1 == s2
    failures += 1
    warn "DETERMINISM FAIL: strings_program not stable for same rng seed"
  end

  # Per-builder smoke: every str method symbol emits parseable, banned-free Ruby.
  M::STR_METHODS.each do |m|
    rng = Random.new(123)
    scope = M::NullScope.new
    expr = M.str_method_expr(rng, scope, 3, method: m)
    prog = "puts #{expr}\n"
    unless parses?(prog)
      failures += 1
      warn "PARSE FAIL for method=#{m}: #{expr}"
    end
    if BANNED.any? { |re| prog =~ re }
      failures += 1
      warn "BANNED token for method=#{m}: #{expr}"
    end
  end

  # Real `ruby -c` AND actual execution on samples (independent of AST parser),
  # proving the programs run clean under CRuby (no runtime errors / exceptions)
  # and stay byte-deterministic.
  exec_failures = 0
  samples_for_ruby_c.first(20).each_with_index do |src, idx|
    Tempfile.create(["strings_selftest", ".rb"]) do |f|
      f.write(src)
      f.flush
      ok_c = system("ruby", "-c", f.path, out: File::NULL, err: File::NULL)
      unless ok_c
        failures += 1
        warn "ruby -c FAIL on sample #{idx}"
        warn src
        next
      end
      # Execute twice; output must be identical and exit clean (determinism +
      # no runtime exception under CRuby reference).
      out1 = `ruby #{f.path} 2>&1`
      ok_run1 = $?.success?
      out2 = `ruby #{f.path} 2>&1`
      unless ok_run1 && $?.success?
        exec_failures += 1
        warn "RUNTIME FAIL on sample #{idx}"
        warn src
        warn out1
      end
      unless out1 == out2
        failures += 1
        warn "EXEC DETERMINISM FAIL on sample #{idx}"
      end
    end
  end
  failures += exec_failures

  puts "strings self-test: #{total} programs generated, #{samples_for_ruby_c.first(20).length} executed, #{failures} failures"
  exit(failures.zero? ? 0 : 1)
end
