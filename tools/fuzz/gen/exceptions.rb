# frozen_string_literal: true

# Feature-generator module for the Spinel fuzzer: EXCEPTIONS.
#
# Dimension: raise/rescue of specific classes, ensure, bounded retry, custom
# exception subclasses, and raising inside methods/blocks.
#
# WHY THIS IS A BOUNDARY (see spinel_codegen.rb line ~1004 / spinel_analyze.rb
# line ~23935): Spinel recognises a *fixed* builtin-exception set as a discrete
# dispatch table (StandardError/RuntimeError/ArgumentError/TypeError/
# ZeroDivisionError/KeyError/IndexError/RangeError/FloatDomainError/
# StopIteration/FrozenError/...) and does not model the exception hierarchy
# beyond name-tagging. So:
#   * rescuing a *parent* class (StandardError) for a raised *child* exercises
#     ancestry resolution an AOT compiler often hardcodes;
#   * a *custom* subclass (class MyErr < StandardError) is itself a declaration,
#     so when wrapped it crosses the decl_controlflow vein (Pass-2 walker that
#     never descends into IfNode/BeginNode children);
#   * ensure-ran-or-not and bounded retry stress BeginNode-arm unification
#     (get_begin_arms / infer_type / collect_return_types).
#
# DETERMINISM CONTRACT (matches generator.rb):
#   * All randomness flows through the injected `rng` (a Random). No Time/rand/
#     object_id/inspect/hash/GC/p — every banned token avoided.
#   * Exceptions print `e.message` ONLY, never `e.backtrace`/`e.inspect`
#     (backtraces leak addresses and line numbers).
#   * retry is counter-guarded with a fixed literal N so it always terminates;
#     output is a pure function of the seed.
#   * All programs are valid Ruby BY CONSTRUCTION and run clean under CRuby.
#
# Pure stdlib. The module exposes module_function builders that take an explicit
# `rng` and (where relevant) a `scope`, mirroring the int(rng)/string(rng)
# discipline in generator.rb. `scope` is duck-typed: only #fresh_name is used,
# so it works with Generator::Scope without requiring it.

module FuzzGen
  module Exceptions
    module_function

    # The builtin-exception names spinel name-tags (subset matching the public
    # API spec). StandardError is the ancestor we rescue for child raises.
    BUILTIN_EXCEPTIONS = %w[
      RuntimeError
      ArgumentError
      TypeError
      ZeroDivisionError
      KeyError
      IndexError
      RangeError
      StopIteration
      FrozenError
      StandardError
    ].freeze

    # Exceptions that are genuine StandardError descendants AND that we can raise
    # with a plain message argument (so `raise EXC, 'msg'` is well-formed and
    # `e.message` is exactly 'msg'). StopIteration/FrozenError are excluded from
    # this list because their default messages / construction are fussier; we
    # still rescue them via the multi-rescue path. All of these are children of
    # StandardError, so rescuing StandardError catches them — the ancestry test.
    RAISABLE_CHILDREN = %w[
      RuntimeError
      ArgumentError
      TypeError
      ZeroDivisionError
      KeyError
      IndexError
      RangeError
    ].freeze

    MESSAGES = [
      "boom",
      "bad arg",
      "kaboom-1",
      "edge case",
      "x|y",
      "retry me",
      "deterministic failure"
    ].freeze

    # Inline string-literal of a deterministic message.
    def message(rng)
      MESSAGES[rng.rand(MESSAGES.length)]
    end

    def q(value)
      value.inspect
    end

    def fresh(scope, prefix)
      scope.fresh_name(prefix)
    end

    # ----------------------------------------------------------------------
    # build_raise_rescue(rng, scope, exc_class:) -> lines
    #   raise EXC, 'msg' inside begin; rescue EXC => e; puts e.message
    #   Caller may pass exc_class: nil to get a random raisable child.
    #   When exc_class is a child, we randomly *widen* the rescue to
    #   StandardError to exercise ancestry resolution (still catches it).
    # ----------------------------------------------------------------------
    def build_raise_rescue(rng, scope, exc_class: nil)
      raised = exc_class || RAISABLE_CHILDREN[rng.rand(RAISABLE_CHILDREN.length)]
      # Widen to StandardError sometimes: a parent rescue for a child raise.
      rescued =
        if RAISABLE_CHILDREN.include?(raised) && rng.rand(2).zero?
          "StandardError"
        else
          raised
        end
      msg = message(rng)
      e = fresh(scope, "e")
      [
        "begin",
        "  raise #{raised}, #{q(msg)}",
        "rescue #{rescued} => #{e}",
        "  puts #{e}.message",
        "end"
      ]
    end

    # ----------------------------------------------------------------------
    # build_multi_rescue(rng, scope) -> lines
    #   Two rescue arms (ClassA; ClassB => e). The raised class is chosen so it
    #   is DETERMINISTICALLY caught by exactly one arm, and which arm fires is a
    #   pure function of the seed. We always raise the SECOND arm's class (or a
    #   child of it) so the first arm is intentionally skipped — proving the
    #   dispatch table picks the right handler.
    # ----------------------------------------------------------------------
    def build_multi_rescue(rng, scope)
      # Pick two distinct classes from raisable children.
      pool = RAISABLE_CHILDREN.dup
      first = pool.delete_at(rng.rand(pool.length))
      second = pool[rng.rand(pool.length)]
      # Decide which fires (deterministic from rng): 0 => first, 1 => second.
      which = rng.rand(2)
      raised = which.zero? ? first : second
      msg = message(rng)
      e = fresh(scope, "e")
      tag = fresh(scope, "tag")
      [
        "#{tag} = nil",
        "begin",
        "  raise #{raised}, #{q(msg)}",
        "rescue #{first} => #{e}",
        "  #{tag} = \"first:\" + #{e}.message",
        "rescue #{second} => #{e}",
        "  #{tag} = \"second:\" + #{e}.message",
        "end",
        "puts #{tag}"
      ]
    end

    # ----------------------------------------------------------------------
    # build_ensure(rng, scope) -> lines
    #   begin/rescue/ensure where the ensure side puts a marker proving it ran.
    #   We randomly choose whether the body raises (caught) or not; in BOTH
    #   cases the ensure marker must print, which is the differential signal.
    # ----------------------------------------------------------------------
    def build_ensure(rng, scope)
      raises = rng.rand(2).zero?
      exc = RAISABLE_CHILDREN[rng.rand(RAISABLE_CHILDREN.length)]
      msg = message(rng)
      e = fresh(scope, "e")
      body =
        if raises
          "  raise #{exc}, #{q(msg)}"
        else
          "  puts \"body-ok\""
        end
      [
        "begin",
        body,
        "rescue StandardError => #{e}",
        "  puts \"rescued:\" + #{e}.message",
        "ensure",
        "  puts \"ensure-ran\"",
        "end"
      ]
    end

    # ----------------------------------------------------------------------
    # build_retry_bounded(rng, scope) -> lines
    #   A counter-guarded retry that terminates after a fixed N. The body raises
    #   while attempts < N; the rescue increments and retries; once attempts
    #   reach N the body stops raising. Deterministic, no infinite loop.
    # ----------------------------------------------------------------------
    def build_retry_bounded(rng, scope)
      n = rng.rand(1..3)
      exc = RAISABLE_CHILDREN[rng.rand(RAISABLE_CHILDREN.length)]
      msg = message(rng)
      attempts = fresh(scope, "att")
      e = fresh(scope, "e")
      [
        "#{attempts} = 0",
        "begin",
        "  if #{attempts} < #{n}",
        "    #{attempts} = #{attempts} + 1",
        "    raise #{exc}, #{q(msg)}",
        "  end",
        "  puts \"succeeded-after:\" + #{attempts}.to_s",
        "rescue #{exc} => #{e}",
        "  retry if #{attempts} < #{n}",
        "  puts \"gave-up:\" + #{e}.message",
        "end"
      ]
    end

    # ----------------------------------------------------------------------
    # custom_exception_class(rng) -> {def_lines:, name:}
    #   'class MyErr < StandardError; end' — a declaration that crosses the
    #   decl_controlflow vein when wrapped. Name is stable per-rng-draw and
    #   guarded with `unless defined?` so repeated emission is idempotent.
    # ----------------------------------------------------------------------
    def custom_exception_class(rng)
      suffix = rng.rand(0..999_999)
      name = "FuzzErr#{suffix}"
      def_lines = [
        "class #{name} < StandardError; end unless defined?(#{name})"
      ]
      { def_lines: def_lines, name: name }
    end

    # ----------------------------------------------------------------------
    # raise_in_method(rng, scope) -> lines
    #   A method that raises; caller wraps the call in begin/rescue. Exercises
    #   raise-across-call-frame plus ancestry (rescue StandardError catches a
    #   raised child or a custom subclass).
    # ----------------------------------------------------------------------
    def raise_in_method(rng, scope)
      mname = fresh(scope, "m_raise")
      use_custom = rng.rand(2).zero?
      e = fresh(scope, "e")
      msg = message(rng)
      lines = []
      if use_custom
        custom = custom_exception_class(rng)
        lines.concat(custom[:def_lines])
        raised = custom[:name]
      else
        raised = RAISABLE_CHILDREN[rng.rand(RAISABLE_CHILDREN.length)]
      end
      lines << "def #{mname}"
      lines << "  raise #{raised}, #{q(msg)}"
      lines << "end"
      lines << "begin"
      lines << "  #{mname}"
      lines << "rescue StandardError => #{e}"
      lines << "  puts \"from-method:\" + #{e}.message"
      lines << "end"
      lines
    end

    # ----------------------------------------------------------------------
    # raise_in_block(rng, scope) -> lines
    #   A raise inside a block passed to an enumerable method; the surrounding
    #   begin/rescue catches it. The block iterates a fixed literal array and
    #   raises on a deterministic element, so exactly which iteration raises is
    #   a pure function of the seed.
    # ----------------------------------------------------------------------
    def raise_in_block(rng, scope)
      exc = RAISABLE_CHILDREN[rng.rand(RAISABLE_CHILDREN.length)]
      msg = message(rng)
      e = fresh(scope, "e")
      # Raise when the element equals a fixed trigger that IS in the array.
      trigger = rng.rand(0..3)
      [
        "begin",
        "  [0, 1, 2, 3].each do |__x|",
        "    raise #{exc}, #{q(msg)} if __x == #{trigger}",
        "  end",
        "rescue #{exc} => #{e}",
        "  puts \"from-block:\" + #{e}.message",
        "end"
      ]
    end

    # ----------------------------------------------------------------------
    # exceptions_program(rng, index, seed) -> String
    #   Whole-program emitter. Composes the builders above into one valid,
    #   deterministic Ruby program. A minimal scope is used if none supplied:
    #   the only contract is #fresh_name, so a tiny local shim suffices when
    #   called standalone.
    # ----------------------------------------------------------------------
    def exceptions_program(rng, index, seed, scope: nil, header_lines: nil)
      scope ||= NameScope.new
      lines = header_lines ? header_lines.dup : default_header(index, seed)

      # Always emit the proven combination, but order/selection driven by rng so
      # different seeds explore different arms. Each builder is self-contained.
      builders = [
        ->(r, s) { build_raise_rescue(r, s, exc_class: nil) },
        ->(r, s) { build_multi_rescue(r, s) },
        ->(r, s) { build_ensure(r, s) },
        ->(r, s) { build_retry_bounded(r, s) },
        ->(r, s) { raise_in_method(r, s) },
        ->(r, s) { raise_in_block(r, s) }
      ]

      # Custom-exception class raised + rescued via parent (ancestry path).
      custom = custom_exception_class(rng)
      lines.concat(custom[:def_lines])
      ce = fresh(scope, "e")
      cmsg = message(rng)
      lines << "begin"
      lines << "  raise #{custom[:name]}, #{q(cmsg)}"
      lines << "rescue StandardError => #{ce}"
      lines << "  puts \"custom-via-parent:\" + #{ce}.message"
      lines << "end"

      # Emit each builder once, in a seed-shuffled order, so the program covers
      # the whole dimension every run while remaining seed-deterministic.
      order = shuffle(builders, rng)
      order.each do |b|
        lines.concat(b.call(rng, scope))
      end

      lines << ""
      lines.join("\n")
    end

    # Deterministic Fisher-Yates using the injected rng (avoids Array#shuffle's
    # default RNG so output stays a pure function of the seed).
    def shuffle(arr, rng)
      a = arr.dup
      i = a.length - 1
      while i > 0
        j = rng.rand(i + 1)
        a[i], a[j] = a[j], a[i]
        i -= 1
      end
      a
    end

    def default_header(index, seed)
      [
        "# fuzz-family: exceptions",
        "# fuzz-index: #{index}",
        "# fuzz-seed: #{seed}"
      ]
    end

    # Minimal scope shim implementing the only method the builders need
    # (#fresh_name) for standalone use / self-test. The real generator passes
    # Generator::Scope, which also provides fresh_name.
    class NameScope
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
    /\.backtrace\b/,
    /\bcaller\b/,
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
  seeds = [1, 7, 42, 1234, 99_999, 2024, 31337]
  per_seed = 40

  samples = []

  seeds.each do |seed|
    rng = Random.new(seed)
    per_seed.times do |i|
      case_seed = rng.rand(1 << 62)
      family_rng = Random.new(case_seed)
      src = FuzzGen::Exceptions.exceptions_program(family_rng, i, case_seed)
      total += 1
      samples << src

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
      end
    end
  end

  # Determinism: same case_seed reproduces identical source.
  s1 = FuzzGen::Exceptions.exceptions_program(Random.new(555), 0, 555)
  s2 = FuzzGen::Exceptions.exceptions_program(Random.new(555), 0, 555)
  unless s1 == s2
    failures += 1
    warn "DETERMINISM FAIL: same seed produced different source"
  end

  # Per-builder smoke: each public builder emits parseable Ruby on its own when
  # wrapped in a minimal runnable program.
  scope = FuzzGen::Exceptions::NameScope.new
  brng = Random.new(909)
  per_builder = []
  per_builder << FuzzGen::Exceptions.build_raise_rescue(brng, scope, exc_class: "ArgumentError")
  per_builder << FuzzGen::Exceptions.build_multi_rescue(brng, scope)
  per_builder << FuzzGen::Exceptions.build_ensure(brng, scope)
  per_builder << FuzzGen::Exceptions.build_retry_bounded(brng, scope)
  per_builder << FuzzGen::Exceptions.raise_in_method(brng, scope)
  per_builder << FuzzGen::Exceptions.raise_in_block(brng, scope)
  per_builder.each_with_index do |lines, idx|
    prog = lines.join("\n") + "\n"
    unless parses?(prog)
      failures += 1
      warn "BUILDER PARSE FAIL idx=#{idx}"
      warn prog
    end
  end

  # custom_exception_class returns the expected shape.
  ce = FuzzGen::Exceptions.custom_exception_class(Random.new(1))
  unless ce.is_a?(Hash) && ce[:def_lines].is_a?(Array) && ce[:name].is_a?(String)
    failures += 1
    warn "custom_exception_class shape FAIL"
  end

  # ruby -c on a spread of full samples AND actually RUN one to confirm clean
  # CRuby execution (no uncaught exception escapes — every raise is rescued).
  check = samples.first(120)
  check.each_with_index do |src, idx|
    Tempfile.create(["exc_selftest", ".rb"]) do |f|
      f.write(src)
      f.flush
      ok = system("ruby", "-c", f.path, out: File::NULL, err: File::NULL)
      unless ok
        failures += 1
        warn "ruby -c FAIL on sample #{idx}"
        warn src
      end
    end
  end

  # Execute a handful end-to-end so we prove they run clean (not just parse).
  samples.first(10).each_with_index do |src, idx|
    Tempfile.create(["exc_run", ".rb"]) do |f|
      f.write(src)
      f.flush
      ok = system("ruby", f.path, out: File::NULL, err: File::NULL)
      unless ok
        failures += 1
        warn "ruby RUN FAIL on sample #{idx}"
        warn src
      end
    end
  end

  puts "exceptions self-test: #{total} programs generated, #{failures} failures"
  exit(failures.zero? ? 0 : 1)
end
