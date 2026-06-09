# frozen_string_literal: true

# THE PROVEN VEIN: top-level declarations and ordinary statements systematically
# wrapped in every control-flow form.
#
# Generalizes the confirmed Pass-2-walker bug. spinel_analyze.rb's top-level
# declaration walker (~line 8874) iterates `stmts.each` and pattern-matches ONLY
# bare DefNode / ConstantWriteNode / MultiWriteNode / CallNode(define_method). It
# never descends into IfNode / UnlessNode / WhileNode / UntilNode / BeginNode
# children. So collect_scoped_constant (~line 10843) and collect_struct_class
# (via ~line 10859) never run for a *wrapped* declaration; the bound name falls
# through to the generic ct="int" path (~line 10864) and later reads
# emit 0 (or error for missing struct types).
#
# Confirmed-broken forms (CRuby right, spinel wrong) — re-verified by hand,
# this module manufactures the whole equivalence class programmatically:
#   Rec = Struct.new(:id,:name) unless defined?(Rec); puts Rec.new(0,"alpha").name  # alpha vs 0
#   Point = Data.define(:x,:y) if true; puts Point.new(3,4).y                       # 4 vs 0
#   N = 42 if true; puts N + 1                                                      # 43 vs ERROR
#   S = "hi" unless defined?(S); puts S.upcase                                      # HI vs empty
#   def foo(a)=a*2 if true; puts foo(21)                                           # 42 vs 0
#   (class C; def v;7;end;end if true); puts C.new.v                               # 7 vs 0
#   begin; Rec=Struct.new(:id,:name); rescue; end; puts Rec.new(5,"y").name        # y vs 0
#
# The module takes the cartesian product of {declaration kinds} x {control-flow
# wrappers} x {guards that are statically/runtime true}, then emits a use site
# that prints the bound value. Every cell where spinel's walker fails to descend
# yields a 0-vs-real or error-vs-real diff. Wrappers keep the guard runtime-true
# so CRuby actually executes the decl (otherwise there is no differential).
#
# Determinism: all randomness flows through an injected `rng` (Random). No Time /
# rand / object_id / inspect / hash / GC. Strings/ints are deterministic. Every
# emitted program is valid Ruby by construction and runs clean under CRuby.
#
# Pure stdlib. No require of generator.rb or sibling fuzz modules.

module FuzzGen
  module DeclControlflow
    module_function

    # ------------------------------------------------------------------
    # Deterministic literal vocabularies (no Time/rand; chosen via rng only).
    # ------------------------------------------------------------------

    STR_LITERALS = %w[alpha beta gamma delta value name token].freeze
    FIELD_NAMES  = %w[id name x y kind tag slot].freeze

    # Control-flow wrappers. The full set exercised against every declaration.
    # apply_wrapper(rng, inner_lines, form) wraps inner_lines (an Array of source
    # lines, the bare declaration) so the declaration becomes a *child* of a
    # control-flow node while still executing under CRuby.
    WRAPPERS = %i[
      modifier_if
      modifier_unless
      modifier_unless_defined
      modifier_while_once
      modifier_until_once
      begin_rescue
      begin_ensure
      begin_rescue_ensure
      nested_if_unless
    ].freeze

    CONST_KINDS = %i[literal_int literal_str literal_float struct_new data_define expr].freeze

    # ------------------------------------------------------------------
    # Small deterministic pickers (rng-driven; never global rand).
    # ------------------------------------------------------------------

    def pick(rng, list)
      list[rng.rand(list.length)]
    end

    def int_lit(rng, min = -9, max = 99)
      rng.rand(min..max)
    end

    def nonzero_int_lit(rng)
      n = 0
      n = rng.rand(1..9) while n.zero?
      n
    end

    def float_lit(rng)
      # Fixed two-decimal float so the literal text is stable and printable.
      whole = rng.rand(0..40)
      frac  = rng.rand(0..99)
      format("%d.%02d", whole, frac)
    end

    def str_lit(rng)
      pick(rng, STR_LITERALS)
    end

    def q(value)
      # Match generator.rb's quoting discipline: Ruby-inspect of a String yields
      # a valid double-quoted literal. Used only on our own ASCII vocab strings,
      # so no banned tokens leak.
      value.inspect
    end

    # Fresh constant / method names. Names embed `scope.fresh_name` so a single
    # program can host many wrapped declarations without collision, and so the
    # `unless defined?(X)` guard references the same name being defined.
    def const_name(scope)
      "K#{scope.fresh_name('')}"
    end

    def class_name(scope)
      "C#{scope.fresh_name('')}"
    end

    def module_name(scope)
      "M#{scope.fresh_name('')}"
    end

    def method_name(scope)
      "m#{scope.fresh_name('')}"
    end

    def loop_flag(scope)
      "f#{scope.fresh_name('')}"
    end

    # ==================================================================
    # PUBLIC API
    # ==================================================================

    # build_wrapped_const_decl(rng, scope, kind:)
    #   -> { decl_lines:, use_lines:, expected_kind: }
    #
    # kind in [:literal_int, :literal_str, :literal_float, :struct_new,
    #          :data_define, :expr]
    #
    # decl_lines is the BARE (un-wrapped) declaration — the caller applies a
    # wrapper. use_lines reads the bound constant and `puts` the resolved value
    # so a 0/empty/error divergence is observable. expected_kind echoes `kind`
    # (the type spinel *should* have inferred had it descended).
    def build_wrapped_const_decl(rng, scope, kind:)
      name = const_name(scope)
      case kind
      when :literal_int
        v = int_lit(rng, 1, 99)
        {
          decl_lines: ["#{name} = #{v}"],
          use_lines: ["puts(#{name} + 1)"],
          expected_kind: :literal_int
        }
      when :literal_str
        s = str_lit(rng)
        {
          decl_lines: ["#{name} = #{q(s)}"],
          use_lines: ["puts #{name}.upcase"],
          expected_kind: :literal_str
        }
      when :literal_float
        f = float_lit(rng)
        {
          decl_lines: ["#{name} = #{f}"],
          # Fixed-format print dodges platform float-repr drift.
          use_lines: ["puts format('%.6f', #{name})"],
          expected_kind: :literal_float
        }
      when :struct_new
        fa, fb = two_fields(rng)
        idv = int_lit(rng, 0, 99)
        nv = str_lit(rng)
        {
          decl_lines: ["#{name} = Struct.new(:#{fa}, :#{fb})"],
          use_lines: ["puts #{name}.new(#{idv}, #{q(nv)}).#{fb}"],
          expected_kind: :struct_new
        }
      when :data_define
        fa, fb = two_fields(rng)
        av = int_lit(rng, 0, 99)
        bv = int_lit(rng, 0, 99)
        {
          decl_lines: ["#{name} = Data.define(:#{fa}, :#{fb})"],
          use_lines: ["puts #{name}.new(#{av}, #{bv}).#{fb}"],
          expected_kind: :data_define
        }
      when :expr
        a = int_lit(rng, 1, 40)
        b = nonzero_int_lit(rng)
        {
          decl_lines: ["#{name} = (#{a} * #{b})"],
          use_lines: ["puts(#{name} - 1)"],
          expected_kind: :expr
        }
      else
        raise ArgumentError, "unknown const kind: #{kind.inspect}"
      end
    end

    # Two distinct field names (so struct/data accessors are unambiguous).
    def two_fields(rng)
      a = pick(rng, FIELD_NAMES)
      b = a
      b = pick(rng, FIELD_NAMES) while b == a
      [a, b]
    end

    # build_wrapped_def(rng, scope, endless:) -> { decl_lines:, use_lines: }
    #
    #   endless: false -> def foo(a)\n  a * k\nend
    #   endless: true  -> def foo(a) = a * k
    #
    # The use site calls foo with a literal arg and `puts` the result; under the
    # bug a wrapped def is invisible and the call resolves to 0 (or errors).
    def build_wrapped_def(rng, scope, endless:)
      name = method_name(scope)
      k = nonzero_int_lit(rng)
      arg = int_lit(rng, 1, 40)
      if endless
        {
          decl_lines: ["def #{name}(a) = a * #{k}"],
          use_lines: ["puts #{name}(#{arg})"]
        }
      else
        {
          decl_lines: [
            "def #{name}(a)",
            "  a * #{k}",
            "end"
          ],
          use_lines: ["puts #{name}(#{arg})"]
        }
      end
    end

    # build_wrapped_class(rng, scope) -> { decl_lines:, use_lines: }
    #
    #   class C
    #     def v
    #       LIT
    #     end
    #   end
    #   then  puts C.new.v
    def build_wrapped_class(rng, scope)
      name = class_name(scope)
      mth  = method_name(scope)
      lit  = int_lit(rng, 1, 99)
      {
        decl_lines: [
          "class #{name}",
          "  def #{mth}",
          "    #{lit}",
          "  end",
          "end"
        ],
        use_lines: ["puts #{name}.new.#{mth}"]
      }
    end

    # build_wrapped_module(rng, scope) -> { decl_lines:, use_lines: }
    #
    #   module M
    #     def self.v
    #       LIT
    #     end
    #   end
    #   then  puts M.v
    def build_wrapped_module(rng, scope)
      name = module_name(scope)
      mth  = method_name(scope)
      lit  = int_lit(rng, 1, 99)
      {
        decl_lines: [
          "module #{name}",
          "  def self.#{mth}",
          "    #{lit}",
          "  end",
          "end"
        ],
        use_lines: ["puts #{name}.#{mth}"]
      }
    end

    # apply_wrapper(rng, inner_lines, form) -> lines
    #
    # Wraps `inner_lines` (the bare declaration source) in control-flow `form`.
    # In EVERY form the guard/predicate is statically/runtime TRUE so CRuby
    # actually executes the declaration — that is what makes the differential
    # appear: CRuby binds the real value, spinel (failing to descend the wrapper)
    # binds the int/unresolved fallthrough.
    #
    # `:modifier_*` forms require a single-statement inner so the trailing
    # modifier is legal Ruby; multi-line declarations are first collapsed into a
    # `begin ... end` (still a single statement node, still a child spinel's
    # walker does not descend) so a modifier can legally hang off them.
    def apply_wrapper(rng, inner_lines, form)
      case form
      when :modifier_if
        with_modifier(inner_lines, "if true")
      when :modifier_unless
        with_modifier(inner_lines, "unless false")
      when :modifier_unless_defined
        # `unless defined?(__nope_<n>)` — a name that is never defined, so the
        # guard is true and the body runs. Deterministic, no rng leakage.
        token = "Undef#{rng.rand(0..999_999)}x"
        with_modifier(inner_lines, "unless defined?(#{token})")
      when :modifier_while_once
        # One-shot loop: a flag that flips on first iteration so the body runs
        # exactly once. Wrapped as a single begin-statement + while modifier
        # (do/end-less post-modifier on a begin runs the body before testing).
        flag = "__w#{rng.rand(0..999_999)}"
        once_loop(inner_lines, flag, "while")
      when :modifier_until_once
        flag = "__u#{rng.rand(0..999_999)}"
        once_loop(inner_lines, flag, "until")
      when :begin_rescue
        [
          "begin",
          *indent(inner_lines),
          "rescue StandardError",
          "  # unreachable: declaration cannot raise",
          "end"
        ]
      when :begin_ensure
        [
          "begin",
          *indent(inner_lines),
          "ensure",
          "  # ensure side runs after the declaration",
          "end"
        ]
      when :begin_rescue_ensure
        [
          "begin",
          *indent(inner_lines),
          "rescue StandardError",
          "  # unreachable",
          "ensure",
          "  # ensure side",
          "end"
        ]
      when :nested_if_unless
        # Nest the declaration two control-flow levels deep so the walker would
        # have to descend twice. Both predicates statically true.
        [
          "if true",
          "  unless false",
          *indent(indent(inner_lines)),
          "  end",
          "end"
        ]
      else
        raise ArgumentError, "unknown wrapper form: #{form.inspect}"
      end
    end

    # Indent a block of lines by two spaces.
    def indent(lines)
      lines.map { |l| l.empty? ? l : "  #{l}" }
    end

    # Attach a trailing modifier to a (possibly multi-line) inner block. A
    # single-line inner gets the modifier directly. A multi-line inner is wrapped
    # in `begin ... end <modifier>` — still one statement node carrying a
    # control-flow modifier, still un-descended by the buggy walker.
    def with_modifier(inner_lines, modifier)
      if inner_lines.length == 1
        ["#{inner_lines.first} #{modifier}"]
      else
        [
          "begin",
          *indent(inner_lines),
          "end #{modifier}"
        ]
      end
    end

    # Build a one-shot while/until loop around inner_lines using a boolean flag,
    # so the body runs exactly once and the loop terminates. The declaration sits
    # inside a WhileNode/UntilNode body — exactly the node the walker skips.
    def once_loop(inner_lines, flag, keyword)
      if keyword == "while"
        # flag starts true, body sets it false -> runs once.
        [
          "#{flag} = true",
          "while #{flag}",
          "  #{flag} = false",
          *indent(inner_lines),
          "end"
        ]
      else
        # until: flag starts false, body sets it true -> runs once.
        [
          "#{flag} = false",
          "until #{flag}",
          "  #{flag} = true",
          *indent(inner_lines),
          "end"
        ]
      end
    end

    # ==================================================================
    # Whole-program emitter.
    # ==================================================================

    # decl_controlflow_program(rng, index, seed) -> String
    #
    # Emits a self-contained program: pick a declaration kind and a wrapper,
    # build the bare declaration, wrap it, then emit the post-wrap use site that
    # `puts`es the resolved value. Deterministic from (rng/seed). A built-in
    # lightweight Scope is used when none is injected, so the module is callable
    # both standalone and from generator.rb's shim (which passes its own scope).
    def decl_controlflow_program(rng, index, seed, scope: nil, header_lines: nil)
      scope ||= MiniScope.new
      lines = header_lines || default_header(index, seed)

      # Choose how many wrapped declarations to stack (1..3): stacking multiple
      # decl x wrapper cells in one program widens coverage of the equivalence
      # class per case while staying deterministic and small.
      count = rng.rand(1..3)
      count.times do
        emit_one_cell(rng, scope, lines)
      end

      lines << ""
      lines.join("\n")
    end

    # Public alias matching the generatorIntegration shim convention
    # (FuzzGen::DeclControlflow.program(rng, scope, index, seed, header)).
    def program(rng, scope, index, seed, header_lines)
      decl_controlflow_program(rng, index, seed, scope: scope, header_lines: header_lines.dup)
    end

    # Emit a single {declaration kind} x {wrapper} cell + its use site.
    def emit_one_cell(rng, scope, lines)
      decl =
        case rng.rand(7)
        when 0 then build_wrapped_const_decl(rng, scope, kind: pick(rng, CONST_KINDS))
        when 1 then build_wrapped_def(rng, scope, endless: false)
        when 2 then build_wrapped_def(rng, scope, endless: true)
        when 3 then build_wrapped_class(rng, scope)
        when 4 then build_wrapped_module(rng, scope)
        when 5 then build_wrapped_const_decl(rng, scope, kind: :struct_new)
        else        build_wrapped_const_decl(rng, scope, kind: :data_define)
        end

      form = pick(rng, WRAPPERS)
      wrapped = apply_wrapper(rng, decl[:decl_lines], form)

      lines.concat(wrapped)
      lines.concat(decl[:use_lines])
    end

    def default_header(index, seed)
      [
        "# fuzz-family: decl_controlflow",
        "# fuzz-index: #{index}",
        "# fuzz-seed: #{seed}",
        "# fuzz-mode: typed"
      ]
    end

    # Minimal fresh-name scope used when generator.rb does not inject its own
    # Scope. Mirrors Generator::Scope#fresh_name's contract (monotonic counter)
    # so wrapped declarations never collide within a program.
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

  M = FuzzGen::DeclControlflow

  # Banned tokens (subset of generator.rb's list, plus the same nondeterminism
  # guards). Our emitted source must never contain any of these.
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
    /\bcaller\b/,
    /\bENV\b/
  ].freeze

  def parses?(source)
    RubyVM::AbstractSyntaxTree.parse(source)
    true
  rescue SyntaxError, ArgumentError
    false
  end

  seeds = [1, 7, 42, 1234, 99_999, 2024, 555]
  per_seed = 40
  total = 0
  failures = 0
  samples = []

  seeds.each do |seed|
    rng = Random.new(seed)
    per_seed.times do |i|
      src = M.decl_controlflow_program(rng, i, seed)
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

  # Determinism: same (seed sequence) reproduces identical source.
  rng_a = Random.new(42)
  rng_b = Random.new(42)
  a = M.decl_controlflow_program(rng_a, 0, 42)
  b = M.decl_controlflow_program(rng_b, 0, 42)
  if a != b
    failures += 1
    warn "DETERMINISM FAIL: identical-seed programs differ"
  end

  # Each public API builder returns the documented shape.
  begin
    sc = M::MiniScope.new
    rng = Random.new(11)
    M::CONST_KINDS.each do |k|
      r = M.build_wrapped_const_decl(rng, sc, kind: k)
      raise "const #{k} missing keys" unless r[:decl_lines] && r[:use_lines] && r[:expected_kind]
    end
    [true, false].each do |e|
      r = M.build_wrapped_def(rng, sc, endless: e)
      raise "def endless=#{e} missing keys" unless r[:decl_lines] && r[:use_lines]
    end
    raise "class missing keys" unless M.build_wrapped_class(rng, sc).values_at(:decl_lines, :use_lines).all?
    raise "module missing keys" unless M.build_wrapped_module(rng, sc).values_at(:decl_lines, :use_lines).all?
    # Every wrapper applies and yields a non-empty block.
    M::WRAPPERS.each do |form|
      out = M.apply_wrapper(rng, ["X = 1"], form)
      raise "wrapper #{form} empty" if out.nil? || out.empty?
    end
  rescue StandardError => e
    failures += 1
    warn "API shape FAIL: #{e.class}: #{e.message}"
  end

  # `ruby -c` cross-check on a sampling (independent of the AST parser).
  sampled = samples.each_slice([samples.length / 25, 1].max).map(&:first)
  sampled.each do |src|
    Tempfile.create(["decl_cf_selftest", ".rb"]) do |f|
      f.write(src)
      f.flush
      ok = system("ruby", "-c", f.path, out: File::NULL, err: File::NULL)
      unless ok
        failures += 1
        warn "ruby -c FAIL on sampled case"
        warn src
      end
    end
  end

  puts "decl_controlflow self-test: #{total} programs generated, #{sampled.length} ruby -c checked, #{failures} failures"
  exit(failures.zero? ? 0 : 1)
end
