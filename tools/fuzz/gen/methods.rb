# frozen_string_literal: true

# Feature-generator module for the Spinel fuzzer: METHODS / PARAMETER ABI.
#
# Targets the densest divergence surface in an AOT compiler: the per-method
# parameter ABI. Spinel computes a fixed rest_index / kwrest_index per method
# and a positional C ABI, so each of these has a *distinct* lowering that can
# mis-bind argument slots:
#
#   * default-arg fill-in            (@meth_has_defaults)
#   * splat collection into an array (@meth_rest_index / RestParameterNode)
#   * kwarg-vs-trailing-hash         (KeywordParameterNode)
#   * double-splat capture           (@meth_kwrest_index / KeywordRestParameterNode)
#   * block / yield                  (@meth_has_yield / YieldNode / BlockParameterNode)
#   * numbered block params          (NumberedParametersNode)
#   * multiple-return + destructuring (MultiWriteNode/MultiTargetNode/SplatNode)
#   * recursion (literal-bounded so CRuby terminates fast, deterministic)
#
# DETERMINISM: every builder takes an explicit injected `rng`. No Time/rand/
# object_id/inspect/hash/GC. Block/recursion bounds are literal so output is a
# pure function of the seed. Floats (rare here) are printed via format('%.6f').
# Hashes are printed keys-sorted; arrays sorted before join.
#
# VALID RUBY BY CONSTRUCTION: signatures are assembled in Ruby's mandated
# parameter order (required, optional, rest, post, keyword, kwrest, block) and
# call sites are matched to the generated signature so every program runs clean
# under CRuby. Generating shapes spinel may mis-lower is the POINT.
#
# Pure stdlib. Defines FuzzGen::Methods with module_function builders.

module FuzzGen
  module Methods
    module_function

    SHAPES = %i[defaults rest_splat kwargs double_splat block_yield numbered_block mixed].freeze
    BASE_KINDS = %i[factorial fib sum_to_n].freeze

    # ---- tiny deterministic primitives ------------------------------------
    # These intentionally mirror generator.rb's int(rng)/q(value) discipline but
    # are kept local so the module is self-contained (no cross-module require).

    def rint(rng, min = -7, max = 7)
      rng.rand(min..max)
    end

    # Small *positive* literal, useful as a bound / count / divisor.
    def small_pos(rng, min = 1, max = 5)
      rng.rand(min..max)
    end

    def qstr(rng)
      %w[alpha beta gamma same x y].fetch(rng.rand(6)).inspect
    end

    # An in-scope int reference if available, else a literal — lets the module
    # compose against the host generator's typed scope when one is supplied, but
    # works standalone (scope == nil) too.
    def int_atom(rng, scope)
      if scope && scope.respond_to?(:any?) && scope.any?(:int) && rng.rand(2).zero?
        scope.pick(:int, rng)
      else
        rint(rng).to_s
      end
    end

    def str_atom(rng, scope)
      if scope && scope.respond_to?(:any?) && scope.any?(:str) && rng.rand(2).zero?
        scope.pick(:str, rng)
      else
        qstr(rng)
      end
    end

    # =======================================================================
    # PUBLIC API
    # =======================================================================

    # param_signature(rng, shape) -> String
    #
    # Builds a parameter list in Ruby's mandated order so it is always parseable:
    #   required , optional(=default) , *rest , post-required , key: , **kwrest , &blk
    # The chosen `shape` decides which segments are present.
    def param_signature(rng, shape)
      req  = ["a"]
      opt  = []
      rest = nil
      post = []
      kw   = []
      kwrest = nil
      block = nil

      case shape
      when :defaults
        opt = ["b=#{rint(rng)}", "c=#{rint(rng)}"]
      when :rest_splat
        rest = "*rest"
        post = ["z"]
      when :kwargs
        kw = ["k1: #{rint(rng)}", "k2: #{rint(rng)}"]
      when :double_splat
        kw = ["k1: #{rint(rng)}"]
        kwrest = "**opts"
      when :block_yield
        block = "&blk"
      when :numbered_block
        # Method itself just takes one required arg; the numbered params live in
        # the *call-site* block. Keep the signature minimal.
        req = ["a"]
      when :mixed
        opt = ["b=#{rint(rng)}"]
        rest = "*rest"
        kw = ["k: #{rint(rng)}"]
        kwrest = "**opts"
        block = "&blk"
      else
        raise ArgumentError, "unknown method shape: #{shape}"
      end

      ([*req, *opt, rest, *post, *kw, kwrest, block].compact).join(", ")
    end

    # build_method_def(rng, scope, shape:) -> {def_lines:, call_exprs:}
    #
    # def_lines:  array of source lines defining ONE method (name is unique).
    # call_exprs: array of *expression strings* that call it; each evaluates to a
    #             deterministic value the caller can `puts`. Every call site is
    #             matched to the generated signature so CRuby runs clean.
    def build_method_def(rng, scope, shape:)
      raise ArgumentError, "unknown method shape: #{shape}" unless SHAPES.include?(shape)

      name = scope_name(scope, rng)
      sig  = param_signature(rng, shape)
      body = method_body(rng, shape)

      def_lines = ["def #{name}(#{sig})", *body.map { |l| "  #{l}" }, "end"]
      call_exprs = call_sites(rng, name, shape, scope)

      { def_lines: def_lines, call_exprs: call_exprs }
    end

    # recursive_method_def(rng, base_kind:) -> {def_lines:, call_exprs:}
    #
    # Classic bounded recursion. The argument is a *small literal* so CRuby
    # terminates fast and output is fully deterministic. Base case is a literal
    # guard, crossing into the decl_controlflow vein (endless/recursive defs).
    def recursive_method_def(rng, base_kind:)
      kind = BASE_KINDS.include?(base_kind) ? base_kind : BASE_KINDS.fetch(rng.rand(BASE_KINDS.length))
      name = "rec_#{kind}_#{rng.rand(1 << 28)}"

      case kind
      when :factorial
        arg = small_pos(rng, 1, 7)
        def_lines = [
          "def #{name}(n)",
          "  return 1 if n <= 1",
          "  n * #{name}(n - 1)",
          "end"
        ]
      when :fib
        arg = small_pos(rng, 0, 12)
        def_lines = [
          "def #{name}(n)",
          "  return n if n < 2",
          "  #{name}(n - 1) + #{name}(n - 2)",
          "end"
        ]
      else # :sum_to_n
        arg = small_pos(rng, 0, 20)
        def_lines = [
          "def #{name}(n)",
          "  return 0 if n <= 0",
          "  n + #{name}(n - 1)",
          "end"
        ]
      end

      { def_lines: def_lines, call_exprs: ["#{name}(#{arg})"] }
    end

    # destructuring_assign(rng, scope) -> lines
    #
    # Stresses MultiWriteNode / MultiTargetNode / SplatNode lowering. Two forms:
    #   a, b, *c = <array>        (rest target)
    #   a, (b, c) = <nested>      (nested target)
    # Each line group includes deterministic prints of the bound names so a
    # mis-bound slot shows up as a value diff. Returns full lines (decl + prints).
    def destructuring_assign(rng, scope)
      lines = []
      n1 = uniq(rng, "d")
      n2 = uniq(rng, "d")
      n3 = uniq(rng, "d")

      if rng.rand(2).zero?
        # rest-in-the-middle / trailing rest. Only the *splatted* target is an
        # array; the others are scalars. Print the splat target sorted-joined,
        # the scalars directly — mismatching this is an easy CRuby error so we
        # are careful to track which slot holds the rest.
        vals = Array.new(small_pos(rng, 3, 6)) { rint(rng) }.join(", ")
        if rng.rand(2).zero?
          # trailing rest: a, b, *c  -> c is the array
          lines << "#{n1}, #{n2}, *#{n3} = #{wrap_array(vals)}"
          lines << "puts #{n1}"
          lines << "puts #{n2}"
          lines << "puts #{n3}.sort.join(\",\")"
        else
          # rest in the middle: a, *b, c -> b is the array
          lines << "#{n1}, *#{n2}, #{n3} = #{wrap_array(vals)}"
          lines << "puts #{n1}"
          lines << "puts #{n2}.sort.join(\",\")"
          lines << "puts #{n3}"
        end
      else
        # nested destructuring
        outer = rint(rng)
        inner_a = rint(rng)
        inner_b = rint(rng)
        lines << "#{n1}, (#{n2}, #{n3}) = #{outer}, [#{inner_a}, #{inner_b}]"
        lines << "puts #{n1}"
        lines << "puts #{n2}"
        lines << "puts #{n3}"
      end

      lines
    end

    # yield_call_site(rng, mname, scope) -> String
    #
    # A call to `mname` with a deterministic block. Covers both `|x|`-style and
    # plain blocks. Body is a pure expression over the block param so output is
    # seed-determined.
    def yield_call_site(rng, mname, scope)
      arg = int_atom(rng, scope)
      case rng.rand(3)
      when 0
        "#{mname}(#{arg}) { |x| x * #{small_pos(rng, 2, 4)} }"
      when 1
        "#{mname}(#{arg}) { |x| x + #{rint(rng)} }"
      else
        "#{mname}(#{arg}) { |x| (x - #{rint(rng)}).abs }"
      end
    end

    # methods_program(rng, index, seed) -> String
    #
    # Whole-program emitter. Self-contained: builds its own minimal scope shim so
    # it works whether or not the host generator passes one in. Emits a handful
    # of method defs across shapes + a recursive def + a destructuring block, then
    # deterministically prints every result.
    def methods_program(rng, index, seed, scope = nil, header_lines = nil)
      scope ||= MiniScope.new
      lines = header_lines ? header_lines.dup : default_header(index, seed)

      # 1) A spread of parameter-ABI shapes.
      shape_count = rng.rand(2..4)
      shapes = pick_shapes(rng, shape_count)
      shapes.each do |shape|
        built = build_method_def(rng, scope, shape: shape)
        lines.concat(built[:def_lines])
        built[:call_exprs].each { |ex| lines << "puts #{ex}" }
      end

      # 2) Bounded recursion.
      rec = recursive_method_def(rng, base_kind: BASE_KINDS.fetch(rng.rand(BASE_KINDS.length)))
      lines.concat(rec[:def_lines])
      rec[:call_exprs].each { |ex| lines << "puts #{ex}" }

      # 3) An explicit yield method + block call site (cross with block ABI).
      yname = "y_#{rng.rand(1 << 28)}"
      lines << "def #{yname}(x)"
      lines << "  yield(x) + yield(x)"
      lines << "end"
      lines << "puts #{yield_call_site(rng, yname, scope)}"

      # 4) Numbered-parameter block over a literal array (NumberedParametersNode).
      lines.concat(numbered_block_lines(rng))

      # 5) Multiple-return + destructuring.
      lines.concat(multi_return_lines(rng))
      lines.concat(destructuring_assign(rng, scope))

      lines << ""
      lines.join("\n")
    end

    # =======================================================================
    # internals
    # =======================================================================

    # Per-method body keyed to the shape. Bodies are deterministic expressions
    # over the bound parameters, reduced to a single integer return so the call
    # site `puts` is a stable scalar.
    def method_body(rng, shape)
      case shape
      when :defaults
        # Sum required + both optionals; defaults fill in when omitted at call.
        ["a + b + c"]
      when :rest_splat
        # `rest` is collected into an array; sum it + bracket the post-arg.
        ["rest.sum + a + z"]
      when :kwargs
        ["a + k1 + k2"]
      when :double_splat
        # kwrest captures extra keywords; sort keys for deterministic fold.
        [
          "extra = opts.keys.sort.map { |kk| opts[kk] }.sum",
          "a + k1 + extra"
        ]
      when :block_yield
        # Either yields the block or returns a default when none given.
        [
          "if block_given?",
          "  blk.call(a) + a",
          "else",
          "  a * 2",
          "end"
        ]
      when :numbered_block
        # Body folds a literal array with a numbered-param block.
        ["[a, a + 1, a + 2].map { _1 * 2 }.sum"]
      when :mixed
        # Touch every captured slot: required, optional, rest, kw, kwrest, block.
        [
          "extra = opts.keys.sort.map { |kk| opts[kk] }.sum",
          "base = a + b + k + extra + rest.sum",
          "if block_given?",
          "  base + blk.call(a)",
          "else",
          "  base",
          "end"
        ]
      else
        ["a"]
      end
    end

    # Call sites matched to the signature produced by param_signature for the
    # same shape. Multiple variants exercise default fill-in / splat / kwarg-vs-
    # hash disambiguation. Every variant is valid CRuby for the generated def.
    def call_sites(rng, name, shape, scope)
      a = int_atom(rng, scope)
      case shape
      when :defaults
        [
          "#{name}(#{a})",                              # both defaults fill in
          "#{name}(#{a}, #{rint(rng)})",                # one default fills in
          "#{name}(#{a}, #{rint(rng)}, #{rint(rng)})"   # all supplied
        ]
      when :rest_splat
        # rest collects 0..k positional args between `a` and the post-required z.
        splat = Array.new(rng.rand(0..3)) { rint(rng) }
        post = rint(rng)
        direct = "#{name}(#{[a, *splat, post].join(', ')})"
        # also drive collection from an explicit array splat
        arr = "[#{Array.new(rng.rand(0..3)) { rint(rng) }.join(', ')}]"
        via_splat = "#{name}(#{a}, *#{arr}, #{rint(rng)})"
        [direct, via_splat]
      when :kwargs
        [
          "#{name}(#{a})",                                 # both kw defaults
          "#{name}(#{a}, k1: #{rint(rng)})",               # one kw supplied
          "#{name}(#{a}, k1: #{rint(rng)}, k2: #{rint(rng)})",
          # kwarg-vs-trailing-hash: pass an explicit hash splat
          "#{name}(#{a}, **{k1: #{rint(rng)}, k2: #{rint(rng)}})"
        ]
      when :double_splat
        [
          "#{name}(#{a})",
          "#{name}(#{a}, k1: #{rint(rng)})",
          # extra keywords land in **opts
          "#{name}(#{a}, k1: #{rint(rng)}, x: #{rint(rng)}, y: #{rint(rng)})",
          "#{name}(#{a}, **{k1: #{rint(rng)}, x: #{rint(rng)}})"
        ]
      when :block_yield
        [
          "#{name}(#{a})",                                  # no block path
          yield_call_site(rng, name, scope)                 # block path
        ]
      when :numbered_block
        ["#{name}(#{a})"]
      when :mixed
        splat = Array.new(rng.rand(0..2)) { rint(rng) }
        [
          "#{name}(#{a})",
          "#{name}(#{[a, rint(rng), *splat].join(', ')}, k: #{rint(rng)}, z: #{rint(rng)})",
          "#{name}(#{a}, #{rint(rng)}, k: #{rint(rng)}) { |x| x + #{rint(rng)} }"
        ]
      else
        ["#{name}(#{a})"]
      end
    end

    # A standalone numbered-parameter block (NumberedParametersNode) over a
    # literal array, reduced to a deterministic sum.
    def numbered_block_lines(rng)
      vals = Array.new(small_pos(rng, 2, 5)) { rint(rng) }.join(", ")
      v = uniq(rng, "nb")
      [
        "#{v} = [#{vals}].map { _1 * #{small_pos(rng, 2, 3)} }.sum",
        "puts #{v}"
      ]
    end

    # Multiple-return method + destructured capture of its return.
    def multi_return_lines(rng)
      name = "mr_#{rng.rand(1 << 28)}"
      x = rint(rng)
      y = rint(rng)
      z = rint(rng)
      a = uniq(rng, "mr")
      b = uniq(rng, "mr")
      c = uniq(rng, "mr")
      [
        "def #{name}",
        "  return #{x}, #{y}, #{z}",
        "end",
        "#{a}, #{b}, #{c} = #{name}",
        "puts #{a}",
        "puts #{b}",
        "puts #{c}",
        # also splat-capture the multi-return
        "head, *tail = #{name}",
        "puts head",
        "puts tail.sort.join(\",\")"
      ]
    end

    def pick_shapes(rng, count)
      pool = SHAPES.dup
      out = []
      count.times do
        break if pool.empty?
        out << pool.delete_at(rng.rand(pool.length))
      end
      out
    end

    # name allocation: use the host scope's fresh_name when present (keeps names
    # unique across composed modules), else a seed-derived unique token.
    def scope_name(scope, rng)
      if scope && scope.respond_to?(:fresh_name)
        scope.fresh_name("mth").sub(/\A/, "m_")
      else
        "m_#{rng.rand(1 << 30)}"
      end
    end

    def uniq(rng, prefix)
      "#{prefix}_#{rng.rand(1 << 30)}"
    end

    def wrap_array(vals)
      "[#{vals}]"
    end

    def default_header(index, seed)
      [
        "# fuzz-family: methods",
        "# fuzz-index: #{index}",
        "# fuzz-seed: #{seed}",
        "# fuzz-mode: standalone"
      ]
    end

    # Minimal scope shim so methods_program runs without the host Scope. Mirrors
    # the subset of the Scope API the builders touch.
    class MiniScope
      def initialize
        @counter = 0
        @vars = { int: [], str: [] }
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

  BANNED = [
    /\bTime\b/, /\bDateTime\b/, /\brand\b/, /\bsrand\b/, /\bobject_id\b/,
    /\b__id__\b/, /\.inspect\b/, /\bp\s/, /\bGC\b/, /\bObjectSpace\b/,
    /\.hash\b/, /\bRandom\b/, /\b__FILE__\b/, /\b__LINE__\b/, /\bcaller\b/, /\bENV\b/
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
  samples = []

  seeds.each do |seed|
    rng = Random.new(seed)
    per_seed.times do |i|
      src = FuzzGen::Methods.methods_program(rng, i, seed)
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

  # Exercise each public-API builder directly with a real MiniScope.
  scope = FuzzGen::Methods::MiniScope.new
  trng = Random.new(123_456)
  FuzzGen::Methods::SHAPES.each do |shape|
    sig = FuzzGen::Methods.param_signature(trng, shape)
    built = FuzzGen::Methods.build_method_def(trng, scope, shape: shape)
    prog = (built[:def_lines] + built[:call_exprs].map { |e| "puts #{e}" }).join("\n") + "\n"
    unless parses?(prog)
      failures += 1
      warn "PARSE FAIL builder shape=#{shape}\nsig=#{sig}\n#{prog}"
    end
    samples << prog
  end
  FuzzGen::Methods::BASE_KINDS.each do |bk|
    rec = FuzzGen::Methods.recursive_method_def(trng, base_kind: bk)
    prog = (rec[:def_lines] + rec[:call_exprs].map { |e| "puts #{e}" }).join("\n") + "\n"
    unless parses?(prog)
      failures += 1
      warn "PARSE FAIL recursive base_kind=#{bk}\n#{prog}"
    end
    samples << prog
  end
  # destructuring_assign + yield_call_site standalone
  da = FuzzGen::Methods.destructuring_assign(trng, scope).join("\n") + "\n"
  failures += 1 unless parses?(da)
  samples << da

  # Determinism: same seed reproduces identical program.
  d1 = FuzzGen::Methods.methods_program(Random.new(42), 5, 42)
  d2 = FuzzGen::Methods.methods_program(Random.new(42), 5, 42)
  unless d1 == d2
    failures += 1
    warn "DETERMINISM FAIL: methods_program(seed=42, i=5) not stable"
  end

  # ruby -c cross-check + actual EXECUTION (must run clean under CRuby) on EVERY
  # sample so we catch arity/binding errors the AST parser misses. Each program
  # is tiny and literal-bounded, so executing all of them is cheap.
  samples.each_with_index do |src, idx|
    Tempfile.create(["methods_selftest_#{idx}", ".rb"]) do |f|
      f.write(src)
      f.flush
      ok_c = system("ruby", "-c", f.path, out: File::NULL, err: File::NULL)
      unless ok_c
        failures += 1
        warn "ruby -c FAIL on sample #{idx}"
        warn src
        next
      end
      ok_run = system("ruby", f.path, out: File::NULL, err: File::NULL)
      unless ok_run
        failures += 1
        warn "ruby RUN FAIL on sample #{idx}"
        warn src
      end
    end
  end

  puts "methods self-test: #{total} programs generated (+#{samples.length - total} direct-builder), #{failures} failures"
  exit(failures.zero? ? 0 : 1)
end
