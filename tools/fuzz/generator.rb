# frozen_string_literal: true

# Recursive, type-directed Ruby program generator for the hardened Spinel fuzzer.
#
# Output is valid Ruby BY CONSTRUCTION: typed expression trees are built
# recursively under a depth budget, against an in-scope typed symbol table so
# every variable reference is defined and correctly typed. The 8 legacy family
# templates are retained as seeds / weighting hints and as fallback whole-program
# emitters (mode: :templates, or as the recursive generator's preamble).
#
# Determinism guarantees:
#   * Fully seeded/replayable via Random.new(seed). Per-case derives a child seed
#     exactly like the legacy generator (top_rng.rand(1 << 62)).
#   * BANS nondeterminism: never emits Time/rand/object_id/GC, never inspects
#     objects (which would leak addresses), never iterates hashes in a way whose
#     output order is unstable; collections are sorted before printing. Only
#     deterministic `puts` of scalars / strings / sorted collections is emitted.
#
# Pure stdlib. No require of other fuzz modules.

# Feature-generator modules (tools/fuzz/gen/*.rb). Each defines a module under
# FuzzGen::* with module_function builders that take an explicit `rng` (the
# per-case family_rng) and a duck-typed `scope`. Loaded sorted for determinism;
# pure stdlib, no global state. These widen the generator's input space far
# beyond the legacy/typed families (control-flow-wrapped declarations, floats,
# overflow ints, hashes, ranges, symbols, parameter ABIs, exceptions, string
# ops, and enumerable chains).
Dir[File.join(__dir__, "gen", "*.rb")].sort.each { |f| require_relative f }

GeneratedCase = Struct.new(:seed, :index, :family, :source, keyword_init: true) unless defined?(GeneratedCase)

class Generator
  # Legacy families (seeds) + typed-expression families. Order is stable.
  LEGACY_FAMILIES = %i[
    scalar
    method_scalar
    array
    string
    hash
    struct_record
    nested_record
  ].freeze

  TYPED_FAMILIES = %i[
    typed_int
    typed_bool
    typed_string
    typed_array
    typed_struct
  ].freeze

  # VEIN families: each backed by a tools/fuzz/gen/*.rb module and aimed at ONE
  # confirmed-divergence root cause. These carry the discovery mass now.
  #   decl_controlflow -> Pass-2 top-level walker never descends control-flow.
  #   poly_render      -> tag-losing unbox on poly/RbVal container read-back.
  #   awk_literal      -> special-case semantics gated on an AST-literal check.
  #   float_format     -> %g/%e/%f format reads the wrong (uninitialized) slot.
  VEIN_FAMILIES = %i[
    decl_controlflow
    poly_render
    awk_literal
    float_format
  ].freeze

  # SUPPORTED-surface feature families: composition + restricted collections /
  # exceptions / strings / enumerable. Each stays INSIDE the documented surface
  # (see README "Supported Ruby Features"); the goal is interaction bugs there.
  #
  # NOTE: `numeric` (bignum-boundary / overflow-ABI gap-chasing) and `methods`
  # (exotic kwargs / splat / double-splat ABIs, undocumented) have been DROPPED
  # from the active set per step 1 -- they primarily probe UNSUPPORTED territory
  # so their divergences are gaps, not bugs. They remain defined and explicitly
  # selectable for back-compat, but carry no default weight.
  SUPPORTED_FEATURE_FAMILIES = %i[
    composition
    collections
    exceptions
    strings
    enumerable
  ].freeze

  # The families that actually carry generation mass by default.
  ACTIVE_FAMILIES = (VEIN_FAMILIES + SUPPORTED_FEATURE_FAMILIES).freeze

  # Legacy/undocumented-surface families kept selectable but un-weighted.
  DORMANT_FEATURE_FAMILIES = %i[numeric methods].freeze

  # Full set of names `emit` can dispatch (the self-test still exercises each).
  FEATURE_FAMILIES = (VEIN_FAMILIES + SUPPORTED_FEATURE_FAMILIES + DORMANT_FEATURE_FAMILIES).uniq.freeze

  KNOWN_FAMILIES = (LEGACY_FAMILIES + TYPED_FAMILIES + FEATURE_FAMILIES).uniq.freeze

  # Weighting hint for legacy/template mode (mirrors the historical distribution).
  TEMPLATE_WEIGHTS = %i[
    scalar
    scalar
    method_scalar
    array
    array
    string
    string
    hash
    struct_record
    struct_record
    nested_record
  ].freeze

  # Weighting for the typed/recursive mode. The mass now sits on the four VEIN
  # families (each probing a distinct confirmed root cause) plus the
  # SUPPORTED-surface composition/feature families. The DORMANT families
  # (numeric/methods) carry NO weight -- they primarily probe unsupported
  # territory (bignum-boundary / exotic kwargs+splat ABIs), so their divergences
  # are documented gaps, not bugs. Each vein is weighted 2x; composition (deep
  # supported nesting) is weighted 2x because supported-territory bugs are
  # interaction bugs. Typed/legacy families are retained as light seeds so legacy
  # coverage never disappears.
  TYPED_WEIGHTS = %i[
    decl_controlflow
    decl_controlflow
    poly_render
    poly_render
    awk_literal
    awk_literal
    float_format
    float_format
    composition
    composition
    collections
    collections
    exceptions
    exceptions
    strings
    strings
    enumerable
    enumerable
    typed_int
    typed_bool
    typed_string
    typed_array
    typed_struct
    scalar
    array
    string
    struct_record
  ].freeze

  STRINGS = [
    "alpha",
    "beta",
    "a,b,,c",
    "left right",
    "x|y|z",
    "",
    "same"
  ].freeze

  SEPARATORS = [",", " ", "|"].freeze

  # Tokens that MUST NOT appear in generated source (nondeterministic / address-leaking).
  # Matched as whole words / method sends against the emitted source in the self-test.
  BANNED_TOKENS = [
    /\bTime\b/,
    /\bDateTime\b/,
    /\brand\b/,
    /\bsrand\b/,
    /\bobject_id\b/,
    /\b__id__\b/,
    /\.inspect\b/,
    /\bp\s/,             # Kernel#p leaks inspect output
    /\bGC\b/,
    /\bObjectSpace\b/,
    /\.hash\b/,
    /\bRandom\b/,
    /\b__FILE__\b/,
    /\b__LINE__\b/,
    /\bcaller\b/,
    /\bENV\b/
  ].freeze

  # GENERATION EXCLUDE GUARD (step 1).
  #
  # Constructs that are DOCUMENTED-UNSUPPORTED or INTENTIONAL DIVERGENCES (so a
  # divergence is a known gap, NOT a bug). The generator must never emit any of
  # these. Sources: README "Limitations", docs/INCOMPATIBILITIES.md,
  # docs/FLOAT-ROUNDING.md, docs/HASH-NULLABLE.md, promote-mode-plan.md.
  #
  # `gate_source` scans every emitted program against this list and, on a hit,
  # deterministically substitutes a guaranteed-supported program so a banned
  # construct can never reach the corpus.
  UNSUPPORTED_TOKENS = [
    # Metaprogramming / reflection (README Limitations).
    /\beval\b/, /\binstance_eval\b/, /\bclass_eval\b/, /\bmodule_eval\b/,
    /\.send\b/, /\.public_send\b/, /\b__send__\b/, /\bmethod_missing\b/,
    /\bdefine_method\b/, /\bremove_method\b/, /\bundef_method\b/,
    /\binstance_variable_get\b/, /\binstance_variable_set\b/,
    /\bconst_get\b/, /\bconst_set\b/, /\bbinding\b/,
    # Threads / concurrency primitives (README Limitations).
    /\bThread\b/, /\bMutex\b/, /\bQueue\b/, /\bConditionVariable\b/,
    # Integer ** / pow with a NEGATIVE exponent (INCOMPATIBILITIES.md; raises by
    # design). Match a power/pow whose exponent is a negative literal.
    /\*\*\s*-\d/, /\.pow\(\s*-\d/,
    # grapheme clustering (INCOMPATIBILITIES.md).
    /\bgrapheme_clusters\b/, /\beach_grapheme_cluster\b/,
    # English regexp-global aliases (INCOMPATIBILITIES.md).
    /require\s+["']English["']/, /\$~/, /\$&/, /\$`/, /\$'/, /\$\+/,
    # inspect/p/to_s on Hash/Range/Struct is a documented gap; .inspect is
    # already in BANNED_TOKENS, but guard explicit inspect-bearing aggregate
    # renderings too (Hash#inspect / Range#inspect / Struct#inspect surfaces).
    /\.inspect\b/,
    # Float round/ceil/floor/truncate with a NON-LITERAL ndigits (FLOAT-ROUNDING
    # intentional return-type divergence): a variable/expression argument.
    /\.round\(\s*[a-z_]/, /\.ceil\(\s*[a-z_]/, /\.floor\(\s*[a-z_]/,
    /\.truncate\(\s*[a-z_]/,
    # Out-of-surface enumerable/aggregate methods (README block-method list is
    # closed): these route through gap paths, not supported lowering.
    /\.group_by\b/, /\.partition\b/, /\.minmax\b/, /\.flat_map\b/,
    /\.filter_map\b/, /\.each_with_object\b/, /\.each_slice\b/,
    /\.each_cons\b/, /\.zip\b/, /\.flatten\b/, /\.chunk\b/, /\.lazy\b/,
    # Non-UTF8 encoding tricks (README Limitations).
    /\.force_encoding\b/, /\.encode\(/, /Encoding::/
  ].freeze

  # 64-bit mask for the splitmix64 case-seed mixer.
  MASK64 = (1 << 64) - 1

  def initialize(seed, families: nil, exclude_families: [], max_depth: 4, mode: :typed)
    @seed = Integer(seed)
    @max_depth = [Integer(max_depth), 1].max
    @mode = validate_mode(mode)
    @families = selected_families(families, exclude_families)
  end

  # Build generator and regenerate exactly one case for repro. Because the case
  # seed is a PURE function of (seed, index) (see case_seed_for), this returns the
  # identical case the sequential run produced for that index — which is what lets
  # the parallel sharder re-derive any case deterministically.
  def self.replay(seed, index, **opts)
    new(seed, **opts).generate(index)
  end

  def generate(index)
    # case_seed depends ONLY on (@seed, index), never on call order, so
    # generate(i) is referentially transparent: the sequential loop and the
    # parallel replay path produce the same diverse corpus, and every index maps
    # to a distinct case. (Previously case_seed was drawn from a stateful @rng,
    # so a fresh replayed generator always re-emitted index 0's program.)
    case_seed = case_seed_for(index)
    family_rng = Random.new(case_seed)
    family = weighted_family(family_rng)
    source = emit(family, family_rng, index, case_seed)

    # GENERATION EXCLUDE GUARD: if anything emitted a documented-unsupported or
    # intentional-divergence construct, substitute a guaranteed-supported program
    # (the composition family is supported by construction). Deterministic: the
    # substitution is a pure function of (case_seed, index), so replay is stable.
    if UNSUPPORTED_TOKENS.any? { |re| source =~ re }
      family = :composition
      source = composition_program(Random.new(case_seed ^ 0x5DEECE66D), index, case_seed)
    end

    GeneratedCase.new(
      seed: case_seed,
      index: index,
      family: family.to_s,
      source: source
    )
  end

  def families
    @families.dup
  end

  private

  # ---- per-index case seed -----------------------------------------------

  # Deterministic, well-distributed 62-bit case seed from (@seed, index) using a
  # splitmix64 finalizer. Pure integer math (no process-randomized Object#hash),
  # so it is stable across processes/forks — essential for the parallel sharder,
  # which re-derives each case in a separate worker.
  def case_seed_for(index)
    z = (@seed + (Integer(index) + 1) * 0x9E3779B97F4A7C15) & MASK64
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
    z ^= (z >> 31)
    z & ((1 << 62) - 1)
  end

  # ---- family / mode selection -------------------------------------------

  def validate_mode(mode)
    m = mode.to_sym
    return m if %i[typed templates].include?(m)

    raise ArgumentError, "unknown generator mode: #{mode} (known: typed, templates)"
  end

  def weights
    @mode == :typed ? TYPED_WEIGHTS : TEMPLATE_WEIGHTS
  end

  def weighted_family(rng)
    choices = weights.select { |family| @families.include?(family) }
    choices = @families if choices.empty?
    choices[rng.rand(choices.length)]
  end

  def selected_families(families, exclude_families)
    # Default typed-mode draw is the ACTIVE set (vein + supported-surface), NOT
    # the full KNOWN set: the dormant numeric/methods families probe unsupported
    # territory and must not be sampled unless explicitly requested.
    default = @mode == :typed ? ACTIVE_FAMILIES : LEGACY_FAMILIES
    selected = Array(families).compact.empty? ? default.dup : normalize_families(families)
    selected -= normalize_families(exclude_families)
    raise ArgumentError, "no fuzz families selected" if selected.empty?

    selected
  end

  def normalize_families(families)
    Array(families).flat_map { |value| value.to_s.split(",") }.reject(&:empty?).map do |name|
      family = name.to_sym
      next family if KNOWN_FAMILIES.include?(family)

      raise ArgumentError, "unknown fuzz family: #{name} (known: #{KNOWN_FAMILIES.join(', ')})"
    end
  end

  def emit(family, rng, index, seed)
    send(:"#{family}_program", rng, index, seed)
  end

  # ---- shared helpers -----------------------------------------------------

  def header(name, index, seed)
    [
      "# fuzz-family: #{name}",
      "# fuzz-index: #{index}",
      "# fuzz-seed: #{seed}",
      "# fuzz-mode: #{@mode}"
    ]
  end

  def int(rng, min = -9, max = 9)
    rng.rand(min..max)
  end

  def nonzero_int(rng)
    n = 0
    n = int(rng, 1, 9) while n == 0
    n
  end

  def q(value)
    value.inspect
  end

  def string(rng)
    STRINGS[rng.rand(STRINGS.length)]
  end

  def separator(rng)
    SEPARATORS[rng.rand(SEPARATORS.length)]
  end

  # ========================================================================
  # Typed, recursive, type-directed generation.
  #
  # A typed scope tracks variables by Ruby type. Expression builders recurse
  # under a depth budget; at depth 0 they bottom out to literals / var refs so
  # the tree is always finite and valid.
  # ========================================================================

  # Mutable per-program typed symbol table.
  class Scope
    # Widened to carry the feature-module types: floats, symbols, hashes,
    # ranges, and a nil-typed slot. add/names/any?/pick work generically off
    # @vars.fetch, so only the key set widens — the feature builders duck-type
    # fresh_name/add/names/any?/pick against this Scope.
    TYPES = %i[int bool str array float symbol hash range nil_t].freeze

    def initialize
      @vars = {
        int: [], bool: [], str: [], array: [],
        float: [], symbol: [], hash: [], range: [], nil_t: []
      }
      @counter = 0
    end

    def fresh_name(prefix = "v")
      @counter += 1
      "#{prefix}#{@counter}"
    end

    def add(type, name)
      @vars.fetch(type) << name
      name
    end

    def names(type)
      @vars.fetch(type)
    end

    def any?(type)
      !@vars.fetch(type).empty?
    end

    def pick(type, rng)
      list = @vars.fetch(type)
      list[rng.rand(list.length)]
    end
  end

  INT_BINOPS = %w[+ - *].freeze

  # int_expr ::= literal
  #            | var-ref
  #            | (int_expr OP int_expr)            OP in + - *
  #            | (int_expr / nonzero) | (int_expr % nonzero)   guarded
  #            | array-index (mod length, via fixed literal length)
  #            | method-call-returning-int
  def int_expr(rng, scope, depth)
    if depth <= 0
      return scope.any?(:int) && rng.rand(2).zero? ? scope.pick(:int, rng) : int(rng).to_s
    end

    case rng.rand(6)
    when 0
      int(rng).to_s
    when 1
      scope.any?(:int) ? scope.pick(:int, rng) : int(rng).to_s
    when 2
      op = INT_BINOPS[rng.rand(INT_BINOPS.length)]
      "(#{int_expr(rng, scope, depth - 1)} #{op} #{int_expr(rng, scope, depth - 1)})"
    when 3
      # Guarded division/modulo: rhs is a literal nonzero constant so it is
      # provably safe regardless of the lhs subtree.
      op = rng.rand(2).zero? ? "/" : "%"
      "(#{int_expr(rng, scope, depth - 1)} #{op} #{nonzero_int(rng)})"
    when 4
      # Array index, modded into range against a known literal length so it is
      # always in-bounds. Build a fresh small literal array inline.
      len = rng.rand(1..4)
      elems = Array.new(len) { int(rng).to_s }.join(", ")
      idx = int_expr(rng, scope, depth - 1)
      "([#{elems}][(#{idx}).abs % #{len}])"
    else
      # method-call-returning-int over int subexprs.
      a = int_expr(rng, scope, depth - 1)
      b = int_expr(rng, scope, depth - 1)
      "[#{a}, #{b}].max"
    end
  end

  # bool_expr ::= literal | comparison(int,int) | (bool && bool) | (bool || bool) | !bool
  def bool_expr(rng, scope, depth)
    if depth <= 0
      return scope.any?(:bool) && rng.rand(2).zero? ? scope.pick(:bool, rng) : %w[true false][rng.rand(2)]
    end

    case rng.rand(5)
    when 0
      %w[true false][rng.rand(2)]
    when 1
      scope.any?(:bool) ? scope.pick(:bool, rng) : %w[true false][rng.rand(2)]
    when 2
      op = %w[< <= > >= == !=][rng.rand(6)]
      "(#{int_expr(rng, scope, depth - 1)} #{op} #{int_expr(rng, scope, depth - 1)})"
    when 3
      op = rng.rand(2).zero? ? "&&" : "||"
      "(#{bool_expr(rng, scope, depth - 1)} #{op} #{bool_expr(rng, scope, depth - 1)})"
    else
      "(!#{bool_expr(rng, scope, depth - 1)})"
    end
  end

  # str_expr ::= literal | var-ref | (str + str) | str * smallcount | str method
  def str_expr(rng, scope, depth)
    if depth <= 0
      return scope.any?(:str) && rng.rand(2).zero? ? scope.pick(:str, rng) : q(string(rng))
    end

    case rng.rand(5)
    when 0
      q(string(rng))
    when 1
      scope.any?(:str) ? scope.pick(:str, rng) : q(string(rng))
    when 2
      "(#{str_expr(rng, scope, depth - 1)} + #{str_expr(rng, scope, depth - 1)})"
    when 3
      "(#{str_expr(rng, scope, depth - 1)} * #{rng.rand(0..3)})"
    else
      "(#{str_expr(rng, scope, depth - 1)}.upcase)"
    end
  end

  # array_expr ::= literal int array | (array + array) | array.sort
  def int_array_expr(rng, scope, depth)
    if depth <= 0
      len = rng.rand(0..4)
      return "[#{Array.new(len) { int(rng).to_s }.join(', ')}]"
    end

    case rng.rand(4)
    when 0
      len = rng.rand(0..4)
      "[#{Array.new(len) { int(rng).to_s }.join(', ')}]"
    when 1
      scope.any?(:array) ? scope.pick(:array, rng) : "[#{int(rng)}, #{int(rng)}]"
    when 2
      "(#{int_array_expr(rng, scope, depth - 1)} + #{int_array_expr(rng, scope, depth - 1)})"
    else
      "(#{int_array_expr(rng, scope, depth - 1)}.sort)"
    end
  end

  # The typed binding types emit_bindings may introduce. Restricted to the
  # original four so legacy typed_* programs keep their historical (legacy-seed)
  # draw order and distribution; the widened Scope::TYPES exist so the feature
  # modules can store float/hash/range/etc. vars, not so emit_bindings auto-picks
  # them. Feature types are introduced explicitly inside the feature modules.
  BINDING_TYPES = %i[int bool str array].freeze

  # Emit a small block of typed `let` bindings into scope, returning lines.
  def emit_bindings(rng, scope, lines, count)
    count.times do
      type = BINDING_TYPES[rng.rand(BINDING_TYPES.length)]
      name = scope.fresh_name
      expr =
        case type
        when :int    then int_expr(rng, scope, rng.rand(1..@max_depth))
        when :bool   then bool_expr(rng, scope, rng.rand(1..@max_depth))
        when :str    then str_expr(rng, scope, rng.rand(1..@max_depth))
        when :array  then int_array_expr(rng, scope, rng.rand(1..@max_depth))
        when :float  then FuzzGen::Numeric.float_expr(rng, scope, rng.rand(1..@max_depth))
        when :hash   then FuzzGen::Collections.hash_expr(rng, scope, 1, key_kind: :str, val_kind: :int)
        when :symbol then FuzzGen::Collections.symbol_literal(rng)
        end
      lines << "#{name} = #{expr}"
      scope.add(type, name)
    end
  end

  # Deterministic print of a typed value. Type-stable printers mirror the array
  # rule (sort for stable order) so the determinism invariant holds for every
  # type: floats via fixed format to dodge platform repr drift; symbols via
  # to_s; hashes via the collections module's sort-keyed emitter.
  #
  # NOTE: no :range printer -- the supported surface does not expose Range
  # aggregate methods (.to_a/.sum/.include?), so ranges are never registered as
  # printable scope vars here; range iteration is emitted via `for..in` inside
  # the collections / composition families instead.
  def emit_prints(rng, scope, lines)
    scope.names(:int).each  { |n| lines << "puts #{n}" }
    scope.names(:bool).each { |n| lines << "puts #{n}" }
    scope.names(:str).each  { |n| lines << "puts #{n}" }
    # Arrays: sort for stable order, then join with a fixed separator.
    scope.names(:array).each { |n| lines << "puts #{n}.sort.join(\",\")" }
    scope.names(:float).each  { |n| lines << "puts format('%.6f', #{n})" }
    scope.names(:symbol).each { |n| lines << "puts #{n}.to_s" }
    scope.names(:hash).each do |n|
      FuzzGen::Collections.emit_hash_prints(rng, n, :str, :int, lines)
    end
  end

  def typed_int_program(rng, index, seed)
    scope = Scope.new
    lines = header(:typed_int, index, seed)
    emit_bindings(rng, scope, lines, rng.rand(2..4))
    # A guarded conditional driven by a bool_expr, assigning an int result var.
    res = scope.fresh_name("r")
    lines << "if #{bool_expr(rng, scope, rng.rand(1..@max_depth))}"
    lines << "  #{res} = #{int_expr(rng, scope, rng.rand(1..@max_depth))}"
    lines << "else"
    lines << "  #{res} = #{int_expr(rng, scope, rng.rand(1..@max_depth))}"
    lines << "end"
    scope.add(:int, res)
    lines << "puts #{res}"
    emit_prints(rng, scope, lines)
    lines << ""
    lines.join("\n")
  end

  def typed_bool_program(rng, index, seed)
    scope = Scope.new
    lines = header(:typed_bool, index, seed)
    emit_bindings(rng, scope, lines, rng.rand(2..4))
    name = scope.fresh_name("b")
    lines << "#{name} = #{bool_expr(rng, scope, @max_depth)}"
    scope.add(:bool, name)
    lines << "puts #{name}"
    lines << "puts(#{bool_expr(rng, scope, @max_depth)})"
    emit_prints(rng, scope, lines)
    lines << ""
    lines.join("\n")
  end

  def typed_string_program(rng, index, seed)
    scope = Scope.new
    lines = header(:typed_string, index, seed)
    emit_bindings(rng, scope, lines, rng.rand(2..4))
    s = scope.fresh_name("s")
    lines << "#{s} = #{str_expr(rng, scope, @max_depth)}"
    scope.add(:str, s)
    lines << "puts #{s}"
    lines << "puts #{s}.length"
    sep = separator(rng)
    lines << "parts = (#{s} + #{q(sep)} + #{str_expr(rng, scope, 1)}).split(#{q(sep)})"
    lines << "puts parts.length"
    lines << "puts parts.sort.join(\"|\")"
    emit_prints(rng, scope, lines)
    lines << ""
    lines.join("\n")
  end

  def typed_array_program(rng, index, seed)
    scope = Scope.new
    lines = header(:typed_array, index, seed)
    emit_bindings(rng, scope, lines, rng.rand(1..3))
    arr = scope.fresh_name("xs")
    lines << "#{arr} = #{int_array_expr(rng, scope, @max_depth)}"
    scope.add(:array, arr)
    lines << "#{arr} << #{int_expr(rng, scope, rng.rand(1..@max_depth))}"
    lines << "puts #{arr}.length"
    lines << "sum = 0"
    lines << "#{arr}.each do |e|"
    lines << "  sum = sum + e"
    lines << "end"
    lines << "puts sum"
    lines << "puts #{arr}.sort.join(\",\")"
    emit_prints(rng, scope, lines)
    lines << ""
    lines.join("\n")
  end

  def typed_struct_program(rng, index, seed)
    scope = Scope.new
    lines = header(:typed_struct, index, seed)
    emit_bindings(rng, scope, lines, rng.rand(1..2))
    lines << "Rec = Struct.new(:id, :name) unless defined?(Rec)"
    id_expr = int_expr(rng, scope, rng.rand(1..@max_depth))
    name_expr = str_expr(rng, scope, rng.rand(1..@max_depth))
    lines << "r = Rec.new(#{id_expr}, #{name_expr})"
    lines << "puts r.id"
    lines << "puts r.name"
    lines << "r.id = #{int_expr(rng, scope, rng.rand(1..@max_depth))}"
    lines << "puts r.id"
    # struct int field feeding a further int expr
    scope.add(:int, "r.id")
    lines << "puts #{int_expr(rng, scope, rng.rand(1..@max_depth))}"
    lines << ""
    lines.join("\n")
  end

  # ========================================================================
  # COMPOSITION family (step 2): COMBINE + NEST supported features.
  #
  # Supported-territory bugs are INTERACTION bugs, so this family spends its
  # budget composing supported constructs deeply: typed expressions nested
  # inside blocks, exceptions, control-flow, case/when, case/in pattern matching,
  # for..in over ranges, and across poly arrays/hashes (type mixing). Everything
  # it emits is INSIDE the documented surface; the UNSUPPORTED guard is a
  # backstop. Determinism: a single injected family_rng; every print is a stable
  # scalar / sorted-join / fixed-format float.
  # ========================================================================

  # A supported pattern-matching block (case/in) that classifies an int and
  # yields a deterministic int result var.
  def emit_case_in(rng, scope, lines, res)
    subject = int_expr(rng, scope, rng.rand(1..@max_depth))
    lo = int(rng, -3, 0)
    hi = int(rng, 1, 6)
    lines << "#{res} = case (#{subject})"
    lines << "in 0"
    lines << "  #{int_expr(rng, scope, 1)}"
    lines << "in #{lo}..#{hi}"
    lines << "  #{int_expr(rng, scope, 1)}"
    lines << "in Integer => __n"
    lines << "  __n + #{int(rng, 1, 5)}"
    lines << "end"
    scope.add(:int, res)
  end

  # A supported case/when over a string, yielding an int.
  def emit_case_when(rng, scope, lines, res)
    s = scope.any?(:str) ? scope.pick(:str, rng) : q(string(rng))
    lines << "#{res} = case (#{s})"
    lines << "when \"alpha\" then #{int(rng, 1, 9)}"
    lines << "when \"beta\", \"same\" then #{int(rng, 1, 9)}"
    lines << "else #{int(rng, 1, 9)}"
    lines << "end"
    scope.add(:int, res)
  end

  # A supported block (each/map/select/reduce) over an int array, nested inside
  # a begin/rescue, with the fold result printed.
  def emit_nested_block(rng, scope, lines)
    arr = int_array_expr(rng, scope, rng.rand(1..@max_depth))
    acc = scope.fresh_name("acc")
    lines << "#{acc} = 0"
    lines << "begin"
    lines << "  #{arr}.each do |__e|"
    lines << "    if __e > 0"
    lines << "      #{acc} = #{acc} + __e"
    lines << "    else"
    lines << "      #{acc} = #{acc} - 1"
    lines << "    end"
    lines << "  end"
    lines << "rescue StandardError"
    lines << "  #{acc} = -1"
    lines << "end"
    lines << "puts #{acc}"
    # A supported map->select->reduce chain reduced to a scalar.
    src = int_array_expr(rng, scope, rng.rand(1..@max_depth))
    lines << "puts #{src}.map { |__x| (__x * 2) }.select { |__x| __x >= 0 }" \
             ".reduce(0) { |__a, __x| __a + __x }"
  end

  # A supported for..in over a range, accumulating into an int var.
  def emit_for_range(rng, scope, lines)
    a = int(rng, -2, 2)
    b = a + int(rng, 0, 5)
    dots = rng.rand(2).zero? ? ".." : "..."
    acc = scope.fresh_name("fr")
    it = scope.fresh_name("it")
    lines << "#{acc} = 0"
    lines << "for #{it} in (#{a}#{dots}#{b})"
    lines << "  #{acc} = #{acc} + #{it}"
    lines << "end"
    lines << "puts #{acc}"
    scope.add(:int, acc)
  end

  # Type mixing through a poly array: store mixed-kind scalars, read back by
  # fixed index, render each via a supported output path (crosses the poly-render
  # vein while staying a composition).
  def emit_poly_mix(rng, scope, lines)
    pa = scope.fresh_name("mix")
    iv = int(rng, -9, 9)
    sv = q(string(rng))
    bv = %w[true false][rng.rand(2)]
    lines << "#{pa} = [#{iv}, #{sv}, #{bv}, nil]"
    lines << "puts #{pa}.length"
    lines << "puts #{pa}[0]"
    lines << "puts((#{pa}[1]).to_s)"
    lines << "puts(\"b=\#{#{pa}[2]}\")"
    lines << "puts((#{pa}[3]).nil? ? \"nil\" : \"some\")"
  end

  def composition_program(rng, index, seed)
    scope = Scope.new
    lines = header(:composition, index, seed)
    emit_bindings(rng, scope, lines, rng.rand(2..4))

    # Stack 3..5 supported, deeply-nested composition blocks in a seed-shuffled
    # order so each program mixes control-flow / blocks / exceptions / case-in /
    # for..in / poly-mixing differently.
    builders = %i[case_in case_when nested_block for_range poly_mix]
    order = builders.shuffle(random: rng)
    count = rng.rand(3..builders.length)
    order.first(count).each do |b|
      case b
      when :case_in      then emit_case_in(rng, scope, lines, scope.fresh_name("ci"))
      when :case_when    then emit_case_when(rng, scope, lines, scope.fresh_name("cw"))
      when :nested_block then emit_nested_block(rng, scope, lines)
      when :for_range    then emit_for_range(rng, scope, lines)
      when :poly_mix     then emit_poly_mix(rng, scope, lines)
      end
    end

    # A deeply-nested supported conditional driving a final int print, so the
    # composed scope vars feed one more interaction site.
    res = scope.fresh_name("z")
    lines << "if #{bool_expr(rng, scope, @max_depth)}"
    lines << "  #{res} = #{int_expr(rng, scope, @max_depth)}"
    lines << "elsif #{bool_expr(rng, scope, rng.rand(1..@max_depth))}"
    lines << "  #{res} = #{int_expr(rng, scope, @max_depth)}"
    lines << "else"
    lines << "  #{res} = #{int_expr(rng, scope, @max_depth)}"
    lines << "end"
    scope.add(:int, res)
    lines << "puts #{res}"

    emit_prints(rng, scope, lines)
    lines << ""
    lines.join("\n")
  end

  # ========================================================================
  # Legacy family templates (seeds / fallback whole-program emitters).
  # Preserved verbatim in behavior from the historical generator.
  # ========================================================================

  def scalar_program(rng, index, seed)
    a = int(rng)
    b = int(rng)
    c = nonzero_int(rng)
    d = int(rng)

    lines = header(:scalar, index, seed)
    lines << "a = #{a}"
    lines << "b = #{b}"
    lines << "c = #{c}"
    lines << "d = #{d}"
    lines << "puts a + b"
    lines << "puts a - b"
    lines << "puts a * c"
    lines << "puts (a + b) / c"
    lines << "puts (a + b) % c"
    lines << "if a < b"
    lines << "  x = a + c"
    lines << "else"
    lines << "  x = b - c"
    lines << "end"
    lines << "puts x"
    lines << "puts d.nil?"
    lines << ""
    lines.join("\n")
  end

  def method_scalar_program(rng, index, seed)
    a = int(rng)
    b = int(rng)
    c = nonzero_int(rng)

    lines = header(:method_scalar, index, seed)
    lines << "def spinel_fuzz_calc(x, y, z)"
    lines << "  if x <= y"
    lines << "    v = x + y"
    lines << "  else"
    lines << "    v = x - y"
    lines << "  end"
    lines << "  v * z"
    lines << "end"
    lines << "puts spinel_fuzz_calc(#{a}, #{b}, #{c})"
    lines << "puts spinel_fuzz_calc(#{b}, #{a}, #{c})"
    lines << ""
    lines.join("\n")
  end

  def array_program(rng, index, seed)
    values = Array.new(rng.rand(2..5)) { int(rng, -5, 8) }
    append = int(rng, -5, 8)
    slot = rng.rand(values.length)

    lines = header(:array, index, seed)
    lines << "xs = [#{values.join(', ')}]"
    lines << "puts xs.length"
    lines << "puts xs[#{slot}]"
    lines << "xs << #{append}"
    lines << "puts xs.length"
    lines << "puts xs[-1]"
    lines << "sum = 0"
    lines << "xs.each do |x|"
    lines << "  sum = sum + x"
    lines << "end"
    lines << "puts sum"
    lines << ""
    lines.join("\n")
  end

  def string_program(rng, index, seed)
    left = string(rng)
    right = string(rng)
    sep = separator(rng)

    lines = header(:string, index, seed)
    lines << "left = #{q(left)}"
    lines << "right = #{q(right)}"
    lines << "sep = #{q(sep)}"
    lines << "joined = left + sep + right"
    lines << "parts = joined.split(sep)"
    lines << "puts joined.length"
    lines << "puts parts.length"
    lines << "puts parts[0]"
    lines << "puts parts[-1]"
    lines << "puts parts.join(\"|\")"
    lines << ""
    lines.join("\n")
  end

  def hash_program(rng, index, seed)
    a = int(rng)
    b = int(rng)
    c = int(rng)
    key = %w[a b c][rng.rand(3)]

    lines = header(:hash, index, seed)
    lines << "h = {\"a\" => #{a}, \"b\" => #{b}}"
    lines << "h[\"c\"] = #{c}"
    lines << "puts h[#{q(key)}]"
    lines << "puts h[\"a\"] + h[\"b\"] + h[\"c\"]"
    lines << "puts h.key?(\"b\")"
    lines << "puts h.key?(\"missing\")"
    lines << ""
    lines.join("\n")
  end

  def struct_record_program(rng, index, seed)
    id = int(rng, 0, 8)
    next_id = int(rng, 9, 15)
    name = string(rng)
    alt = string(rng)

    lines = header(:struct_record, index, seed)
    lines << "Rec = Struct.new(:id, :name) unless defined?(Rec)"
    lines << "r = Rec.new(#{id}, #{q(name)})"
    lines << "puts r.id"
    lines << "puts r.name"
    lines << "r.id = #{next_id}"
    lines << "r.name = #{q(alt)}"
    lines << "puts r.id"
    lines << "puts r.name"
    lines << ""
    lines.join("\n")
  end

  def nested_record_program(rng, index, seed)
    id = int(rng, 1, 9)
    name = string(rng)
    fallback = int(rng, 10, 20)

    lines = header(:nested_record, index, seed)
    lines << "Rec = Struct.new(:id, :name) unless defined?(Rec)"
    lines << "items = [Rec.new(nil, #{q(name)}), Rec.new(#{id}, \"second\")]"
    lines << "if items[0].id.nil?"
    lines << "  items[0].id = #{fallback}"
    lines << "end"
    lines << "puts items[0].id"
    lines << "puts items[0].name"
    lines << "puts items[1].id"
    lines << "puts items[1].name"
    lines << ""
    lines.join("\n")
  end

  # ========================================================================
  # Feature-family emitters (thin shims into tools/fuzz/gen/*.rb modules).
  #
  # `emit` dispatches via send(:"#{family}_program", rng, index, seed), so each
  # FEATURE_FAMILY needs a top-level <family>_program(rng, index, seed). Each
  # shim injects a fresh widened Scope and the standard header() lines, then
  # delegates to the module's whole-program emitter. Determinism is preserved:
  # the single injected family_rng is the only source of randomness.
  # ========================================================================

  def build_scope
    Scope.new
  end

  def decl_controlflow_program(rng, index, seed)
    FuzzGen::DeclControlflow.program(
      rng, build_scope, index, seed, header(:decl_controlflow, index, seed)
    )
  end

  # ---- VEIN family shims --------------------------------------------------

  def poly_render_program(rng, index, seed)
    FuzzGen::PolyRender.program(
      rng, build_scope, index, seed, header(:poly_render, index, seed)
    )
  end

  def awk_literal_program(rng, index, seed)
    FuzzGen::AwkLiteral.program(
      rng, build_scope, index, seed, header(:awk_literal, index, seed)
    )
  end

  def float_format_program(rng, index, seed)
    FuzzGen::FloatFormat.program(
      rng, build_scope, index, seed, header(:float_format, index, seed)
    )
  end

  def numeric_program(rng, index, seed)
    FuzzGen::Numeric.numeric_program(
      rng, index, seed,
      scope: build_scope,
      header_lines: header(:numeric, index, seed),
      max_depth: @max_depth
    )
  end

  def collections_program(rng, index, seed)
    body = FuzzGen::Collections.collections_program(rng, index, seed)
    prepend_header(:collections, index, seed, body)
  end

  def methods_program(rng, index, seed)
    FuzzGen::Methods.methods_program(
      rng, index, seed, build_scope, header(:methods, index, seed)
    )
  end

  def exceptions_program(rng, index, seed)
    FuzzGen::Exceptions.exceptions_program(
      rng, index, seed,
      scope: build_scope,
      header_lines: header(:exceptions, index, seed)
    )
  end

  def strings_program(rng, index, seed)
    FuzzGen::Strings.program(
      rng, build_scope, index, seed, header(:strings, index, seed)
    )
  end

  def enumerable_program(rng, index, seed)
    # FuzzGen::Enumerable.program ignores header_lines (it emits its own
    # fuzz-* header), so swap in the generator's canonical header.
    body = FuzzGen::Enumerable.program(rng, build_scope, index, seed)
    prepend_header(:enumerable, index, seed, body)
  end

  # Replace a module's self-supplied `# fuzz-*` header block with the generator's
  # canonical header (so family/index/seed/mode are consistent across families).
  # Modules whose whole-program emitter does not accept header_lines (currently
  # collections) emit their own header; we swap it for ours.
  def prepend_header(name, index, seed, body)
    lines = body.split("\n", -1)
    lines.shift while lines.first&.start_with?("# fuzz-")
    (header(name, index, seed) + lines).join("\n")
  end
end

# ---------------------------------------------------------------------------
# Self-test (guarded so it never runs on require).
# ---------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  require "tempfile"

  PARSER_SUPPORTS_ACTIVE_SYNTAX =
    begin
      RubyVM::AbstractSyntaxTree.parse("case 1\nin 1\n  1\nend\n")
      RubyVM::AbstractSyntaxTree.parse("def __spinel_fuzz_probe__(a) = a\n")
      true
    rescue SyntaxError, ArgumentError
      false
    end

  def parses?(source)
    return true unless PARSER_SUPPORTS_ACTIVE_SYNTAX

    RubyVM::AbstractSyntaxTree.parse(source)
    true
  rescue SyntaxError, ArgumentError
    false
  end

  banned = Generator::BANNED_TOKENS
  excluded = Generator::UNSUPPORTED_TOKENS
  total = 0
  failures = 0

  seeds = [1, 7, 42, 1234, 99_999]
  per_seed = 200

  modes = %i[typed templates]

  unless PARSER_SUPPORTS_ACTIVE_SYNTAX
    warn "generator self-test: Ruby #{RUBY_VERSION} cannot parse the active Ruby 3 corpus; skipping parse-only checks"
  end

  # Track which families are actually drawn in default typed mode (to prove the
  # vein + supported-feature mass distribution AND that dormant families are
  # never auto-sampled), and count the vein/composition shapes that appear.
  family_counts = Hash.new(0)

  modes.each do |mode|
    seeds.each do |seed|
      gen = Generator.new(seed, mode: mode)
      per_seed.times do |i|
        c = gen.generate(i)
        total += 1
        family_counts[c.family] += 1 if mode == :typed

        unless parses?(c.source)
          failures += 1
          warn "PARSE FAIL mode=#{mode} seed=#{seed} index=#{i} family=#{c.family}"
          warn c.source
          next
        end

        hit = banned.find { |re| c.source =~ re }
        if hit
          failures += 1
          warn "BANNED TOKEN #{hit.inspect} mode=#{mode} seed=#{seed} index=#{i} family=#{c.family}"
          warn c.source
          next
        end

        # GENERATION EXCLUDE GUARD: no documented-unsupported / intentional-
        # divergence construct may ever reach the corpus.
        xhit = excluded.find { |re| c.source =~ re }
        if xhit
          failures += 1
          warn "EXCLUDE TOKEN #{xhit.inspect} mode=#{mode} seed=#{seed} index=#{i} family=#{c.family}"
          warn c.source
        end
      end
    end
  end

  # Dormant families must NOT be auto-sampled in default typed mode.
  Generator::DORMANT_FEATURE_FAMILIES.each do |fam|
    next if family_counts[fam.to_s].zero?

    failures += 1
    warn "DORMANT FAMILY SAMPLED: #{fam} drawn #{family_counts[fam.to_s]}x in default typed mode"
  end

  # The vein + composition families must carry real mass (shapes present).
  %w[decl_controlflow poly_render awk_literal float_format composition].each do |fam|
    next unless family_counts[fam].zero?

    failures += 1
    warn "EXPECTED FAMILY ABSENT: #{fam} never drawn in default typed mode"
  end

  # Determinism: same (seed,index) reproduces identical source.
  a = Generator.replay(42, 5)
  b = Generator.replay(42, 5)
  unless a.source == b.source && a.seed == b.seed
    failures += 1
    warn "DETERMINISM FAIL: replay(42,5) not stable"
  end

  # Cross-check: ruby -c on a sampling via a temp file (independent of AST parser).
  if PARSER_SUPPORTS_ACTIVE_SYNTAX
    sample = Generator.new(2024, mode: :typed).generate(3)
    Tempfile.create(["gen_selftest", ".rb"]) do |f|
      f.write(sample.source)
      f.flush
      ok = system("ruby", "-c", f.path, out: File::NULL, err: File::NULL)
      unless ok
        failures += 1
        warn "ruby -c FAIL on sampled case"
        warn sample.source
      end
    end
  else
    warn "generator self-test: skipped ruby -c sample under Ruby #{RUBY_VERSION}"
  end

  # Family selection / validation sanity.
  begin
    Generator.new(1, families: "typed_int,scalar", mode: :typed)
    Generator.new(1, exclude_families: %i[hash], mode: :templates)
  rescue StandardError => e
    failures += 1
    warn "family selection FAIL: #{e.class}: #{e.message}"
  end
  begin
    Generator.new(1, families: "nope")
    failures += 1
    warn "expected ArgumentError for unknown family"
  rescue ArgumentError
    # expected
  end

  # Each FEATURE_FAMILY must be selectable in isolation and emit parseable,
  # banned-token-free, EXCLUDE-token-free Ruby on its own. (Dormant families that
  # could emit unsupported constructs are caught by the EXCLUDE gate inside
  # generate, which substitutes a supported composition program.)
  Generator::FEATURE_FAMILIES.each do |fam|
    gen = Generator.new(7, families: fam.to_s, mode: :typed)
    20.times do |i|
      c = gen.generate(i)
      total += 1
      ok = parses?(c.source) &&
           banned.none? { |re| c.source =~ re } &&
           excluded.none? { |re| c.source =~ re }
      next if ok

      failures += 1
      warn "FEATURE FAMILY FAIL fam=#{fam} index=#{i}"
      warn c.source
    end
  end

  # The SUPPORTED-surface feature families must be selectable as the default set
  # and validate cleanly across many seeds (this is the active corpus).
  Generator::ACTIVE_FAMILIES.each do |fam|
    gen = Generator.new(99, families: fam.to_s, mode: :typed)
    30.times do |i|
      c = gen.generate(i)
      total += 1
      ok = parses?(c.source) &&
           banned.none? { |re| c.source =~ re } &&
           excluded.none? { |re| c.source =~ re }
      next if ok

      failures += 1
      warn "ACTIVE FAMILY FAIL fam=#{fam} index=#{i}"
      warn c.source
    end
  end

  # Report the default typed-mode family distribution so the mass is visible.
  dist = family_counts.sort_by { |_, n| -n }.map { |f, n| "#{f}=#{n}" }.join(" ")
  warn "default typed-mode family distribution: #{dist}"

  puts "self-test: #{total} programs generated, #{failures} failures"
  exit(failures.zero? ? 0 : 1)
end
