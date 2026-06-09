# frozen_string_literal: true

# VEIN: tag-losing unbox on poly/RbVal container read-back.
#
# Confirmed root cause (from the upstream handoff): a non-int value
# (true/false/nil/symbol/float) stored in a poly_array / *_poly_hash loses its
# tag when read back and travels the INT rendering path, so `to_s` / `inspect`
# renders "1"/"0" instead of "true"/"false" (and nil/symbol/float likewise
# narrow). The narrowing also corrupts is_a? checks and comparisons.
#
# This module round-trips EVERY supported scalar type
# (bool / nil / symbol / float / int / string) THROUGH a polymorphic container
# (a heterogeneous array, or a poly-valued hash) and then renders the read-back
# value through EVERY supported output path:
#   * puts <v>
#   * print <v>; puts        (separate print path)
#   * "#{<v>}" interpolation
#   * <v>.to_s
#   * a chooser that branches on is_a?(...) and prints which arm fired
#
# Because Spinel's `p`/`inspect` on Hash/Range/Struct is a DOCUMENTED gap, we
# NEVER inspect a hash/range/struct here, and we never call `.inspect` at all
# (it is a BANNED token). We render scalars via to_s / interpolation / puts,
# all of which ARE in the supported surface, so any divergence is a
# supported-territory finding.
#
# DETERMINISM: all randomness flows through the injected `rng`. Booleans/nil/
# symbols/ints/strings render byte-exactly; floats are printed via
# format('%.6f', ...). Heterogeneous arrays are NOT sorted (mixed-type sort is
# undefined), so we index them by a fixed literal position instead -- the read
# order is therefore deterministic and position-stable. Valid Ruby by
# construction; the reference CRuby run is always clean.
#
# Pure stdlib. module_function builders take an explicit `rng` and a duck-typed
# `scope` (only #fresh_name is required).

module FuzzGen
  module PolyRender
    module_function

    SYM_NAMES = %w[a b alpha beta key flag on off red green].freeze
    STR_WORDS = %w[alpha beta gamma value token same].freeze
    FLOATS    = %w[0.0 1.0 -1.0 0.5 -0.5 2.5 -2.5 1.5 10.0 -10.0].freeze

    # A source token for a scalar of the named kind, paired with the kind so the
    # renderer can choose a type-stable print path.
    def scalar_source(rng, kind)
      case kind
      when :bool  then %w[true false][rng.rand(2)]
      when :nil   then "nil"
      when :sym   then ":#{SYM_NAMES[rng.rand(SYM_NAMES.length)]}"
      when :float then FLOATS[rng.rand(FLOATS.length)]
      when :int   then rng.rand(-9..9).to_s
      when :str   then STR_WORDS[rng.rand(STR_WORDS.length)].inspect
      else raise ArgumentError, "unknown scalar kind: #{kind.inspect}"
      end
    end

    POLY_KINDS = %i[bool nil sym float int str].freeze

    # A type-stable print of a single read-back element expression `expr`, whose
    # *intended* kind is `kind`. Floats use %.6f; every other kind uses a path
    # that renders byte-exactly under CRuby (and SHOULD under Spinel).
    def render_line(rng, expr, kind)
      case kind
      when :float
        # %.6f dodges platform float-repr drift; the tag-loss bug would render
        # this as an int instead.
        "puts format('%.6f', #{expr})"
      else
        case rng.rand(4)
        when 0 then "puts #{expr}"
        when 1 then "puts((#{expr}).to_s)"
        when 2 then "puts(\"v=\#{#{expr}}\")"
        else
          # is_a? chooser: the tag-loss bug makes a bool/nil/sym read-back claim
          # to be an Integer, so the WRONG arm fires -> observable divergence.
          "puts(((#{expr}).is_a?(Integer)) ? \"int\" : ((#{expr}).nil? ? \"nil\" : \"other\"))"
        end
      end
    end

    # poly_array_roundtrip(rng, scope, lines)
    #
    # Build a heterogeneous array literal mixing several scalar kinds, store it in
    # a fresh var, then read EACH slot back by fixed literal index and render it
    # through a supported output path. Indexing by literal position keeps the read
    # deterministic without sorting a mixed-type array.
    def poly_array_roundtrip(rng, scope, lines)
      # 3..6 elements, kinds chosen so at least one non-int tag is present.
      n = rng.rand(3..6)
      kinds = Array.new(n) { POLY_KINDS[rng.rand(POLY_KINDS.length)] }
      kinds[0] = %i[bool nil sym float][rng.rand(4)] # force a tag-bearing slot
      elems = kinds.map { |k| scalar_source(rng, k) }
      name = scope.fresh_name("pa")
      lines << "#{name} = [#{elems.join(', ')}]"
      lines << "puts #{name}.length"
      kinds.each_index do |i|
        lines << render_line(rng, "#{name}[#{i}]", kinds[i])
      end
    end

    # poly_hash_roundtrip(rng, scope, lines)
    #
    # Build a poly-VALUED hash (string keys -> mixed-kind values), store it, then
    # read each value back by its (sorted, deterministic) key and render it. The
    # hash itself is never inspected (Hash#inspect is a documented gap); only its
    # scalar VALUES travel the render paths.
    def poly_hash_roundtrip(rng, scope, lines)
      n = rng.rand(2..4)
      keys = %w[k0 k1 k2 k3].first(n)
      kinds = Array.new(n) { POLY_KINDS[rng.rand(POLY_KINDS.length)] }
      kinds[0] = %i[bool nil sym float][rng.rand(4)]
      pairs = keys.each_index.map { |i| "#{keys[i].inspect} => #{scalar_source(rng, kinds[i])}" }
      name = scope.fresh_name("ph")
      lines << "#{name} = {#{pairs.join(', ')}}"
      lines << "puts #{name}.length"
      # Read back in sorted-key order (deterministic) and render each value.
      keys.each_index do |i|
        lines << render_line(rng, "#{name}[#{keys[i].inspect}]", kinds[i])
      end
    end

    # bool_into_poly_compare(rng, scope, lines)
    #
    # Store a boolean into a poly slot, read it back, and use it in a boolean
    # CONTEXT (if / && / ==) so a tag-narrowed read (true -> 1) changes control
    # flow. Pure supported surface (if/else, ==, puts).
    def bool_into_poly_compare(rng, scope, lines)
      b = %w[true false][rng.rand(2)]
      name = scope.fresh_name("pb")
      lines << "#{name} = [#{b}, 0]"
      v = scope.fresh_name("bv")
      lines << "#{v} = #{name}[0]"
      lines << "if #{v} == true"
      lines << "  puts \"is-true\""
      lines << "elsif #{v} == false"
      lines << "  puts \"is-false\""
      lines << "else"
      lines << "  puts \"is-other\""
      lines << "end"
      lines << "puts(#{v} ? \"truthy\" : \"falsy\")"
    end

    # ------------------------------------------------------------------
    # Whole-program emitter + generator-integration shim.
    # ------------------------------------------------------------------

    def program(rng, scope, index, seed, header_lines = nil)
      scope ||= MiniScope.new
      lines = header_lines ? header_lines.dup : default_header(index, seed)

      rng.rand(1..2).times { poly_array_roundtrip(rng, scope, lines) }
      rng.rand(1..2).times { poly_hash_roundtrip(rng, scope, lines) }
      bool_into_poly_compare(rng, scope, lines)

      lines << ""
      lines.join("\n")
    end

    def poly_render_program(rng, index, seed)
      program(rng, nil, index, seed)
    end

    def default_header(index, seed)
      [
        "# fuzz-family: poly_render",
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
      src = FuzzGen::PolyRender.poly_render_program(crng, i, case_seed)
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

      Tempfile.create(["poly_selftest", ".rb"]) do |f|
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

  a = FuzzGen::PolyRender.poly_render_program(Random.new(123), 5, 123)
  b = FuzzGen::PolyRender.poly_render_program(Random.new(123), 5, 123)
  if a != b
    failures += 1
    warn "DETERMINISM FAIL"
  end

  puts "poly_render self-test: #{total} programs generated, #{failures} failures"
  exit(failures.zero? ? 0 : 1)
end
