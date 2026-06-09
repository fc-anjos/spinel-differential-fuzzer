# frozen_string_literal: true

# Feature generator: COLLECTIONS dimension for the Spinel fuzzer.
#
# Aims AT and ACROSS the typed-hash variant lattice, nested arrays/hashes,
# ranges, symbols, nil, and mixed-type literals.
#
# Spinel infers a concrete typed-hash variant per literal from its key/value
# types (spinel_analyze.rb ~3103-3175):
#   str_int_hash / sym_int_hash / int_int_hash / str_str_hash / sym_str_hash /
#   str_poly_hash / sym_poly_hash / poly_poly_hash.
# Float values have NO dedicated variant (codegen line 4483) and route through
# poly storage -- a hand-noted boundary. An empty `{}` defaults to one variant
# (str_int_hash, analyze line 219) while a populated one infers another, so the
# generator deliberately emits empty/singleton/populated forms and merges across
# variants (codegen line 2180 'Wrap a narrower-hash RHS') to stress widening.
# RangeNode -> `range` (analyze line 2253); SymbolNode -> `symbol`.
# Mixed nil/int arrays force poly_array promotion.
#
# DETERMINISM: every printed hash is keys-sorted before iteration (hashes have
# no guaranteed C-side iteration order); ranges/arrays are sorted/aggregated;
# floats are printed via format('%.6f', ...) to dodge platform repr drift.
# No Time/rand/object_id/inspect/hash/p/GC -- randomness is always the injected
# `rng`. Valid Ruby by construction.
#
# Pure stdlib. The module exposes module_function builders that take an explicit
# `rng` (per-case Random) and a `scope` (Generator::Scope), matching the
# generator.rb int(rng)/string(rng) discipline.

module FuzzGen
  module Collections
    module_function

    # --- small deterministic literal helpers (RNG always injected) ----------

    # Symbol names drawn from a fixed pool; used both as keys and values.
    SYM_NAMES = %w[a b c d alpha beta gamma key one two red green].freeze
    # String literals used as keys/values (kept simple, no escapes that the
    # banned-token scan or sort could trip over).
    STR_WORDS = %w[apple banana cherry delta echo foxtrot zulu nil_ze].freeze

    def int_lit(rng, min = -9, max = 9)
      rng.rand(min..max)
    end

    def nonzero_int(rng)
      n = 0
      n = rng.rand(1..9) while n.zero?
      n
    end

    def float_lit(rng)
      # Bounded, non-integral, fixed-precision so format('%.6f', ...) is stable.
      whole = rng.rand(-5..5)
      frac = rng.rand(1..99)
      "#{whole}.#{frac.to_s.rjust(2, '0')}"
    end

    def str_word(rng)
      STR_WORDS[rng.rand(STR_WORDS.length)]
    end

    def sym_name(rng)
      SYM_NAMES[rng.rand(SYM_NAMES.length)]
    end

    # symbol_literal(rng) -> String : a SymbolNode source like ":alpha".
    def symbol_literal(rng)
      ":#{sym_name(rng)}"
    end

    # --- key / value emitters keyed by kind ---------------------------------

    # A distinct, sortable key for the given kind. We track used keys so a hash
    # literal never collides keys (which would shrink it and break the
    # element-count assertions). Keys are returned together with a sort token.
    def key_source(rng, key_kind, used)
      case key_kind
      when :str
        loop do
          w = str_word(rng)
          k = w.dup
          unless used.include?(k)
            used << k
            return ["#{k.inspect}", k]
          end
          # fall back to a numbered key to guarantee progress / uniqueness
          k = "#{w}#{used.length}"
          next if used.include?(k)
          used << k
          return ["#{k.inspect}", k]
        end
      when :sym
        loop do
          s = sym_name(rng)
          unless used.include?(s)
            used << s
            return [":#{s}", s]
          end
          s2 = "#{s}#{used.length}"
          next if used.include?(s2)
          used << s2
          return [":#{s2}", s2]
        end
      when :int
        loop do
          n = rng.rand(0..99)
          unless used.include?(n)
            used << n
            return [n.to_s, n]
          end
        end
      else
        raise ArgumentError, "unknown key_kind: #{key_kind.inspect}"
      end
    end

    # A value source for the given value kind. depth bounds nesting.
    def value_source(rng, scope, depth, val_kind)
      case val_kind
      when :int
        int_lit(rng).to_s
      when :str
        str_word(rng).inspect
      when :sym
        symbol_literal(rng)
      when :float
        float_lit(rng)
      when :poly
        # Mixed value types within one hash -> forces *_poly_hash storage.
        case rng.rand(4)
        when 0 then int_lit(rng).to_s
        when 1 then str_word(rng).inspect
        when 2 then symbol_literal(rng)
        else        %w[true false nil][rng.rand(3)]
        end
      when :nested
        # An inner collection value -> forces poly outer (analyze ~3170).
        if depth <= 0
          "[#{Array.new(rng.rand(0..3)) { int_lit(rng).to_s }.join(', ')}]"
        elsif rng.rand(2).zero?
          "[#{Array.new(rng.rand(1..3)) { int_lit(rng).to_s }.join(', ')}]"
        else
          inner_key = rng.rand(2).zero? ? :str : :sym
          hash_expr(rng, scope, depth - 1, key_kind: inner_key, val_kind: :int)
        end
      else
        raise ArgumentError, "unknown val_kind: #{val_kind.inspect}"
      end
    end

    # --- hash_expr ----------------------------------------------------------

    # hash_expr(rng, scope, depth, key_kind:, val_kind:) -> String
    #
    # Drives specific typed-hash variant selection AND the unhandled float-value
    # path. key_kind in [:str,:sym,:int]; val_kind in
    # [:int,:str,:sym,:float,:poly,:nested].
    #
    # Emits empty / singleton / populated forms (the empty `{}` default-variant
    # vs populated-inference boundary, analyze line 219). Occasionally emits a
    # `.merge(...)` across a narrower RHS to stress widening (codegen line 2180).
    def hash_expr(rng, scope, depth, key_kind:, val_kind:)
      shape = rng.rand(10)
      base =
        if shape.zero?
          # Empty hash: defaults to str_int_hash regardless of declared kinds.
          "{}"
        else
          count =
            if shape == 1
              1 # singleton
            else
              rng.rand(1..4)
            end
          used = []
          pairs = Array.new(count) do
            k, = key_source(rng, key_kind, used)
            v = value_source(rng, scope, depth, val_kind)
            "#{k} => #{v}"
          end
          "{#{pairs.join(', ')}}"
        end

      # Cross-variant merge: a narrower RHS (e.g. populated str_int) merged into
      # the base stresses the 'Wrap a narrower-hash RHS' widening path.
      if depth.positive? && rng.rand(4).zero?
        used2 = []
        rk, = key_source(rng, key_kind, used2)
        rv = value_source(rng, scope, [depth - 1, 0].max, rng.rand(2).zero? ? val_kind : :int)
        return "#{base}.merge({#{rk} => #{rv}})"
      end

      base
    end

    # --- nested_collection_expr ---------------------------------------------

    # nested_collection_expr(rng, scope, depth) -> String
    # Array of hashes, or hash of arrays, depth-bounded.
    def nested_collection_expr(rng, scope, depth)
      d = [depth, 0].max
      if rng.rand(2).zero?
        # Array of hashes.
        kk = %i[str sym int][rng.rand(3)]
        vk = %i[int str sym][rng.rand(3)]
        len = rng.rand(0..3)
        elems = Array.new(len) do
          hash_expr(rng, scope, d > 0 ? d - 1 : 0, key_kind: kk, val_kind: vk)
        end
        "[#{elems.join(', ')}]"
      else
        # Hash of arrays (value kind :nested yields inner arrays/hashes).
        kk = %i[str sym int][rng.rand(3)]
        hash_expr(rng, scope, d, key_kind: kk, val_kind: :nested)
      end
    end

    # --- range_lines --------------------------------------------------------

    # range_lines(rng, scope, lines)
    # SUPPORTED-SURFACE range usage only: `for..in` over a range (documented
    # supported) accumulating into a plain int var. The Range AGGREGATE methods
    # (.to_a / .sum / .include? / .min / .max) are OUT of the documented surface
    # and were dropped; we never call them. Emits a singleton/empty edge plus a
    # multi-element range, both folded by an explicit for-loop, and prints the
    # deterministic accumulator. `lines` receives the emitted statements.
    # `fresh` is a name allocator (lambda or anything responding to #call(prefix))
    # supplied by the caller so names are unique AND reset per program (keeping
    # generation a pure function of the seed -- no module-level mutable counter).
    def range_lines(rng, fresh, lines)
      excl = rng.rand(2).zero?
      dots = excl ? "..." : ".."
      a = rng.rand(-3..5)
      b =
        case rng.rand(4)
        when 0 then a          # singleton (a..a) / empty (a...a)
        when 1 then a + 1
        else        a + rng.rand(2..5)
        end
      acc = fresh.call("rg")
      itv = fresh.call("ri")
      lines << "#{acc} = 0"
      lines << "for #{itv} in (#{a}#{dots}#{b})"
      lines << "  #{acc} = #{acc} + #{itv}"
      lines << "end"
      lines << "puts #{acc}"
    end

    # --- nil_mixed_array_expr ----------------------------------------------

    # nil_mixed_array_expr(rng, scope) -> String
    # Arrays containing nil + ints, forcing poly_array promotion. Printed by the
    # caller via a nil-safe, sorted reduction. Returns the array source.
    def nil_mixed_array_expr(rng, scope)
      len = rng.rand(2..5)
      elems = Array.new(len) do
        case rng.rand(3)
        when 0 then "nil"
        else        int_lit(rng).to_s
        end
      end
      # Guarantee at least one nil and one int so promotion always fires.
      elems[0] = "nil"
      elems[1] = int_lit(rng).to_s if elems.length > 1
      "[#{elems.join(', ')}]"
    end

    # --- emit_hash_prints ---------------------------------------------------

    # emit_hash_prints(rng, name, key_kind, val_kind, lines)
    # Deterministic: sort the keys, then iterate in sorted order. NEVER raw hash
    # iteration (no .each / .map over the hash directly), since C-side hash
    # iteration order is not guaranteed.
    #
    # `name` is a Ruby expression referring to an in-scope hash variable.
    def emit_hash_prints(rng, name, key_kind, val_kind, lines)
      lines << "puts #{name}.length"
      # Sort keys deterministically. For symbol keys, sort by to_s; ints/strings
      # sort natively. Then look each value up and print a type-stable rendering.
      sorter =
        case key_kind
        when :sym then "#{name}.keys.sort_by(&:to_s)"
        else           "#{name}.keys.sort"
        end
      kvar = "__hk"
      vvar = "__hv"
      lines << "#{sorter}.each do |#{kvar}|"
      key_render =
        case key_kind
        when :sym then "#{kvar}.to_s"
        else           "#{kvar}.to_s"
        end
      lines << "  #{vvar} = #{name}[#{kvar}]"
      lines << "  #{value_print_line(vvar, val_kind, key_render)}"
      lines << "end"
    end

    # Build the body line that prints a key/value pair in a type-stable way.
    def value_print_line(vvar, val_kind, key_render)
      case val_kind
      when :int, :sym, :str
        # to_s renders int/symbol/string uniformly and deterministically.
        "puts(#{key_render} + \"=\" + #{vvar}.to_s)"
      when :float
        # Fixed precision dodges platform float repr drift.
        "puts(#{key_render} + \"=\" + format('%.6f', #{vvar}))"
      when :poly, :nested
        # Mixed / nested values: render each via a nil-safe, sorted-if-collection
        # stable form. Use a helper expression that never leaks address/order.
        "puts(#{key_render} + \"=\" + #{stable_render(vvar)})"
      else
        "puts(#{key_render} + \"=\" + #{vvar}.to_s)"
      end
    end

    # A deterministic string rendering of an arbitrary (poly/nested) value:
    #   - Array  -> sorted-by-to_s, comma-joined inside brackets
    #   - Hash   -> keys sorted, "k:v" pairs joined
    #   - Float  -> fixed precision
    #   - nil    -> "nil"
    #   - else   -> to_s
    # Avoids .inspect / .hash entirely.
    def stable_render(vvar)
      "(" \
        "#{vvar}.is_a?(Array) ? (\"[\" + #{vvar}.map { |__e| __e.nil? ? \"nil\" : __e.to_s }.sort.join(\",\") + \"]\") : " \
        "(#{vvar}.is_a?(Hash) ? (\"{\" + #{vvar}.keys.sort_by(&:to_s).map { |__k| __k.to_s + \":\" + #{vvar}[__k].to_s }.join(\",\") + \"}\") : " \
        "(#{vvar}.is_a?(Float) ? format('%.6f', #{vvar}) : " \
        "(#{vvar}.nil? ? \"nil\" : #{vvar}.to_s)))" \
        ")"
    end

    # --- whole-program emitter ----------------------------------------------

    # collections_program(rng, index, seed) -> String
    #
    # Self-contained, valid-Ruby program exercising the collections dimension.
    # Header comments match generator.rb's header() shape (family/index/seed).
    # All prints are deterministic.
    def collections_program(rng, index, seed)
      lines = []
      lines << "# fuzz-family: collections"
      lines << "# fuzz-index: #{index}"
      lines << "# fuzz-seed: #{seed}"
      lines << "# fuzz-mode: typed"

      counter = 0
      fresh = lambda do |prefix|
        counter += 1
        "#{prefix}#{counter}"
      end

      # 1) Typed-hash variants: walk the key x value cartesian product so every
      #    concrete variant (str_int/sym_int/int_int/str_str/sym_str/str_poly/
      #    sym_poly/poly_poly) AND the float-value poly path is exercised.
      key_kinds = %i[str sym int]
      val_kinds = %i[int str sym float poly nested]
      # Pick a deterministic subset each run so programs stay small but the
      # union across seeds covers the whole lattice.
      pairs = key_kinds.product(val_kinds)
      chosen = pairs.select { rng.rand(3).zero? }
      chosen = [pairs[rng.rand(pairs.length)]] if chosen.empty?

      chosen.each do |kk, vk|
        hname = fresh.call("h")
        depth = rng.rand(0..2)
        lines << "#{hname} = #{hash_expr(rng, nil, depth, key_kind: kk, val_kind: vk)}"
        # Mutate via assignment to a fresh key (re-exercises set-site lowering).
        used = []
        nk, = key_source(rng, kk, used)
        nv = value_source(rng, nil, 0, vk == :nested ? :int : vk)
        lines << "#{hname}[#{nk}] = #{nv}"
        emit_hash_prints(rng, hname, kk, vk, lines)
      end

      # 2) Nested collections (array of hashes / hash of arrays).
      nname = fresh.call("nc")
      lines << "#{nname} = #{nested_collection_expr(rng, nil, rng.rand(1..2))}"
      lines << "if #{nname}.is_a?(Array)"
      lines << "  puts #{nname}.length"
      lines << "  #{nname}.each_with_index do |__el, __i|"
      lines << "    if __el.is_a?(Hash)"
      lines << "      puts(__i.to_s + \":\" + __el.keys.sort_by(&:to_s).map { |__k| __k.to_s }.join(\",\"))"
      lines << "    else"
      lines << "      puts(__i.to_s + \":\" + __el.to_s)"
      lines << "    end"
      lines << "  end"
      lines << "else"
      lines << "  puts #{nname}.length"
      lines << "  #{nname}.keys.sort_by(&:to_s).each do |__k|"
      lines << "    __v = #{nname}[__k]"
      lines << "    if __v.is_a?(Array)"
      lines << "      puts(__k.to_s + \"=\" + __v.map { |__e| __e.nil? ? \"nil\" : __e.to_s }.sort.join(\",\"))"
      lines << "    else"
      lines << "      puts(__k.to_s + \"=\" + __v.to_s)"
      lines << "    end"
      lines << "  end"
      lines << "end"

      # 3) Ranges via SUPPORTED `for..in` folds (singleton/empty/multi edges).
      #    Range aggregate methods (.to_a/.sum/.include?) are out of surface.
      rng.rand(2..3).times do
        range_lines(rng, fresh, lines)
      end

      # 4) Symbols.
      symvar = fresh.call("sy")
      lines << "#{symvar} = #{symbol_literal(rng)}"
      lines << "puts #{symvar}.to_s"

      # 5) nil + int mixed array forcing poly_array promotion. Reduce via
      #    SUPPORTED ops only: select to drop nils, sort_by + reduce to fold
      #    (no .compact / .sum -- neither is in the documented surface).
      mavar = fresh.call("ma")
      lines << "#{mavar} = #{nil_mixed_array_expr(rng, nil)}"
      lines << "puts #{mavar}.length"
      lines << "#{mavar}_nn = #{mavar}.select { |__e| !__e.nil? }"
      lines << "puts #{mavar}_nn.sort_by { |__e| __e }.reduce(0) { |__a, __e| __a + __e }"
      lines << "puts #{mavar}_nn.length"
      lines << "puts(#{mavar}.map { |__e| __e.nil? ? \"nil\" : __e.to_s }.sort.join(\",\"))"

      lines << ""
      lines.join("\n")
    end
  end
end

# ---------------------------------------------------------------------------
# Self-test (guarded so it never runs on require).
# Generates >=100 snippets across several seeds, writes each to a temp file,
# and asserts `ruby -c` passes and no banned tokens appear. Also runs each
# generated program to confirm it is clean valid Ruby (the reference CRuby run
# must be clean so any spinel diff is attributable to spinel).
# ---------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  require "tempfile"

  BANNED = [
    /\bTime\b/, /\bDateTime\b/, /\brand\b/, /\bsrand\b/, /\bobject_id\b/,
    /\b__id__\b/, /\.inspect\b/, /\bp\s/, /\bGC\b/, /\bObjectSpace\b/,
    /\.hash\b/, /\bRandom\b/, /\b__FILE__\b/, /\b__LINE__\b/, /\bcaller\b/,
    /\bENV\b/,
    # Out-of-surface aggregate methods that must no longer be emitted.
    /\.sum\b/, /\.compact\b/, /\.to_a\b/, /\.include\?/, /\.group_by\b/,
    /\.minmax\b/, /\.flatten\b/
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
      family_rng = Random.new(case_seed)
      src = FuzzGen::Collections.collections_program(family_rng, i, case_seed)
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
      end

      # ruby -c + actual execution (reference CRuby must be clean).
      Tempfile.create(["coll_selftest", ".rb"]) do |f|
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

  # Determinism: same (seed,index)->same source.
  a = FuzzGen::Collections.collections_program(Random.new(123), 5, 123)
  b = FuzzGen::Collections.collections_program(Random.new(123), 5, 123)
  if a != b
    failures += 1
    warn "DETERMINISM FAIL"
  end

  puts "collections self-test: #{total} programs generated, #{failures} failures"
  exit(failures.zero? ? 0 : 1)
end
