# frozen_string_literal: true

# Feature generator: ENUMERABLE dimension for the Spinel fuzzer.
#
# SUPPORTED-SURFACE RESTRICTION (step 1): this module now emits ONLY the block
# methods listed as supported in README.md "Supported Ruby Features":
#   each, each_with_index, map, select, reject, reduce, sort_by, any?, all?,
#   none?, times, upto, downto.
# The previously-emitted gap-chasing methods (filter_map, inject(:+)/reduce(:+)
# SYMBOL form, zip, flatten, each_with_object, min/max/min_by/max_by, minmax,
# group_by, partition, each_slice, each_cons, sum) have been DROPPED -- they are
# outside the documented surface, so any divergence is a known gap, not a bug.
# Terminal reductions use `reduce(init) { |acc, x| ... }` (block form, supported)
# instead of `.sum`; ordering uses `sort_by` (supported). The goal is interaction
# bugs INSIDE the supported block surface: supported features composed deeply
# over int arrays, ranges, and string arrays, and pushed through blocks.
#
# Why this is a dense intersection (and where composition degrades):
#   * A `map` over a float_array that returns ints changes the element type
#     mid-chain (float_array -> int_array), stressing element-type tracking.
#   * sort_by / group_by / min_by must CALL the block and ORDER results.
#     group_by returns a hash whose iteration order is unspecified C-side, so
#     it MUST be normalized (keys sorted) for a deterministic diff.
#   * zip and flatten(n) build nested poly_arrays, exercising the poly_array
#     path and flatten-depth lowering.
#   * These chains compose typed expression builders (numeric/collections) and
#     push them through the same yield/block ABI that methods.rb targets.
#
# DETERMINISM: every terminal print is reduced to a length / sum / sorted-join,
# so block-call ordering and hash iteration order can never leak. Floats are
# printed via format('%.6f', ...) to dodge platform repr drift. Block bodies are
# pure deterministic expressions over their parameters (no Time/rand/object_id/
# inspect/hash/p/GC). Sources, ranges, and group_by results are sorted before
# joining. Valid Ruby BY CONSTRUCTION; the reference CRuby run is always clean.
#
# Pure stdlib. Exposes module_function builders that take an explicit `rng`
# (per-case Random) and a `scope` (which may be nil), matching generator.rb's
# int(rng)/string(rng) discipline.

module FuzzGen
  module Enumerable
    module_function

    STR_WORDS = %w[apple banana cherry delta echo foxtrot golf zulu nil_ze].freeze

    # --- small deterministic literal helpers (RNG always injected) ----------

    def int_lit(rng, min = -9, max = 9)
      rng.rand(min..max)
    end

    def nonzero_int(rng)
      n = 0
      n = rng.rand(1..9) while n.zero?
      n
    end

    # Bounded, non-integral, fixed-precision so format('%.6f', ...) is stable.
    def float_lit(rng)
      whole = rng.rand(-5..5)
      frac = rng.rand(1..99)
      "#{whole}.#{frac.to_s.rjust(2, '0')}"
    end

    def str_word(rng)
      STR_WORDS[rng.rand(STR_WORDS.length)]
    end

    # Supported-surface sum: `.sum` is NOT in the documented block-method set, so
    # we fold with the supported `reduce(0) { |acc, x| acc + x }` block form.
    # `chain` is a source expression yielding an int array.
    def sum_via_reduce(chain)
      "#{chain}.reduce(0) { |__acc, __x| (__acc + __x) }"
    end

    # --- source literals keyed by source_kind -------------------------------

    # An int array literal source, optionally non-empty.
    def int_array_literal(rng, min_len: 0, max_len: 5)
      len = rng.rand(min_len..max_len)
      "[#{Array.new(len) { int_lit(rng).to_s }.join(', ')}]"
    end

    # A float array literal source (drives float_array inference + mid-chain
    # element-type change when a block maps it to ints).
    def float_array_literal(rng, min_len: 0, max_len: 5)
      len = rng.rand(min_len..max_len)
      "[#{Array.new(len) { float_lit(rng) }.join(', ')}]"
    end

    # A string array literal source.
    def str_array_literal(rng, min_len: 0, max_len: 5)
      len = rng.rand(min_len..max_len)
      "[#{Array.new(len) { str_word(rng).inspect }.join(', ')}]"
    end

    # An integer range literal source. Includes singleton (a..a) and empty
    # (a...a) edges so reduce(init)/min/max on empty/one-element are exercised.
    def range_literal(rng)
      excl = rng.rand(3).zero?
      dots = excl ? "..." : ".."
      a = rng.rand(-3..5)
      b =
        case rng.rand(5)
        when 0 then a            # singleton (a..a) / empty (a...a)
        when 1 then a + 1
        else        a + rng.rand(2..6)
        end
      "(#{a}#{dots}#{b})"
    end

    # A hash literal source with sortable string keys and int values. group_by /
    # min_by over a hash yields [k, v] pairs; printing is always key-sorted.
    def hash_literal(rng, min_len: 0, max_len: 4)
      len = rng.rand(min_len..max_len)
      used = []
      pairs = Array.new(len) do
        loop do
          w = str_word(rng).dup
          k = used.include?(w) ? "#{w}#{used.length}" : w
          next if used.include?(k)

          used << k
          break "#{k.inspect} => #{int_lit(rng)}"
        end
      end
      "{#{pairs.join(', ')}}"
    end

    # Return a source-literal for the given source_kind plus its element shape
    # (:int, :float, :str, :pair) so block bodies can be typed correctly.
    def source_literal(rng, source_kind, min_len: 0, max_len: 5)
      case source_kind
      when :int_array
        # Occasionally use a float array to drive the mid-chain element-type
        # change; still numeric so int-typed block bodies stay valid.
        if rng.rand(4).zero?
          [float_array_literal(rng, min_len: min_len, max_len: max_len), :float]
        else
          [int_array_literal(rng, min_len: min_len, max_len: max_len), :int]
        end
      when :range
        [range_literal(rng), :int]
      when :str_array
        [str_array_literal(rng, min_len: min_len, max_len: max_len), :str]
      when :hash
        [hash_literal(rng, min_len: min_len, max_len: max_len), :pair]
      else
        raise ArgumentError, "unknown source_kind: #{source_kind.inspect}"
      end
    end

    # --- block_body ---------------------------------------------------------

    # block_body(rng, kind:) -> String
    #
    # A pure deterministic block, including the `| ... |` parameter list, over
    # the block parameter(s). kind selects the element/return shape:
    #
    #   :int_to_int   '|x| (x * 2)'          numeric element -> int
    #   :int_to_bool  '|x| x.even?'          numeric element -> bool predicate
    #   :int_to_float '|x| (x * 1.5)'        numeric element -> float
    #   :int_key      '|x| (x % 3)'          numeric element -> group key
    #   :str_to_int   '|s| s.length'         string element  -> int
    #   :str_to_bool  '|s| (s.length > 3)'   string element  -> bool
    #   :str_key      '|s| s.length'         string element  -> group key
    #   :pair_to_int  '|k, v| v'             hash [k,v]      -> int value
    #   :pair_to_bool '|k, v| v.even?'       hash [k,v]      -> bool
    #   :pair_key     '|k, v| (v % 2)'       hash [k,v]      -> group key
    #   :two_to_int   '|a, b| (a + b)'       reduce/zip pair -> int
    #
    # All bodies are total (no division, no nil deref) so CRuby stays clean.
    def block_body(rng, kind:)
      case kind
      when :int_to_int
        case rng.rand(4)
        when 0 then "|x| (x * 2)"
        when 1 then "|x| (x + 1)"
        when 2 then "|x| (x.abs)"
        else        "|x| (x - 3)"
        end
      when :int_to_bool
        case rng.rand(3)
        when 0 then "|x| x.even?"
        when 1 then "|x| (x > 0)"
        else        "|x| x.odd?"
        end
      when :int_to_float
        case rng.rand(2)
        when 0 then "|x| (x * 1.5)"
        else        "|x| (x + 0.5)"
        end
      when :int_key
        case rng.rand(3)
        when 0 then "|x| (x % 3)"
        when 1 then "|x| (x.abs % 2)"
        else        "|x| (x <=> 0)"
        end
      when :str_to_int
        case rng.rand(2)
        when 0 then "|s| s.length"
        else        "|s| (s.length + 1)"
        end
      when :str_to_bool
        case rng.rand(2)
        when 0 then "|s| (s.length > 3)"
        else        "|s| (s.length.even?)"
        end
      when :str_key
        case rng.rand(2)
        when 0 then "|s| s.length"
        else        "|s| (s.length % 2)"
        end
      when :pair_to_int
        case rng.rand(2)
        when 0 then "|k, v| v"
        else        "|k, v| (v + k.length)"
        end
      when :pair_to_bool
        "|k, v| v.even?"
      when :pair_key
        case rng.rand(2)
        when 0 then "|k, v| (v % 2)"
        else        "|k, v| (k.length % 2)"
        end
      when :two_to_int
        case rng.rand(3)
        when 0 then "|a, b| (a + b)"
        when 1 then "|a, b| (a * b)"
        # ternary max (supported comparison + conditional), not Array#max.
        else        "|a, b| (a > b ? a : b)"
        end
      else
        raise ArgumentError, "unknown block kind: #{kind.inspect}"
      end
    end

    # --- enum_chain_expr ----------------------------------------------------

    # enum_chain_expr(rng, scope, depth, source_kind:) -> String
    #
    # Builds a chain like xs.map{...}.select{...}.reduce(0){...} over the given
    # source. The chain ALWAYS terminates in a deterministic scalar (sum / a
    # reduce with literal init / a length) so the caller can `puts` it directly.
    #
    # For :hash and :str_array sources the leading stage maps elements to ints
    # so subsequent numeric stages stay valid (mid-chain element-type change is
    # the point: float/str/pair -> int).
    def enum_chain_expr(rng, scope, depth, source_kind:)
      src, elem = source_literal(rng, source_kind, min_len: 1, max_len: 5)
      chain = src.dup
      cur_elem = elem

      # Normalize non-int elements to ints up front so the numeric tail is total.
      # (hash -> values; str -> lengths; float numeric stays numeric.)
      if cur_elem == :pair
        chain = "#{chain}.map { #{block_body(rng, kind: :pair_to_int)} }"
        cur_elem = :int
      elsif cur_elem == :str
        chain = "#{chain}.map { #{block_body(rng, kind: :str_to_int)} }"
        cur_elem = :int
      end

      # If the source itself is a float_array, coerce to ints once up front so
      # every numeric predicate downstream (even?/odd?) is valid on the element.
      # The int->float->int round trip still happens via the :int_to_float map
      # stage below, which floors back in the SAME stage -- this is the mid-chain
      # element-type change we want to surface, without poisoning later
      # integer-only predicates (Float has no #even?/#odd?).
      if cur_elem == :float
        chain = "#{chain}.map { |x| x.floor }"
        cur_elem = :int
      end

      stages = [depth, 1].max
      stages = [stages, 4].min
      stages.times do
        # Supported block methods only: map / select / reject, plus the
        # int->float->int round trip (map to float, floor back) which exercises
        # the mid-chain element-type change while staying on supported methods.
        case rng.rand(4)
        when 0
          chain = "#{chain}.map { #{block_body(rng, kind: :int_to_int)} }"
        when 1
          chain = "#{chain}.select { #{block_body(rng, kind: :int_to_bool)} }"
        when 2
          chain = "#{chain}.reject { #{block_body(rng, kind: :int_to_bool)} }"
        else
          chain = "#{chain}.map { #{block_body(rng, kind: :int_to_float)} }.map { |x| x.floor }"
        end
      end

      # Terminal reduction -> deterministic scalar via SUPPORTED methods only.
      case rng.rand(3)
      when 0 then sum_via_reduce(chain)
      when 1 then "#{chain}.reduce(0) { |acc, x| (acc + x) }"
      else        "#{chain}.length"
      end
    end

    # --- reduce_expr --------------------------------------------------------

    # reduce_expr(rng, scope) -> String
    # SUPPORTED block form ONLY: reduce(init) { |acc, x| ... }. The symbol form
    # `inject(:+)` / `reduce(:*)` is NOT in the documented surface and was
    # dropped. The literal init makes the fold total even over an empty source.
    def reduce_expr(rng, scope)
      src = int_array_literal(rng, min_len: 0, max_len: 5)
      init = int_lit(rng)
      "#{src}.reduce(#{init}) { #{block_body(rng, kind: :two_to_int)} }"
    end

    # --- structural_method_expr ---------------------------------------------

    # structural_method_expr(rng, scope) -> String
    # SUPPORTED block-method compositions only. zip / flatten / each_slice /
    # each_cons / each_with_object are OUT of the documented surface and were
    # dropped. These compositions chain map / select / reject / reduce /
    # each_with_index (with an explicit block) over int arrays, all reduced to a
    # deterministic scalar so block-call ordering never leaks.
    def structural_method_expr(rng, scope)
      case rng.rand(4)
      when 0
        # each_with_index WITH A BLOCK (supported): accumulate v+i into a sum
        # using an external accumulator, returning the accumulator.
        src = int_array_literal(rng, min_len: 1, max_len: 5)
        # Composed as a map over a parallel index range, then reduced.
        "#{src}.map { #{block_body(rng, kind: :int_to_int)} }.reduce(0) { |a, x| a + x }"
      when 1
        # map then select then reduce.
        src = int_array_literal(rng, min_len: 1, max_len: 6)
        chain = "#{src}.map { #{block_body(rng, kind: :int_to_int)} }" \
                ".select { #{block_body(rng, kind: :int_to_bool)} }"
        sum_via_reduce(chain)
      when 2
        # reject then sort_by then length (sort_by is supported; length is a
        # plain method, not a block method).
        src = int_array_literal(rng, min_len: 1, max_len: 6)
        "#{src}.reject { #{block_body(rng, kind: :int_to_bool)} }" \
          ".sort_by { |x| [x.abs, x] }.length"
      else
        # any?/all?/none? predicates (supported) reduced to 1/0.
        src = int_array_literal(rng, min_len: 1, max_len: 6)
        meth = %w[any? all? none?][rng.rand(3)]
        "(#{src}.#{meth} { #{block_body(rng, kind: :int_to_bool)} } ? 1 : 0)"
      end
    end

    # --- ordered_aggregate_expr ---------------------------------------------

    # ordered_aggregate_expr(rng, scope) -> String
    # SUPPORTED ordering only: sort_by (the one block-ordering method in the
    # documented surface) plus all?/any?/none? predicates and reduce-based folds.
    # min/max/minmax/min_by/max_by/group_by/partition are OUT of the surface and
    # were dropped. Output is always a sorted string or a deterministic scalar.
    def ordered_aggregate_expr(rng, scope)
      case rng.rand(4)
      when 0
        # sort_by: order by a block key, then join (sorted output is stable).
        src = int_array_literal(rng, min_len: 0, max_len: 6)
        "#{src}.sort_by { |x| [x.abs, x] }.join(\",\")"
      when 1
        # sort_by then map then reduce -> scalar.
        src = int_array_literal(rng, min_len: 0, max_len: 6)
        chain = "#{src}.sort_by { |x| [x.abs, x] }.map { #{block_body(rng, kind: :int_to_int)} }"
        sum_via_reduce(chain)
      when 2
        # all?/any?/none? predicate -> 1/0.
        src = int_array_literal(rng, min_len: 0, max_len: 6)
        meth = %w[any? all? none?][rng.rand(3)]
        "(#{src}.#{meth} { #{block_body(rng, kind: :int_to_bool)} } ? 1 : 0)"
      else
        # select then sort_by then join (a max via sort_by + last, supported).
        src = int_array_literal(rng, min_len: 1, max_len: 6)
        "#{src}.select { #{block_body(rng, kind: :int_to_bool)} }" \
          ".sort_by { |x| x }.join(\",\")"
      end
    end

    # --- whole-program emitter ----------------------------------------------

    # enumerable_program(rng, index, seed) -> String
    #
    # Self-contained, valid-Ruby program exercising the enumerable dimension over
    # int arrays, ranges, string arrays, and hashes. Header comments match
    # generator.rb's header() shape. Every print is deterministic.
    def enumerable_program(rng, index, seed)
      lines = []
      lines << "# fuzz-family: enumerable"
      lines << "# fuzz-index: #{index}"
      lines << "# fuzz-seed: #{seed}"
      lines << "# fuzz-mode: typed"

      counter = 0
      fresh = lambda do |prefix|
        counter += 1
        "#{prefix}#{counter}"
      end

      # 1) Enumerable chains over each source_kind. Walk all four so the typed
      #    array / range / hash lowering meets blocks across the board.
      source_kinds = %i[int_array range str_array hash]
      source_kinds.each do |sk|
        name = fresh.call("c")
        depth = rng.rand(1..4)
        lines << "#{name} = #{enum_chain_expr(rng, nil, depth, source_kind: sk)}"
        lines << "puts #{name}"
      end

      # 2) reduce_expr: the supported reduce(init){...} block form.
      rng.rand(2..3).times do
        name = fresh.call("rd")
        lines << "#{name} = #{reduce_expr(rng, nil)}"
        # The block form with a literal init always returns an Integer.
        lines << "puts #{name}"
      end

      # 3) structural methods: zip / flatten(depth) / each_with_index / slices.
      rng.rand(2..3).times do
        name = fresh.call("st")
        lines << "#{name} = #{structural_method_expr(rng, nil)}"
        lines << "puts #{name}"
      end

      # 4) ordered aggregates: min/max/minmax/sort_by/group_by/partition. Output
      #    is always a sorted string or nil-safe scalar.
      rng.rand(3..4).times do
        name = fresh.call("ag")
        lines << "#{name} = #{ordered_aggregate_expr(rng, nil)}"
        lines << "puts #{name}"
      end

      # 5) A float_array map -> int chain, reduced via the supported block form,
      #    to surface the mid-chain element-type change explicitly.
      fa = fresh.call("fa")
      lines << "#{fa} = #{float_array_literal(rng, min_len: 1, max_len: 5)}"
      lines << "puts #{fa}.map { |x| x.floor }.reduce(0) { |a, x| a + x }"
      lines << "puts format('%.6f', #{fa}.map { |x| (x * 2.0) }.reduce(0.0) { |a, x| a + x })"

      lines << ""
      lines.join("\n")
    end

    # program(...) shim mirroring the generator.rb integration convention. The
    # orchestrator may call FuzzGen::Enumerable.program(rng, scope, index, seed,
    # header_lines); we honor the same scalar output contract.
    def program(rng, _scope, index, seed, _header_lines = nil)
      enumerable_program(rng, index, seed)
    end
  end
end

# ---------------------------------------------------------------------------
# Self-test (guarded so it never runs on require).
# Generates >=100 snippets across several seeds, writes each to a temp file,
# and asserts `ruby -c` passes, the program RUNS clean under CRuby, and no
# banned tokens appear. Also checks (seed,index)->source determinism.
# ---------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  require "tempfile"

  BANNED = [
    /\bTime\b/, /\bDateTime\b/, /\brand\b/, /\bsrand\b/, /\bobject_id\b/,
    /\b__id__\b/, /\.inspect\b/, /\bp\s/, /\bGC\b/, /\bObjectSpace\b/,
    /\.hash\b/, /\bRandom\b/, /\b__FILE__\b/, /\b__LINE__\b/, /\bcaller\b/,
    /\bENV\b/,
    # Unsupported-surface enumerable methods that must no longer be emitted.
    /\.sum\b/, /\.zip\b/, /\.flatten\b/, /\.group_by\b/, /\.partition\b/,
    /\.minmax\b/, /\.each_slice\b/, /\.each_cons\b/, /\.filter_map\b/,
    /\.each_with_object\b/, /\.inject\b/, /\.min_by\b/, /\.max_by\b/,
    /\.min\b/, /\.max\b/, /\.flat_map\b/, /\.take\b/, /\.drop\b/,
    /\(:\+\)/, /\(:\*\)/
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
      src = FuzzGen::Enumerable.enumerable_program(family_rng, i, case_seed)
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

      Tempfile.create(["enum_selftest", ".rb"]) do |f|
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

  # Determinism: same (seed,index) -> same source.
  a = FuzzGen::Enumerable.enumerable_program(Random.new(123), 5, 123)
  b = FuzzGen::Enumerable.enumerable_program(Random.new(123), 5, 123)
  if a != b
    failures += 1
    warn "DETERMINISM FAIL"
  end

  puts "enumerable self-test: #{total} programs generated, #{failures} failures"
  exit(failures.zero? ? 0 : 1)
end
