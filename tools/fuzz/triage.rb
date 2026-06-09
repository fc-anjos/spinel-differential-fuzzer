#!/usr/bin/env ruby
# frozen_string_literal: true

# Triage: failure signature/dedup + delta-debugging shrinker + reproducibility
# manifest + regression-corpus writer for the hardened Spinel fuzzer.
#
# Pure stdlib only (digest, json, fileutils). NO require_relative of other fuzz
# modules: the shrinker's reproduce? predicate is INJECTED as a lambda, so this
# module stays free of any dependency cycle with oracle.rb / runner.rb.

require "digest"
require "json"
require "fileutils"

module Triage
  module_function

  # ----------------------------------------------------------------------------
  # (a) Signatures / dedup
  # ----------------------------------------------------------------------------

  # Stable 12-hex id for dedup. Normalizes any provided inputs (so two failures
  # that differ only by address/pid/path/line:col collapse to one signature),
  # then hashes the concatenation. At least one of stderr/stack/source should be
  # given; if all are nil it still produces a deterministic (empty-input) id.
  def signature(stderr: nil, stack: nil, source: nil)
    parts = []
    parts << "stderr:#{normalize_stderr(stderr)}" unless stderr.nil?
    parts << "stack:#{normalize_stack(stack)}" unless stack.nil?
    parts << "source:#{normalize_source(source)}" unless source.nil?
    payload = parts.join("\n\x00\n")
    Digest::SHA256.hexdigest(payload)[0, 12]
  end

  # Strip volatile tokens out of stderr so signatures are stable across runs:
  #   - hex addresses        0xdeadbeef
  #   - asan/ubsan pid tags  ==12345==
  #   - tmp/scratch paths    /tmp/..., /var/folders/..., TMPDIR style dirs
  #   - source line:col      foo.rb:12:5  / foo.c:88
  #   - thread/frame ids and timing-ish numbers in sanitizer "#N 0x.. in" frames
  def normalize_stderr(text)
    s = (text || "").dup
    s = s.gsub(/\r\n?/, "\n")
    # Address space -> placeholder.
    s = s.gsub(/0x[0-9a-fA-F]+/, "0xADDR")
    # ==<pid>== sanitizer tags.
    s = s.gsub(/==\d+==/, "==PID==")
    # PID in other common forms: "pid=1234", "(1234)".
    s = s.gsub(/\bpid[=: ]\d+/i, "pid=PID")
    # Shell job-control crash lines leak a bare PID, e.g.
    #   "/bin/sh: line 487: 31161 Segmentation fault: 11  ..."
    # Without this, every crash of the same bug hashes to a DIFFERENT signature
    # (the PID varies per run) and dedup fails for the whole crash class.
    s = s.gsub(/\b\d+\s+(Segmentation fault|Bus error|Abort(?:ed)?|Killed|Trace\/BPT trap|Illegal instruction|Floating point exception)/i, 'PID \1')
    # tmp/scratch directories (macOS /var/folders + /tmp + generic mktmpdir).
    s = s.gsub(%r{/private/var/folders/[^\s:]+}, "TMPPATH")
    s = s.gsub(%r{/var/folders/[^\s:]+}, "TMPPATH")
    s = s.gsub(%r{/tmp/[^\s:]+}, "TMPPATH")
    s = s.gsub(%r{\b[^\s:]*/T/[^\s:]+}, "TMPPATH")
    # Any remaining absolute path component basenames keep, but strip dir prefix
    # for case/scratch artifacts (case-XXXXXX dirs, .asan/.c temp files).
    s = s.gsub(%r{[^\s:]*/(case[-\w]*\.\w+)}, '\1')
    s = s.gsub(%r{[^\s:]*/(spinel-fuzz-?\w*)}, '\1')
    # file:line:col -> file:L:C  (handles .rb/.c/.h with one or two numbers).
    s = s.gsub(/([\w.\-\/]+\.(?:rb|c|h|cpp|cc)):\d+(?::\d+)?/, '\1:L')
    # A TMPPATH placeholder may have absorbed the file path; strip a trailing
    # :line[:col] left dangling after the path token so line numbers don't leak
    # into the signature.
    s = s.gsub(/TMPPATH:\d+(?::\d+)?/, "TMPPATH:L")
    # Frame indices "#3 0xADDR in" -> "#N 0xADDR in".
    s = s.gsub(/#\d+\s+0xADDR/, "#N 0xADDR")
    # Collapse trailing whitespace + blank lines for stable hashing.
    s = s.split("\n").map { |line| line.rstrip }.join("\n")
    s.strip
  end

  # Normalize a sanitizer stack (array of frame strings or a newline blob).
  # Keeps only the symbolized function names + module, drops offsets/addresses.
  def normalize_stack(stack)
    frames =
      case stack
      when Array then stack
      when nil then []
      else stack.to_s.split("\n")
      end
    frames.map do |frame|
      f = frame.to_s
      f = f.gsub(/0x[0-9a-fA-F]+/, "0xADDR")
      f = f.gsub(/#\d+/, "#N")
      f = f.gsub(/\(\+0xADDR\)/, "")
      # Drop the trailing "file:line:col" location if present.
      f = f.gsub(/\s+[\w.\-\/]+:\d+(?::\d+)?$/, "")
      f.strip
    end.reject(&:empty?).join("\n")
  end

  # Normalize source for signature purposes: drop fuzz header comments and
  # blank-line noise, collapse runs of whitespace, so the minimized program
  # yields a stable id regardless of incidental formatting.
  def normalize_source(source)
    (source || "").split("\n")
      .reject { |line| line.strip.start_with?("# fuzz-") }
      .map { |line| line.rstrip }
      .reject(&:empty?)
      .join("\n")
      .strip
  end

  # ----------------------------------------------------------------------------
  # (b) Delta-debugging shrinker
  # ----------------------------------------------------------------------------

  # Shrinks a source program down to a minimal form that still satisfies an
  # injected predicate `reproduce.call(candidate) -> Boolean`. Deterministic and
  # idempotent. Strategy, applied repeatedly until a fixpoint (or max_passes):
  #   1. ddmin over top-level statements (respecting begin/def/if/do..end blocks)
  #   2. integer-literal shrinking toward 0
  #   3. nesting collapse (replace a block body with a representative line)
  class Shrinker
    def initialize(reproduce:, max_passes: 10)
      raise ArgumentError, "reproduce: must respond to call" unless reproduce.respond_to?(:call)

      @reproduce = reproduce
      @max_passes = max_passes
      @passes = 0
      @candidates_tried = 0
      @original_bytes = 0
      @final_bytes = 0
    end

    def stats
      {
        passes: @passes,
        candidates_tried: @candidates_tried,
        original_bytes: @original_bytes,
        final_bytes: @final_bytes
      }
    end

    def shrink(source)
      @original_bytes = source.bytesize
      current = source

      unless reproduces?(current)
        # Predicate does not hold for the input as given; nothing to shrink.
        @final_bytes = current.bytesize
        return current
      end

      @passes = 0
      loop do
        break if @passes >= @max_passes

        before = current
        current = ddmin_lines(current)
        current = shrink_int_literals(current)
        current = collapse_blocks(current)
        @passes += 1
        break if current == before
      end

      @final_bytes = current.bytesize
      current
    end

    private

    def reproduces?(candidate)
      @candidates_tried += 1
      !!@reproduce.call(candidate)
    end

    # ddmin over top-level units. Units are grouped so that multi-line blocks
    # (def..end, if..end, do..end, begin..end, {..}) stay together — removing a
    # block header without its end would always break parsing and never
    # reproduce, so we keep balanced groups atomic.
    def ddmin_lines(source)
      units = top_level_units(source)
      return source if units.length <= 1

      n = 2
      while units.length >= 2
        chunk_len = (units.length.to_f / n).ceil
        chunks = units.each_slice(chunk_len).to_a
        reduced = false

        # Try removing each complement (ddmin "increase granularity" step).
        chunks.each_with_index do |_chunk, i|
          complement = chunks.each_with_index.reject { |_, j| j == i }.map(&:first).flatten
          next if complement.empty?

          candidate = join_units(complement)
          if reproduces?(candidate)
            units = complement
            n = [n - 1, 2].max
            reduced = true
            break
          end
        end

        next if reduced

        # Also try removing each single chunk directly (subset removal).
        if n < units.length
          removed_any = false
          chunks.each do |chunk|
            remaining = units - chunk
            next if remaining.empty?

            candidate = join_units(remaining)
            if reproduces?(candidate)
              units = remaining
              removed_any = true
              break
            end
          end
          next if removed_any
        end

        break if n >= units.length

        n = [n * 2, units.length].min
      end

      join_units(units)
    end

    # Greedy single-unit removal as a final tightening pass embedded in ddmin's
    # join. Splits source into atomic top-level units.
    def top_level_units(source)
      lines = source.split("\n", -1)
      units = []
      buffer = []
      depth = 0

      lines.each do |line|
        buffer << line
        depth += block_delta(line)
        if depth <= 0
          units << buffer.join("\n")
          buffer = []
          depth = 0
        end
      end
      units << buffer.join("\n") unless buffer.empty?
      # Drop empty units (blank-line-only) but keep at least structure.
      units.reject { |u| u.strip.empty? }
    end

    def join_units(units)
      units.join("\n")
    end

    # Net change in block nesting contributed by a single physical line.
    # Counts opening keywords/tokens minus closing `end`/`}`. Heuristic but
    # safe: an unbalanced candidate simply fails to reproduce and is discarded.
    def block_delta(line)
      stripped = line.strip
      return 0 if stripped.empty?
      return 0 if stripped.start_with?("#")

      delta = 0
      # Openers: def/if/unless/while/until/case/begin/class/module at start,
      # and trailing `do`. Exclude modifier forms (e.g. `x if y`) by requiring
      # the keyword to start the statement.
      if stripped =~ /\A(def|class|module|begin|case)\b/
        delta += 1
      elsif stripped =~ /\A(if|unless|while|until|for)\b/ &&
            stripped !~ /\bthen\b.+\bend\z/
        delta += 1
      end
      # `do` block opener (e.g. `xs.each do |x|`).
      delta += 1 if stripped =~ /\bdo\b(\s*\|[^|]*\|)?\s*\z/
      # Closers.
      delta -= 1 if stripped =~ /\Aend\b/ || stripped == "end"
      # Inline brace blocks net to zero; ignore.
      delta
    end

    # Shrink integer literals toward 0, one literal at a time, keeping only the
    # changes that preserve reproduction. Skips numbers that are part of an
    # identifier or a fuzz header.
    def shrink_int_literals(source)
      current = source
      # Iterate until no literal can be reduced further (bounded).
      improved = true
      guard = 0
      while improved && guard < 64
        improved = false
        guard += 1
        positions = int_literal_positions(current)
        positions.each do |start, len, value|
          next if value == 0

          [0, value / 2, value > 0 ? value - 1 : value + 1].uniq.each do |target|
            next if target == value

            candidate = current.dup
            candidate[start, len] = target.to_s
            if reproduces?(candidate)
              current = candidate
              improved = true
              break
            end
          end
          break if improved
        end
      end
      current
    end

    # Find integer literals not preceded/followed by identifier chars.
    def int_literal_positions(source)
      positions = []
      source.each_line.reduce(0) do |offset, line|
        unless line.strip.start_with?("#")
          line.to_enum(:scan, /-?\d+/).each do
            m = Regexp.last_match
            ms = m.begin(0)
            me = m.end(0)
            before = ms.positive? ? line[ms - 1] : nil
            after = line[me]
            # Skip if glued to an identifier (e.g. var2, 0x..).
            next if before && before =~ /[A-Za-z_]/
            next if after && after =~ /[A-Za-z_]/
            positions << [offset + ms, me - ms, line[ms...me].to_i]
          end
        end
        offset + line.length
      end
      # Reverse so edits don't shift earlier offsets within a single pass.
      positions.sort_by { |start, _, _| -start }
    end

    # Collapse a block body to a minimal representative if the block can be
    # emptied while still reproducing (e.g. drop the loop body but keep the
    # header+end for structural validity). Conservative: tries removing interior
    # lines of each balanced block one unit at a time via the unit splitter.
    def collapse_blocks(source)
      units = top_level_units(source)
      changed = false
      units = units.map do |unit|
        next unit unless unit.include?("\n")

        inner = unit.split("\n")
        next unit if inner.length <= 2

        header = inner.first
        footer = inner.last
        # Only collapse if footer is a clean `end` (or `}`); otherwise leave.
        next unit unless footer.strip == "end" || footer.strip == "}"

        candidate_unit = "#{header}\n#{footer}"
        candidate = join_units(units.map { |u| u.equal?(unit) ? candidate_unit : u })
        if reproduces?(candidate)
          changed = true
          candidate_unit
        else
          unit
        end
      end
      changed ? join_units(units) : source
    end
  end

  # ----------------------------------------------------------------------------
  # (c) Reproducibility manifest
  # ----------------------------------------------------------------------------

  # Build a manifest Hash capturing everything needed to reproduce a fuzz run.
  def manifest(spinel:, spinel_dir:, cc:, ref_ruby:, seed:, opt_level:,
               int_overflow:, timeout:, jobs:, sanitize:)
    {
      "spinel" => spinel.to_s,
      "spinel_dir" => spinel_dir.to_s,
      "spinel_sha" => spinel_sha(spinel_dir),
      "cc" => cc.to_s,
      "cc_version" => cc_version(cc),
      "ruby" => RUBY_DESCRIPTION,
      "ref_ruby" => ref_ruby,
      "seed" => seed,
      "opt_level" => opt_level,
      "int_overflow" => int_overflow.to_s,
      "timeout" => timeout,
      "jobs" => jobs,
      "sanitize" => !!sanitize,
      "platform" => RUBY_PLATFORM
    }
  end

  def write_manifest(path, manifest_hash)
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, "#{JSON.pretty_generate(manifest_hash)}\n")
    nil
  end

  # spinel git SHA from the directory containing the `spinel` script.
  def spinel_sha(spinel_dir)
    out = `git -C #{shell_quote(spinel_dir.to_s)} rev-parse HEAD 2>/dev/null`.strip
    out.empty? ? "unknown" : out
  rescue StandardError
    "unknown"
  end

  # First line of `<cc> --version`.
  def cc_version(cc)
    out = `#{cc} --version 2>/dev/null`
    line = out.to_s.lines.first
    line ? line.strip : "unknown"
  rescue StandardError
    "unknown"
  end

  # ----------------------------------------------------------------------------
  # (d) Regression-corpus writer
  # ----------------------------------------------------------------------------

  # Write a minimized repro under <dir>/<signature>.rb plus a sidecar
  # <signature>.json holding the manifest + expected reference stdout. Returns
  # the written .rb path.
  def save_regression(source:, signature:, expected_stdout:, manifest:, dir: "test/fuzz-regressions")
    FileUtils.mkdir_p(dir)
    rb_path = File.join(dir, "#{signature}.rb")
    json_path = File.join(dir, "#{signature}.json")

    File.write(rb_path, ensure_trailing_newline(source))
    sidecar = {
      "signature" => signature,
      "manifest" => manifest,
      "expected_stdout" => expected_stdout
    }
    File.write(json_path, "#{JSON.pretty_generate(sidecar)}\n")
    rb_path
  end

  # ----------------------------------------------------------------------------
  # helpers
  # ----------------------------------------------------------------------------

  def shell_quote(str)
    "'#{str.gsub("'", "'\\\\''")}'"
  end

  def ensure_trailing_newline(text)
    text.end_with?("\n") ? text : "#{text}\n"
  end
end

# ------------------------------------------------------------------------------
# Self-test (guarded so it never runs on require)
# ------------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  require "tmpdir"

  failures = []
  assert = lambda do |label, cond|
    if cond
      puts "  ok  #{label}"
    else
      failures << label
      puts "FAIL  #{label}"
    end
  end

  # --- (a) signature stability ---------------------------------------------
  raw1 = <<~ERR
    ==12345==ERROR: AddressSanitizer: stack-overflow on address 0x7ffeefbff8a0
        #0 0x10ab23f4c in spinel_fuzz_calc /tmp/case-000042-scalar/case.c:88:5
        #1 0x10ab24010 in main /private/var/folders/xy/abc123/T/spinel-fuzz/case.c:12
    SUMMARY: AddressSanitizer: stack-overflow /tmp/case-000042-scalar/case.c:88:5
  ERR
  raw2 = <<~ERR
    ==99999==ERROR: AddressSanitizer: stack-overflow on address 0xdeadbeef0000
        #0 0x55deadbeef in spinel_fuzz_calc /tmp/case-777777-array/case.c:88:9
        #1 0x55deadc000 in main /var/folders/zz/zzz/T/spinel-fuzz/case.c:12
    SUMMARY: AddressSanitizer: stack-overflow /tmp/case-777777-array/case.c:88:1
  ERR
  sig1 = Triage.signature(stderr: raw1)
  sig2 = Triage.signature(stderr: raw2)
  assert.call("signature is 12 hex chars", sig1 =~ /\A[0-9a-f]{12}\z/)
  assert.call("signature stable across address/pid/path/line:col noise", sig1 == sig2)
  assert.call("different errors -> different signature",
              Triage.signature(stderr: "totally different error") != sig1)
  assert.call("signature deterministic on repeat", Triage.signature(stderr: raw1) == sig1)
  assert.call("source signature stable ignoring fuzz headers",
              Triage.signature(source: "# fuzz-seed: 1\nputs 1/0\n") ==
              Triage.signature(source: "# fuzz-seed: 999\nputs 1/0"))

  # --- (b) shrinker: reduce multi-statement program against a synthetic
  #         predicate ("still contains a division") down to minimal ------------
  program = <<~RUBY
    # fuzz-family: scalar
    # fuzz-seed: 4242
    a = 7
    b = 3
    c = 5
    d = 9
    puts a + b
    puts a - b
    puts a * c
    puts (a + b) / c
    puts (a + b) % c
    if a < b
      x = a + c
    else
      x = b - c
    end
    puts x
  RUBY

  # Predicate: candidate must still parse as Ruby AND contain a `/` division.
  predicate = lambda do |candidate|
    return false unless candidate.include?("/")

    # Reject candidates that don't parse (mirrors a real "still compiles" check).
    ok = system("ruby", "-c", "-e", candidate, out: File::NULL, err: File::NULL)
    !!ok
  end

  shrinker = Triage::Shrinker.new(reproduce: predicate, max_passes: 10)
  minimized = shrinker.shrink(program)

  assert.call("shrink: result still contains division", minimized.include?("/"))
  assert.call("shrink: result still parses", system("ruby", "-c", "-e", minimized, out: File::NULL, err: File::NULL))
  assert.call("shrink: strictly smaller than original", minimized.bytesize < program.bytesize)
  # Minimal: the only line that the predicate strictly needs is the division
  # line; the `%` line, the if/else, the unrelated puts should be gone.
  assert.call("shrink: dropped the modulo line", !minimized.include?("%"))
  assert.call("shrink: dropped the if/else block", !minimized.include?("else"))
  stats = shrinker.stats
  assert.call("shrink: stats report original/final bytes",
              stats[:original_bytes] == program.bytesize && stats[:final_bytes] == minimized.bytesize)
  assert.call("shrink: stats counted candidates", stats[:candidates_tried] > 0)

  # Idempotence: shrinking the minimized output again yields the same thing.
  shrinker2 = Triage::Shrinker.new(reproduce: predicate)
  minimized2 = shrinker2.shrink(minimized)
  assert.call("shrink: idempotent", minimized2 == minimized)

  # Predicate that never holds -> returns input unchanged.
  noop_shrinker = Triage::Shrinker.new(reproduce: ->(_c) { false })
  assert.call("shrink: non-reproducing input returned unchanged",
              noop_shrinker.shrink(program) == program)

  puts "  (minimized program)"
  minimized.each_line { |l| puts "    | #{l.chomp}" }

  # --- (c) manifest captures spinel SHA / cc / ruby versions ----------------
  spinel_dir = File.expand_path("../..", __dir__) # .vendor/spinel
  man = Triage.manifest(
    spinel: File.join(spinel_dir, "spinel"),
    spinel_dir: spinel_dir,
    cc: "cc",
    ref_ruby: ["ruby"],
    seed: 4242,
    opt_level: 0,
    int_overflow: "raise",
    timeout: 10,
    jobs: 4,
    sanitize: true
  )
  assert.call("manifest captures spinel SHA (40-hex or 'unknown')",
              man["spinel_sha"] =~ /\A([0-9a-f]{40}|unknown)\z/)
  assert.call("manifest spinel SHA resolved (not unknown) in repo",
              man["spinel_sha"] != "unknown")
  assert.call("manifest captures cc version", man["cc_version"] && man["cc_version"] != "")
  # Accept any real compiler first-line banner across platforms: Apple/Linux
  # clang ("... clang version 15.0.0"), but also GCC invoked as `cc` on Ubuntu
  # CI, whose first line is "cc (Ubuntu 13.2.0-...) 13.2.0" -- no clang/gcc/version
  # word, just a dotted version number. Match a version number as the fallback.
  assert.call("manifest cc version looks like a compiler banner",
              man["cc_version"] =~ /clang|gcc|version|\d+\.\d+/i)
  assert.call("manifest captures ruby description", man["ruby"] == RUBY_DESCRIPTION)
  assert.call("manifest captures platform", man["platform"] == RUBY_PLATFORM)
  assert.call("manifest records sanitize flag", man["sanitize"] == true)
  assert.call("manifest records int_overflow", man["int_overflow"] == "raise")

  # write_manifest round-trips to disk as valid JSON.
  Dir.mktmpdir("triage-selftest") do |tmp|
    run_json = File.join(tmp, "run.json")
    Triage.write_manifest(run_json, man)
    reread = JSON.parse(File.read(run_json))
    assert.call("write_manifest produced valid JSON", reread["spinel_sha"] == man["spinel_sha"])

    # --- (d) save_regression --------------------------------------------------
    sig = Triage.signature(source: minimized)
    reg_dir = File.join(tmp, "fuzz-regressions")
    rb_path = Triage.save_regression(
      source: minimized,
      signature: sig,
      expected_stdout: "1\n",
      manifest: man,
      dir: reg_dir
    )
    assert.call("save_regression wrote .rb at <signature>.rb",
                File.basename(rb_path) == "#{sig}.rb" && File.exist?(rb_path))
    assert.call("save_regression .rb ends with newline", File.read(rb_path).end_with?("\n"))
    json_sidecar = File.join(reg_dir, "#{sig}.json")
    assert.call("save_regression wrote sidecar .json", File.exist?(json_sidecar))
    sidecar = JSON.parse(File.read(json_sidecar))
    assert.call("sidecar holds manifest", sidecar["manifest"]["spinel_sha"] == man["spinel_sha"])
    assert.call("sidecar holds expected_stdout", sidecar["expected_stdout"] == "1\n")
  end

  puts
  if failures.empty?
    puts "ALL SELF-TESTS PASSED"
    exit 0
  else
    puts "SELF-TEST FAILURES (#{failures.length}):"
    failures.each { |f| puts "  - #{f}" }
    exit 1
  end
end
