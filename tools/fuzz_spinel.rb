#!/usr/bin/env ruby
# frozen_string_literal: true

# Thin orchestrator for the hardened Spinel differential + sanitizer fuzzer.
#
# Wires four decoupled modules (acyclic DAG: runner <- oracle; generator and
# triage standalone; this orchestrator depends on all four):
#
#   tools/fuzz/generator.rb  -- type-directed program generation (valid by construction)
#   tools/fuzz/runner.rb     -- hardened subprocess execution + parallel sharding
#   tools/fuzz/oracle.rb     -- differential + ASan/UBSan sanitizer oracle
#   tools/fuzz/triage.rb     -- signature/dedup + delta-debug shrinker + manifest
#
# Legacy class names are preserved (ProgramGenerator delegates to Generator,
# Fuzzer drives the loop) so `make fuzz-smoke` and the README invocation keep
# working. The shrinker stays decoupled: its reproduce? predicate is INJECTED
# from here (it re-runs the oracle on the candidate source).
#
# Pure stdlib only.

require "fileutils"
require "json"
require "optparse"
require "rbconfig"
require "set"
require "shellwords"

require_relative "fuzz/runner"     # defines RunResult, Runner
require_relative "fuzz/generator"  # defines GeneratedCase, Generator
require_relative "fuzz/oracle"     # defines Verdict, Oracle (require_relative 'runner')
require_relative "fuzz/triage"     # defines Triage

ROOT = File.expand_path("..", __dir__)

# Spinel lives as a git submodule at vendor/spinel. Its compiled toolchain
# (the `spinel` driver plus spinel_parse / spinel_analyze.rb / spinel_codegen.rb)
# is rooted there, while the fuzzer's own scratch output stays under ROOT/tmp.
# `--spinel` and `--root` still override these defaults for out-of-tree checkouts.
SPINEL_ROOT = File.expand_path(ENV.fetch("SPINEL_ROOT", File.join(ROOT, "vendor", "spinel")))

def ruby_supports_generator_syntax?(cmd)
  argv = Shellwords.split(cmd)
  probe = "RubyVM::AbstractSyntaxTree.parse(\"case 1\\nin 1\\n  1\\nend\\n\"); " \
          "RubyVM::AbstractSyntaxTree.parse(\"def __spinel_fuzz_probe__(a) = a\\n\")"
  system(*(argv + ["-e", probe]), out: File::NULL, err: File::NULL)
rescue StandardError
  false
end

def default_ref_ruby
  return ENV.fetch("REF_RUBY") if ENV.key?("REF_RUBY")
  return "ruby -EUTF-8" if ruby_supports_generator_syntax?("ruby")

  if system("command -v mise >/dev/null 2>&1") &&
     ruby_supports_generator_syntax?("mise exec ruby -- ruby")
    return "mise exec ruby -- ruby -EUTF-8"
  end

  "ruby"
end

# Back-compat shim: legacy name ProgramGenerator delegates to Generator so any
# external caller / doc invocation that referenced ProgramGenerator keeps
# working. Generator.new validates families/exclude against KNOWN_FAMILIES.
class ProgramGenerator
  def initialize(seed, families: nil, exclude_families: [], mode: :typed, max_depth: 4)
    @generator = Generator.new(
      seed,
      families: families,
      exclude_families: exclude_families,
      mode: mode,
      max_depth: max_depth
    )
  end

  def generate(index)
    @generator.generate(index)
  end

  def families
    @generator.families
  end
end

class Fuzzer
  PROGRESS_EVERY = 25 # cases between progress.json checkpoints (for --continue)

  def initialize(options)
    @options = options
    @root = options.fetch(:root)
    @spinel = File.expand_path(options.fetch(:spinel), @root)
    # Spinel engine revision this run executes against, captured once in
    # spinelgems' rev format (git:<sha>[+dirty]/<arch-os>) so persisted findings
    # are keyed to the exact engine. Pure git-metadata read of @root (no Spinel
    # build needed); nil for a non-git out-of-tree checkout.
    @spinel_rev = self.class.spinel_rev(@root)
    @ref_ruby = Shellwords.split(options.fetch(:ref_ruby))
    @seed = options.fetch(:seed)
    @mode = options.fetch(:typed) ? :typed : :templates

    @generator = ProgramGenerator.new(
      @seed,
      families: options.fetch(:families),
      exclude_families: options.fetch(:exclude_families),
      mode: @mode
    )

    timeout = options.fetch(:timeout)
    # RLIMIT_CPU is a backstop against runaway CPU spinners that starve the
    # wall-clock watchdog; the wall timeout (group kill) is the primary bound.
    # A spinel -E run legitimately burns CPU (compile + link + execute), and
    # under heavy --jobs parallelism the per-process CPU time of one honest
    # compile can approach the wall window, so keep the CPU budget generously
    # above it to avoid false-killing the linker.
    @runner = Runner.new(
      timeout: timeout,
      cpu_seconds: [timeout * 4, timeout + 30].max,
      fsize_bytes: Runner::DEFAULT_FSIZE_BYTES
    )

    @sanitize = !options.fetch(:no_sanitize)
    @oracle = Oracle.new(
      spinel: @spinel,
      ref_ruby: @ref_ruby,
      runner: @runner,
      spinel_dir: @root,
      opt_level: options.fetch(:opt_level),
      int_overflow: options.fetch(:int_overflow),
      sanitize: @sanitize,
      sanitizer_cc: options.fetch(:sanitizer_cc),
      overflow_ubsan_lane: options.fetch(:overflow_ubsan),
      supported_only: options.fetch(:supported_only)
    )

    @run_dir = File.expand_path("seed-#{@seed}", options.fetch(:out))
    @jobs = options.fetch(:jobs)
    @continue = options.fetch(:continue)

    @signatures = {} # signature => first case_dir (dedup)
    @failures = []   # one entry per UNIQUE signature
    @pending_regressions = [] # {payload:, signature:} per unique failure, shrunk+saved post-loop
    @skips = 0
    @passes = 0
    @dup_failures = 0
    # Per-class counts of divergences DISCARDED by --supported-only, so the gap
    # filter never loses anything: a divergence that was downgraded to a
    # :skip is tallied here by its gap_class (:degradation_gap / :intentional_incompat).
    @filtered_gaps = Hash.new(0)
  end

  def run
    FileUtils.mkdir_p(@run_dir)
    write_manifest

    start_index, prior = resume_state
    total = @options.fetch(:cases)
    indices = (start_index...total).to_a

    if @jobs > 1
      run_parallel(indices)
    else
      run_sequential(indices)
    end

    shrink_and_save_regressions
    finalize(prior)
  end

  private

  # ---- driving the loop ------------------------------------------------------

  # Parallel path: each worker re-derives its case DETERMINISTICALLY via
  # Generator.replay(seed, index, ...) so sharding stays reproducible and
  # seed-stable, then runs the oracle. Workers return a Marshal-able payload;
  # the parent owns dedup/shrink/artifacts (single-writer, no IPC races).
  def run_parallel(indices)
    seed = @seed
    mode = @mode
    families = @options.fetch(:families)
    exclude = @options.fetch(:exclude_families)
    oracle = @oracle

    # Stream each shard result into ingest as it arrives (completion order), so
    # dedup/shrink/save and progress advance during the run instead of waiting
    # for every worker to finish. The parent runs ingest single-threaded.
    @runner.parallel_map(indices, jobs: @jobs, on_result: ->(payload) { ingest(payload) }) do |index|
      generated = Generator.replay(
        seed, index,
        families: families, exclude_families: exclude, mode: mode
      )
      worker_evaluate(oracle, generated, index)
    end
  end

  def run_sequential(indices)
    indices.each do |index|
      generated = @generator.generate(index)
      payload = worker_evaluate(@oracle, generated, index)
      ingest(payload)
      checkpoint(index) if !@options.fetch(:no_progress) && ((index + 1) % PROGRESS_EVERY).zero?
      # --stop-after bounds the sequential loop (legacy behavior); --continue
      # disables the bound so a long hunt collects many unique failures.
      break if @stop_hit && !@continue
    end
  end

  # Runs the oracle for one case and returns a plain, Marshal-able Hash payload
  # (so the fork pool can ship it back). The verdict's RunResults are reduced to
  # the fields we persist; the source travels with the payload for artifact
  # writing + shrinking in the parent.
  def worker_evaluate(oracle, generated, index)
    case_dir = case_dir_for(generated)
    source_path = File.join(case_dir, "case.rb")
    FileUtils.mkdir_p(case_dir)
    File.write(source_path, generated.source)

    verdict = oracle.check(source_path)

    {
      index: index,
      family: generated.family,
      seed: generated.seed,
      source: generated.source,
      case_dir: case_dir,
      source_path: source_path,
      status: verdict.status,
      reason: verdict.reason,
      gap_class: verdict.gap_class,
      reference: runresult_h(verdict.reference),
      spinel: runresult_h(verdict.spinel),
      sanitizer: runresult_h(verdict.sanitizer)
    }
  end

  # Parent-side: account a worker payload (pass/skip/fail), dedup, shrink, save.
  def ingest(payload)
    case payload[:status]
    when :pass
      @passes += 1
      FileUtils.rm_rf(payload[:case_dir]) unless @options.fetch(:keep_passing)
      print_progress(".")
    when :skip
      @skips += 1
      # A gap-filtered divergence (degradation-gap / intentional-incompat) comes
      # back as a :skip carrying its gap_class. Tally it separately so the filter
      # is auditable (counts reported in finalize) and mark its progress glyph 'g'
      # to distinguish it from a sound reference-failed skip ('s').
      gap = payload[:gap_class]
      if gap && gap != :supported_divergence
        @filtered_gaps[gap.to_s] += 1
        save_skip(payload)
        FileUtils.rm_rf(payload[:case_dir]) unless @options.fetch(:keep_skips)
        print_progress("g")
      else
        save_skip(payload)
        FileUtils.rm_rf(payload[:case_dir]) unless @options.fetch(:keep_skips)
        print_progress("s")
      end
    else
      handle_failure(payload)
    end
  end

  def handle_failure(payload)
    signature = compute_signature(payload)

    if @signatures.key?(signature)
      # Duplicate failure class. Drop its dir, count it, do not re-shrink.
      @dup_failures += 1
      FileUtils.rm_rf(payload[:case_dir])
      print_progress("d")
      return
    end

    @signatures[signature] = payload[:case_dir]
    save_failure(payload, signature)

    # Defer shrink + regression-write out of the hot ingest path: shrinking
    # re-runs the oracle many times, and doing it inline serializes the parent
    # against the --jobs workers. Collected here, processed in a parallel pass
    # after the loop (shrink_and_save_regressions).
    @pending_regressions << { payload: payload, signature: signature }

    @failures << {
      signature: signature,
      reason: payload[:reason],
      path: payload[:case_dir],
      replay: replay_command(payload[:source_path])
    }
    print_progress("F")
    @stop_hit = true if @failures.length >= @options.fetch(:stop_after)
  end

  # Shrink (when enabled) and persist regressions for every unique failure AFTER
  # the hunt loop. The shrink predicate re-runs the oracle dozens of times per
  # failure, so this runs as a parallel_map across --jobs workers instead of
  # serially in the parent — otherwise --shrink collapses --jobs back to ~1x.
  # Each worker writes its own min.rb/shrink-stats into the failure's case dir;
  # the parent (single writer) then writes the regression files.
  def shrink_and_save_regressions
    return if @pending_regressions.empty?

    minimized =
      if @options.fetch(:shrink)
        @runner.parallel_map(@pending_regressions, jobs: @jobs) do |entry|
          shrink_failure(entry[:payload], entry[:signature])
        end
      else
        Array.new(@pending_regressions.length)
      end

    @pending_regressions.each_with_index do |entry, i|
      save_regression(entry[:payload], entry[:signature], minimized[i])
    end
  end

  # ---- signatures / shrink / regression -------------------------------------

  def compute_signature(payload)
    stderr =
      if payload[:reason] == :sanitizer_report && payload[:sanitizer]
        payload[:sanitizer][:stderr]
      elsif payload[:spinel]
        payload[:spinel][:stderr]
      end
    Triage.signature(stderr: stderr, source: payload[:source])
  end

  # Distinctive (normalized) stderr lines for a stream — the per-bug fingerprint
  # the shrinker must preserve. Address/path/line noise is stripped by
  # Triage.normalize_stderr so the set is stable across runs.
  def distinctive_stderr_lines(stderr)
    return [] if stderr.nil? || stderr.empty?

    Triage.normalize_stderr(stderr).split("\n").map(&:strip).reject(&:empty?)
  end

  # Inject the shrinker predicate: re-run the oracle on a candidate source and
  # require it to reproduce the SAME bug (so we shrink toward the original, not
  # some incidentally-different failure). This keeps triage.rb decoupled — it
  # never requires the oracle.
  #
  # The guard is the SAME reason AND a stderr SUBSET: every distinctive failure
  # line the candidate emits must already appear in the original's stderr. Subset
  # (not equality) is deliberate — removing independent failing statements during
  # shrinking legitimately drops warnings, so the set only ever shrinks; but a
  # candidate that introduces a NEW failure line has drifted to a different bug
  # and is rejected. (When the original has no distinctive stderr — e.g. a pure
  # stdout mismatch with no warnings — this degrades to the reason check.)
  def shrink_failure(payload, signature)
    orig_diff_lines = distinctive_stderr_lines(payload[:spinel] && payload[:spinel][:stderr]).to_set
    orig_san_lines = distinctive_stderr_lines(payload[:sanitizer] && payload[:sanitizer][:stderr]).to_set

    predicate = lambda do |candidate|
      Dir.mktmpdir("spinel-shrink-") do |dir|
        path = File.join(dir, "case.rb")
        File.write(path, candidate)
        verdict = @oracle.diff_only(path)
        reproduced =
          if verdict.status == :fail
            cand_lines = distinctive_stderr_lines(verdict.spinel && verdict.spinel.stderr).to_set
            verdict.reason == payload[:reason] &&
              (orig_diff_lines.empty? || cand_lines.subset?(orig_diff_lines))
          elsif @sanitize && payload[:reason] == :sanitizer_report
            clean, san_run = @oracle.sanitizer_check(path)
            cand_lines = distinctive_stderr_lines(san_run && san_run.stderr).to_set
            !clean && (orig_san_lines.empty? || cand_lines.subset?(orig_san_lines))
          else
            false
          end
        reproduced
      end
    end

    shrinker = Triage::Shrinker.new(reproduce: predicate)
    minimized = shrinker.shrink(payload[:source])
    File.write(File.join(payload[:case_dir], "min.rb"), minimized)
    File.write(
      File.join(payload[:case_dir], "shrink-stats.json"),
      JSON.pretty_generate(shrinker.stats)
    )
    minimized
  rescue StandardError => e
    # A shrinker hiccup must never abort the hunt; record and move on.
    File.write(File.join(payload[:case_dir], "shrink-error.txt"), "#{e.class}: #{e.message}")
    nil
  end

  def save_regression(payload, signature, minimized)
    source = minimized || payload[:source]
    expected = payload[:reference] ? payload[:reference][:stdout].to_s : ""
    Triage.save_regression(
      source: source,
      signature: signature,
      expected_stdout: expected,
      manifest: manifest_hash,
      dir: File.join(@run_dir, "regressions")
    )
  rescue StandardError => e
    File.write(File.join(payload[:case_dir], "regression-error.txt"), "#{e.class}: #{e.message}")
    nil
  end

  # ---- persistence -----------------------------------------------------------

  # Spinel engine rev in spinelgems' format (git:<sha>[+dirty]/<arch-os>), or nil
  # when root is not a git checkout. Reads git metadata only -- safe without a
  # Spinel build, so it stamps whatever the pinned vendor/spinel submodule is.
  def self.spinel_rev(root)
    sha = `git -C #{Shellwords.escape(root)} rev-parse --short=7 HEAD 2>/dev/null`.strip
    return nil if sha.empty?
    dirty = `git -C #{Shellwords.escape(root)} status --porcelain 2>/dev/null`.strip.empty? ? "" : "+dirty"
    "git:#{sha}#{dirty}/#{RbConfig::CONFIG['host']}"
  end

  def save_skip(payload)
    dir = payload[:case_dir]
    File.write(File.join(dir, "meta.json"), JSON.pretty_generate({
      "case" => case_meta(payload),
      "skip" => payload[:reason].to_s,
      "gap_class" => payload[:gap_class].to_s,
      "spinel_rev" => @spinel_rev,
      "reference" => payload[:reference]
    }))
    write_stream(dir, "reference", payload[:reference])
  end

  def save_failure(payload, signature)
    dir = payload[:case_dir]
    File.write(File.join(dir, "meta.json"), JSON.pretty_generate({
      "case" => case_meta(payload),
      "signature" => signature,
      "reason" => payload[:reason].to_s,
      "gap_class" => payload[:gap_class].to_s,
      "spinel_rev" => @spinel_rev,
      "reference" => payload[:reference],
      "spinel" => payload[:spinel],
      "sanitizer" => payload[:sanitizer]
    }))
    write_stream(dir, "reference", payload[:reference])
    write_stream(dir, "spinel", payload[:spinel])
    write_stream(dir, "sanitizer", payload[:sanitizer])

    if payload[:reference] && payload[:spinel]
      File.write(
        File.join(dir, "stdout.diff"),
        diff_text(payload[:reference][:stdout], payload[:spinel][:stdout])
      )
    end

    # Deep pipeline capture re-runs spinel/parse/analyze/codegen (4 subprocesses,
    # incl. loading the multi-MB analyzer/codegen Ruby) PER failure, serially in
    # the parent. On failure-heavy seeds that dominates wall time and starves the
    # --jobs workers. It is debug tooling, so it is opt-in: the cheap artifacts
    # above (meta, streams, diff) plus the minimized repro are enough to triage.
    capture_artifacts(dir) if @options.fetch(:capture_artifacts)
  end

  def write_stream(dir, name, rr)
    return if rr.nil?

    File.write(File.join(dir, "#{name}.stdout"), rr[:stdout].to_s)
    File.write(File.join(dir, "#{name}.stderr"), rr[:stderr].to_s)
  end

  # Re-run spinel emit/parse/analyze/codegen to capture pipeline artifacts next
  # to a failure for triage (mirrors the legacy capture_artifacts).
  def capture_artifacts(case_dir)
    source_path = File.join(case_dir, "case.rb")
    c_path = File.join(case_dir, "case.c")
    ast_path = File.join(case_dir, "case.ast")
    ir_path = File.join(case_dir, "case.ir")
    opt = @options.fetch(:opt_level).to_s
    overflow = @options.fetch(:int_overflow)

    c_result = @runner.run([@spinel, "--int-overflow=#{overflow}", "-O", opt, "-c", "-o", c_path, source_path])
    File.write(File.join(case_dir, "spinel-capture.stdout"), c_result.stdout)
    File.write(File.join(case_dir, "spinel-capture.stderr"), c_result.stderr)
    File.write(File.join(case_dir, "spinel-capture.json"), JSON.pretty_generate(c_result.to_h))

    parse_bin = File.join(@root, "spinel_parse")
    analyze_rb = File.join(@root, "spinel_analyze.rb")
    codegen_rb = File.join(@root, "spinel_codegen.rb")
    return unless File.executable?(parse_bin)

    parse_result = @runner.run([parse_bin, source_path, ast_path])
    File.write(File.join(case_dir, "source-parse.stderr"), parse_result.stderr)
    return unless parse_result.success?

    analyze_result = @runner.run(["ruby", analyze_rb, ast_path, ir_path])
    File.write(File.join(case_dir, "source-analyze.stderr"), analyze_result.stderr)
    return unless analyze_result.success?

    codegen_result = @runner.run(["ruby", codegen_rb, ast_path, ir_path, File.join(case_dir, "source-analyze.c")])
    File.write(File.join(case_dir, "source-codegen.stderr"), codegen_result.stderr)
  rescue StandardError => e
    File.write(File.join(case_dir, "capture-error.txt"), "#{e.class}: #{e.message}")
  end

  # ---- manifest / progress / resume -----------------------------------------

  def manifest_hash
    @manifest_hash ||= Triage.manifest(
      spinel: @spinel,
      spinel_dir: @root,
      cc: @options.fetch(:sanitizer_cc),
      ref_ruby: @ref_ruby,
      seed: @seed,
      opt_level: @options.fetch(:opt_level),
      int_overflow: @options.fetch(:int_overflow),
      timeout: @options.fetch(:timeout),
      jobs: @jobs,
      sanitize: @sanitize
    ).merge(
      "cases" => @options.fetch(:cases),
      "families" => @options.fetch(:families),
      "exclude_families" => @options.fetch(:exclude_families),
      "mode" => @mode.to_s,
      "run_dir" => @run_dir
    )
  end

  def write_manifest
    Triage.write_manifest(File.join(@run_dir, "run.json"), manifest_hash)
  end

  def checkpoint(last_index)
    File.write(File.join(@run_dir, "progress.json"), JSON.pretty_generate({
      "last_completed_index" => last_index,
      "passes" => @passes,
      "skips" => @skips,
      "unique_failures" => @failures.length,
      "duplicate_failures" => @dup_failures,
      "filtered_gaps" => @filtered_gaps
    }))
  rescue StandardError
    nil
  end

  # When --continue and a progress.json exists, resume from the next index and
  # re-load already-seen failure signatures so dedup stays idempotent across
  # resumed runs. Otherwise start at 0.
  def resume_state
    return [0, nil] unless @continue

    progress_path = File.join(@run_dir, "progress.json")
    return [0, nil] unless File.exist?(progress_path)

    data = JSON.parse(File.read(progress_path))
    last = data["last_completed_index"].to_i

    # Re-seed dedup set from existing failure dirs (their meta.json carries the
    # signature) so resumed runs don't re-report the same classes.
    Dir.glob(File.join(@run_dir, "case-*", "meta.json")).each do |meta|
      sig = JSON.parse(File.read(meta))["signature"] rescue nil
      @signatures[sig] ||= File.dirname(meta) if sig
    end

    [last + 1, data]
  rescue StandardError
    [0, nil]
  end

  # ---- finalize --------------------------------------------------------------

  def finalize(_prior)
    checkpoint(@options.fetch(:cases) - 1) unless @options.fetch(:no_progress)
    puts unless @options.fetch(:no_progress) == false && @passes + @skips + @failures.length == 0

    total = @passes + @skips + @signatures.length + @dup_failures
    puts
    puts "Fuzzed #{total} cases: #{@passes} pass, #{@skips} skip, " \
         "#{@signatures.length} unique failures (#{@dup_failures} duplicates)"

    # Gap-filter accounting: how many divergences were DISCARDED (not lost) by
    # --supported-only, broken down by class. Only meaningful when the filter is on.
    if options_supported_only?
      filtered_total = @filtered_gaps.values.sum
      if filtered_total.positive?
        breakdown = @filtered_gaps.sort.map { |k, v| "#{v} #{k}" }.join(", ")
        puts "Gap filter (--supported-only) discarded #{filtered_total} divergence(s): #{breakdown}"
        puts "  (these are degradation-warned or documented-intentional gaps, NOT supported-territory failures)"
      else
        puts "Gap filter (--supported-only) ON: 0 divergences discarded as gaps."
      end
      unless @failures.empty?
        puts "Reported failures are supported-territory divergences; run classify_run.rb for review buckets."
      end
    end

    if @failures.empty?
      puts "No failures found. Run dir: #{@run_dir}"
      return 0
    end

    @failures.each do |failure|
      puts "Failure [#{failure[:signature]}]: #{failure[:reason]} #{failure[:path]}"
      puts "  Replay: #{failure[:replay]}"
    end
    puts "Run dir: #{@run_dir}"
    @options.fetch(:allow_failures) ? 0 : 1
  end

  # ---- helpers ---------------------------------------------------------------

  def options_supported_only?
    @options.fetch(:supported_only)
  end

  def case_dir_for(generated)
    File.join(@run_dir, "case-%06d-%s" % [generated.index, generated.family])
  end

  def replay_command(source_path)
    overflow = @options.fetch(:int_overflow)
    "#{@spinel} -O #{@options.fetch(:opt_level)} --int-overflow=#{overflow} -E #{source_path.shellescape}"
  end

  def runresult_h(rr)
    return nil if rr.nil?

    {
      argv: rr.argv,
      status: rr.status,
      stdout: rr.stdout.to_s,
      stderr: rr.stderr.to_s,
      timed_out: rr.timed_out,
      signal: rr.signal
    }
  end

  def diff_text(expected, actual)
    expected_lines = normalize(expected.to_s).lines
    actual_lines = normalize(actual.to_s).lines
    return "" if expected_lines == actual_lines

    body = ["--- reference.stdout\n", "+++ spinel.stdout\n"]
    max = [expected_lines.length, actual_lines.length].max
    max.times do |i|
      e = expected_lines[i]
      a = actual_lines[i]
      next if e == a

      body << "-#{e || ''}"
      body << "+#{a || ''}"
    end
    body.join
  end

  def normalize(text)
    text.gsub(/\r\n?/, "\n")
  end

  def print_progress(char)
    return if @options.fetch(:no_progress)

    print char
    $stdout.flush
  end

  def case_meta(payload)
    {
      "seed" => payload[:seed],
      "index" => payload[:index],
      "family" => payload[:family]
    }
  end
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

options = {
  seed: 1,
  cases: 100,
  out: File.join(ROOT, "tmp", "fuzz"),
  spinel: "spinel",
  ref_ruby: default_ref_ruby,
  opt_level: 0,
  timeout: 10,
  stop_after: 1,
  families: nil,
  exclude_families: [],
  keep_passing: false,
  keep_skips: false,
  no_progress: false,
  # new flags
  jobs: 1,
  no_sanitize: false,
  shrink: false,
  capture_artifacts: false,
  continue: false,
  int_overflow: "raise",
  sanitizer_cc: "clang",
  overflow_ubsan: false,
  typed: true,
  allow_failures: false,
  # Gap filter: default ON. When ON, the oracle discards degradation-gap and
  # intentional-incompat divergences (counted, not lost) and surfaces only
  # supported-territory divergences for post-run classification.
  supported_only: true,
  root: SPINEL_ROOT
}

OptionParser.new do |parser|
  parser.banner = "Usage: ruby tools/fuzz_spinel.rb [options]"
  # ---- existing flags (preserved exactly) ----
  parser.on("--seed N", Integer, "Top-level random seed") { |v| options[:seed] = v }
  parser.on("--cases N", Integer, "Number of generated cases") { |v| options[:cases] = v }
  parser.on("--out DIR", "Output directory") { |v| options[:out] = v }
  parser.on("--spinel PATH", "Path to spinel executable (default vendor/spinel/spinel)") { |v| options[:spinel] = v }
  parser.on("--root DIR", "Spinel toolchain root holding spinel_parse / spinel_analyze.rb / spinel_codegen.rb (default vendor/spinel)") { |v| options[:root] = File.expand_path(v) }
  parser.on("--ref-ruby CMD", "Reference Ruby command") { |v| options[:ref_ruby] = v }
  parser.on("--opt LEVEL", Integer, "Spinel C optimization level") { |v| options[:opt_level] = v }
  parser.on("--timeout SEC", Integer, "Per-command timeout") { |v| options[:timeout] = v }
  parser.on("--stop-after N", Integer, "Stop after this many unique failures (seq mode)") { |v| options[:stop_after] = v }
  parser.on("--families LIST", "Comma-separated family allow-list") { |v| options[:families] = v }
  parser.on("--exclude-family NAME", "Family to exclude; may be repeated") { |v| options[:exclude_families] << v }
  parser.on("--keep-passing", "Keep passing case directories") { options[:keep_passing] = true }
  parser.on("--keep-skips", "Keep skipped case directories") { options[:keep_skips] = true }
  parser.on("--no-progress", "Disable dot progress + checkpoints") { options[:no_progress] = true }
  # ---- new flags ----
  parser.on("--jobs N", Integer, "Parallel worker shard count (default 1)") { |v| options[:jobs] = v }
  parser.on("--no-sanitize", "Disable the ASan/UBSan sanitizer lane") { options[:no_sanitize] = true }
  parser.on("--shrink", "Auto-minimize each unique failure (delta-debug)") { options[:shrink] = true }
  parser.on("--capture-artifacts", "Deep pipeline dump (.c/.ast/.ir) per failure; slow, off by default") { options[:capture_artifacts] = true }
  parser.on("--continue", "Resume from run_dir progress.json; collect many failures with dedup") { options[:continue] = true }
  parser.on("--int-overflow MODE", "Int overflow mode: raise|wrap|promote (default raise)") { |v| options[:int_overflow] = v }
  parser.on("--sanitizer-cc CMD", "C compiler for the two-phase ASan/UBSan build (default clang)") { |v| options[:sanitizer_cc] = v }
  parser.on("--overflow-ubsan", "Extra opt-in lane: wrap-mode UBSan signed-overflow as findings") { options[:overflow_ubsan] = true }
  parser.on("--allow-failures", "Exit 0 even when failures are found (for smoke/CI harness checks)") { options[:allow_failures] = true }
  parser.on("--supported-only", "Gap filter (default ON): report only supported-territory divergences; discard degradation-gap + intentional-incompat divergences") { options[:supported_only] = true }
  parser.on("--all-divergences", "Disable the gap filter: report EVERY divergence (degradation gaps included)") { options[:supported_only] = false }
  parser.on("--templates", "Use legacy template families instead of typed recursive generation") { options[:typed] = false }
end.parse!

exit Fuzzer.new(options).run
