#!/usr/bin/env ruby
# frozen_string_literal: true

# promote.rb -- upstream repro exporter for the Spinel fuzzer.
#
# Converts a minimized fuzzer repro (a valid CRuby program whose stdout the
# Spinel AOT compiler diverges from) into a small upstream-ready artifact pair:
# `<name>.rb` plus `<name>.rb.expected`. The standalone fuzzer keeps these under
# tmp/upstream-repros by default; whether Spinel wants known-fail tests, normal
# regressions, or issue-only repros is an upstream process decision.
#
# Pure Ruby stdlib only.
#
# CLI:
#   ruby tools/fuzz/promote.rb [options] <repro.rb> [more.rb ...]
#
# Options:
#   --name <snake_case>   Output basename (default: derived from repro filename).
#   --issue <n>           Upstream issue number for the header (default: TBD).
#   --overflow <mode>     Record a mode-specific bug (raise|wrap|promote): runs
#                         spinel under that --int-overflow and stamps a warning
#                         that the case must be graded under that build mode.
#   --spinel <path>       Spinel driver (default: <repo>/vendor/spinel/spinel).
#   --out-dir <dir>       Override output dir (default: <repo>/tmp/upstream-repros).
#   --ref-ruby <cmd>      Reference CRuby (default: $REF_RUBY or "ruby").
#   --force               Emit even if a different name already holds this
#                         normalized-source signature (skips the dedup refusal).
#   -h, --help            Show usage.
#
# Behavior per repro:
#   1. Run reference CRuby -> capture stdout = the CORRECT/expected output. If
#      CRuby itself fails (nonzero), REFUSE -- no sound oracle.
#   2. Run spinel (./spinel -E) on the same source. Confirm the bug CURRENTLY
#      reproduces: spinel build-fails OR crashes OR stdout != CRuby stdout. If
#      spinel MATCHES CRuby, REFUSE: "not a divergence -- nothing to promote".
#   3. Emit <out-dir>/<name>.rb (repro + upstream-friendly header),
#      <out-dir>/<name>.rb.expected (CRuby stdout), and .rb.args if needed.
#
# Idempotent: re-running over the same repro overwrites deterministically.
# Signature-keyed on normalized source so the same bug can't be emitted twice
# under two names (unless --force).

require "open3"
require "fileutils"
require "digest"
require "shellwords"

module Promote
  # --- repo layout ------------------------------------------------------------

  # tools/fuzz/promote.rb -> repo root is two dirs up.
  REPO_ROOT = File.expand_path("../..", __dir__)

  def self.default_out_dir
    File.join(REPO_ROOT, "tmp", "upstream-repros")
  end

  def self.default_spinel
    File.join(REPO_ROOT, "vendor", "spinel", "spinel")
  end

  VALID_OVERFLOW_MODES = %w[raise wrap promote].freeze

  # --- stdout normalization (mirror the Makefile's LC_ALL=C sed 's/\r$//') ----

  # Strip CR before LF and lone CR, so the emitted .expected is stable across
  # platforms and matches the fuzzer's own stdout normalization.
  def self.normalize_stdout(text)
    (text || "").gsub("\r\n", "\n").gsub("\r", "\n")
  end

  # --- source normalization for the dedup signature (mirror triage.rb) --------

  # Drop the fuzzer's own "# fuzz-*" header, blank lines, and trailing
  # whitespace so the same bug yields a stable signature regardless of
  # incidental formatting.
  def self.normalize_source(source)
    (source || "").split("\n")
      .reject { |line| line.strip.start_with?("# fuzz-") }
      .map(&:rstrip)
      .reject(&:empty?)
      .join("\n")
      .strip
  end

  def self.signature(source)
    Digest::SHA256.hexdigest(normalize_source(source))[0, 12]
  end

  # Strip the fuzzer's own "# fuzz-*" header lines from a source for emission.
  # Only leading fuzz-* comment lines are removed (the header block), matching
  # the generator's own header-replacement idiom.
  def self.strip_fuzz_header(source)
    lines = (source || "").split("\n", -1)
    lines.shift while lines.first&.strip&.start_with?("# fuzz-")
    # Drop a single leading blank line left behind by the header strip.
    lines.shift if lines.first && lines.first.strip.empty?
    lines.join("\n")
  end

  # --- subprocess runner ------------------------------------------------------

  RunResult = Struct.new(:status, :stdout, :stderr, :timed_out, keyword_init: true) do
    def success?
      !timed_out && status&.zero?
    end
  end

  def self.run(argv, env: {})
    out, err, st = Open3.capture3(env, *argv)
    RunResult.new(status: st.exitstatus, stdout: out, stderr: err, timed_out: false)
  rescue StandardError => e
    RunResult.new(status: nil, stdout: "", stderr: e.message, timed_out: false)
  end

  # --- divergence classification ----------------------------------------------

  # Compare spinel against the CRuby oracle. Returns a hash:
  #   { diverges: Bool, kind: Symbol, spinel: RunResult, observed: String }
  # kind is one of :build_fail, :crash, :stdout_mismatch, :match.
  #
  # "build-fails OR crashes OR stdout != CRuby" all count as the bug being
  # present for repro export. Only a clean exit with matching stdout is :match
  # (no bug -> refuse).
  def self.classify(spinel_run, expected_stdout)
    observed = normalize_stdout(spinel_run.stdout)

    # spinel -E does both build and run; a nonzero/failed status with NO stdout
    # produced is a build failure (broken-C codegen, analyze rejection, etc.).
    if spinel_run.status.nil? || spinel_run.timed_out
      return { diverges: true, kind: :crash, spinel: spinel_run, observed: observed }
    end

    if spinel_run.status != 0
      # Signal-style termination (segfault) lands here too. Distinguish a
      # build-time failure (no stdout at all) from a runtime crash.
      kind = observed.empty? ? :build_fail : :crash
      return { diverges: true, kind: kind, spinel: spinel_run, observed: observed }
    end

    if observed == expected_stdout
      { diverges: false, kind: :match, spinel: spinel_run, observed: observed }
    else
      { diverges: true, kind: :stdout_mismatch, spinel: spinel_run, observed: observed }
    end
  end

  # --- header rendering (Spinel house style) ----------------------------------

  KIND_LABEL = {
    build_fail: "build failure (codegen/analyze rejects valid CRuby)",
    crash: "crash / nonzero exit (binary aborts where CRuby succeeds)",
    stdout_mismatch: "supported divergence (wrong stdout, clean exit)"
  }.freeze

  def self.indent_block(text, prefix)
    lines = (text.empty? ? ["(no output)"] : text.split("\n"))
    lines.map { |l| "#{prefix}#{l}" }.join("\n")
  end

  def self.render_header(name:, kind:, expected:, observed:, issue:, overflow:, ref_ruby:)
    issue_line =
      if issue
        "# Issue ##{issue} (partial): spinel diverges from CRuby on this repro."
      else
        "# Spinel repro: differential divergence harvested by the standalone fuzzer."
      end

    overflow_note =
      if overflow
        [
          "#",
          "# MODE-SPECIFIC: this bug reproduces under --int-overflow=#{overflow}.",
          "# It must be graded under the matching SPINEL_INT_OVERFLOW=#{overflow} build",
          "# (see the ifeq ($(SPINEL_INT_OVERFLOW),...) filter-out idiom in the Makefile)."
        ]
      else
        []
      end

    lines = []
    lines << issue_line
    lines << "#"
    lines << "# CATEGORY:  #{KIND_LABEL.fetch(kind)}"
    lines << "#"
    lines << "# TRIGGER:   This minimized repro is a valid CRuby program. spinel's AOT"
    lines << "#            output diverges from the reference interpreter (#{kind})."
    lines << "#"
    lines << "# EXPECTED (CRuby via #{ref_ruby}):"
    lines << indent_block(expected, "#   ")
    lines << "#"
    lines << "# OBSERVED (spinel -E):"
    lines << indent_block(observed, "#   ")
    lines.concat(overflow_note)
    lines << "#"
    lines << "# Upstream-issue: #{issue ? "##{issue}" : 'TBD'}"
    lines.join("\n")
  end

  # --- emission ---------------------------------------------------------------

  # Renders the full .rb file body (header + cleaned source). Deterministic:
  # same inputs -> identical bytes (idempotent overwrite).
  def self.render_rb(repro_source, **header_kwargs)
    body = strip_fuzz_header(repro_source)
    body = "#{body}\n" unless body.end_with?("\n") || body.empty?
    "#{render_header(**header_kwargs)}\n#{body}"
  end

  # --- one-shot export of a single repro ---------------------------------------

  Result = Struct.new(:ok, :reason, :name, :files, keyword_init: true)

  # Promotes one repro. Returns a Result. Pure of process exit; the CLI decides
  # how to surface refusals. `signatures` is a mutable {sig => name} map used to
  # detect duplicate bugs across a single invocation AND already-on-disk cases.
  def self.promote_one(repro_path, opts, signatures)
    unless File.file?(repro_path)
      return Result.new(ok: false, reason: "no such file: #{repro_path}", name: nil, files: [])
    end

    repro_source = File.read(repro_path)
    name = opts[:name] || derive_name(repro_path)
    out_dir = opts[:out_dir]
    ref_ruby_argv = opts[:ref_ruby_argv]
    spinel = opts[:spinel]

    args = read_args(repro_path)

    # (1) Reference CRuby oracle.
    ref = run(ref_ruby_argv + [repro_path] + args)
    unless ref.success?
      return Result.new(
        ok: false,
        name: name, files: [],
        reason: "REFUSE: CRuby reference failed (status=#{ref.status.inspect}); " \
                "cannot form a sound oracle. stderr: #{ref.stderr.strip[0, 200]}"
      )
    end
    expected = normalize_stdout(ref.stdout)

    # (2) spinel -- confirm the bug currently reproduces.
    overflow = opts[:overflow]
    spinel_argv = [spinel]
    spinel_argv.concat(["--int-overflow=#{overflow}"]) if overflow
    spinel_argv.concat(["-E", repro_path])
    spinel_argv.concat(args)
    sp_env = overflow ? { "SPINEL_INT_OVERFLOW" => overflow } : {}
    sp = run(spinel_argv, env: sp_env)

    verdict = classify(sp, expected)
    unless verdict[:diverges]
      return Result.new(
        ok: false,
        name: name, files: [],
        reason: "REFUSE: not a divergence -- nothing to promote (spinel stdout " \
                "matches CRuby for #{File.basename(repro_path)})."
      )
    end

    # Dedup: same normalized source = same bug. Guard against emitting under a
    # second name unless --force.
    sig = signature(repro_source)
    if (existing = signatures[sig]) && existing != name && !opts[:force]
      return Result.new(
        ok: false,
        name: name, files: [],
        reason: "REFUSE: duplicate bug (signature #{sig}) already tracked as " \
                "'#{existing}'. Use --force or --name to override."
      )
    end

    # (3) Emit fixtures.
    FileUtils.mkdir_p(out_dir)
    rb_path = File.join(out_dir, "#{name}.rb")
    exp_path = File.join(out_dir, "#{name}.rb.expected")
    args_path = File.join(out_dir, "#{name}.rb.args")

    rb_body = render_rb(
      repro_source,
      name: name,
      kind: verdict[:kind],
      expected: expected,
      observed: verdict[:observed],
      issue: opts[:issue],
      overflow: overflow,
      ref_ruby: ref_ruby_argv.join(" ")
    )

    files = []
    write_stable(rb_path, rb_body); files << rb_path
    write_stable(exp_path, expected); files << exp_path
    if args.empty?
      File.delete(args_path) if File.exist?(args_path)
    else
      write_stable(args_path, "#{args.shelljoin}\n"); files << args_path
    end

    signatures[sig] = name
    Result.new(ok: true, reason: "exported (#{verdict[:kind]})", name: name, files: files)
  end

  # Write only if content differs, so mtime stays stable on idempotent reruns
  # (keeps the make target's mtime-based caching honest).
  def self.write_stable(path, content)
    return if File.exist?(path) && File.read(path) == content

    File.write(path, content)
  end

  def self.derive_name(repro_path)
    base = File.basename(repro_path, ".*")
    # Strip a leading NNN- numbered prefix; upstream repro names should be
    # snake_case, not the numbered fuzz-regression style.
    base = base.sub(/\A\d+[-_]/, "")
    base = base.gsub(/[^a-zA-Z0-9]+/, "_").gsub(/_+/, "_").gsub(/\A_|_\z/, "").downcase
    base.empty? ? "spinel_repro_case" : base
  end

  def self.read_args(repro_path)
    args_file = "#{repro_path}.args"
    return [] unless File.file?(args_file)

    Shellwords.split(File.read(args_file).strip)
  end

  # Scan an existing out_dir to seed the signature map, so dedup spans prior
  # runs (idempotency across invocations). Reads the committed .rb fixtures and
  # signs their post-header source.
  def self.scan_existing_signatures(out_dir)
    sigs = {}
    return sigs unless Dir.exist?(out_dir)

    Dir.glob(File.join(out_dir, "*.rb")).sort.each do |rb|
      name = File.basename(rb, ".rb")
      src = File.read(rb)
      # Drop the leading "#"-comment header block we emit before signing.
      body = src.split("\n", -1).drop_while { |l| l.strip.start_with?("#") || l.strip.empty? }.join("\n")
      sigs[signature(body)] = name
    end
    sigs
  end

  # --- CLI --------------------------------------------------------------------

  USAGE = <<~TXT
    Usage: ruby tools/fuzz/promote.rb [options] <repro.rb> [more.rb ...]

      --name <snake_case>   Output basename (default: derived from repro filename)
      --issue <n>           Upstream issue number for the header
      --overflow <mode>     Mode-specific bug: raise|wrap|promote
      --spinel <path>       Spinel driver (default: <repo>/vendor/spinel/spinel)
      --out-dir <dir>       Output dir (default: <repo>/tmp/upstream-repros)
      --ref-ruby <cmd>      Reference CRuby (default: $REF_RUBY or "ruby")
      --force               Emit even if the source signature is already tracked
      -h, --help            Show this help
  TXT

  def self.parse_argv(argv)
    opts = {
      name: nil, issue: nil, overflow: nil,
      spinel: default_spinel,
      out_dir: default_out_dir,
      ref_ruby_argv: Shellwords.split(ENV["REF_RUBY"].to_s.empty? ? "ruby" : ENV["REF_RUBY"]),
      force: false
    }
    repros = []
    argv = argv.dup
    until argv.empty?
      arg = argv.shift
      case arg
      when "--name"      then opts[:name] = argv.shift
      when "--issue"     then opts[:issue] = argv.shift
      when "--overflow"  then opts[:overflow] = argv.shift
      when "--spinel"    then opts[:spinel] = argv.shift
      when "--out-dir"   then opts[:out_dir] = argv.shift
      when "--ref-ruby"  then opts[:ref_ruby_argv] = Shellwords.split(argv.shift.to_s)
      when "--force"     then opts[:force] = true
      when "-h", "--help" then opts[:help] = true
      else
        if arg.start_with?("-")
          raise ArgumentError, "unknown option: #{arg}"
        end

        repros << arg
      end
    end

    if opts[:overflow] && !VALID_OVERFLOW_MODES.include?(opts[:overflow])
      raise ArgumentError, "invalid --overflow #{opts[:overflow].inspect} (expected one of #{VALID_OVERFLOW_MODES.join('/')})"
    end

    [opts, repros]
  end

  def self.main(argv)
    opts, repros = parse_argv(argv)

    if opts[:help]
      puts USAGE
      return 0
    end

    if repros.empty?
      warn "export: no repro files given"
      warn USAGE
      return 2
    end

    if repros.size > 1 && opts[:name]
      warn "export: --name with multiple repros would collide; pass one repro at a time"
      return 2
    end

    warn "export: --overflow=#{opts[:overflow]} -- emitted case must be graded under " \
         "the SPINEL_INT_OVERFLOW=#{opts[:overflow]} build." if opts[:overflow]

    signatures = scan_existing_signatures(opts[:out_dir])

    promoted = 0
    refused = 0
    repros.each do |repro|
      res = promote_one(repro, opts, signatures)
      if res.ok
        promoted += 1
        puts "EXPORTED #{res.name}: #{res.reason}"
        res.files.each { |f| puts "  -> #{f}" }
      else
        refused += 1
        warn res.reason
      end
    end

    puts "Exported #{promoted} upstream repro case(s); #{refused} refused."
    # Nonzero only when nothing was exported AND something was attempted, so a
    # batch with at least one good export still succeeds for CI.
    promoted.zero? ? 1 : 0
  end
end

# ---------------------------------------------------------------------------
# Self-test (guarded; does not run on require).
# ---------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME && ARGV.delete("--selftest")
  require "tmpdir"

  failures = []
  assert = lambda do |cond, msg|
    if cond
      print "."
    else
      print "F"
      failures << msg
    end
  end

  # --- pure-unit checks -------------------------------------------------------
  assert.call(Promote.normalize_stdout("a\r\nb\rc\n") == "a\nb\nc\n", "normalize CRLF/CR -> LF")
  assert.call(
    Promote.signature("# fuzz-seed: 1\nputs 1/0\n") == Promote.signature("# fuzz-seed: 999\nputs 1/0"),
    "signature ignores fuzz header + trailing ws"
  )
  assert.call(Promote.strip_fuzz_header("# fuzz-a: 1\n# fuzz-b: 2\nputs 1\n") == "puts 1\n",
              "strip_fuzz_header drops leading fuzz lines")
  cl = Promote.classify(Promote::RunResult.new(status: 0, stdout: "x\n", stderr: "", timed_out: false), "x\n")
  assert.call(cl[:kind] == :match && !cl[:diverges], "classify match")
  cl = Promote.classify(Promote::RunResult.new(status: 0, stdout: "wrong\n", stderr: "", timed_out: false), "x\n")
  assert.call(cl[:kind] == :stdout_mismatch && cl[:diverges], "classify stdout mismatch")
  cl = Promote.classify(Promote::RunResult.new(status: 1, stdout: "", stderr: "boom", timed_out: false), "x\n")
  assert.call(cl[:kind] == :build_fail && cl[:diverges], "classify build fail")

  # --- end-to-end against the real spinel + ruby ------------------------------
  spinel = Promote.default_spinel
  have_spinel = File.executable?(spinel)
  have_ruby = system("ruby -e 'exit 0' >/dev/null 2>&1")

  if have_spinel && have_ruby
    Dir.mktmpdir("promote-selftest-") do |dir|
      out_dir = File.join(dir, "upstream-repros")

      # A KNOWN stdout divergence (fuzz-regression bug 001/002 family): a
      # `Const = Struct.new(...)` under a conditional modifier is mis-typed as
      # int, so spinel prints 0 where CRuby prints the field value.
      divergent = File.join(dir, "div.rb")
      File.write(divergent, "# fuzz-seed: 7\nPt = Struct.new(:x) if true\nputs Pt.new(5).x\n")

      base_opts = {
        name: "selftest_case", issue: 738, overflow: nil,
        spinel: spinel, out_dir: out_dir,
        ref_ruby_argv: ["ruby"], force: false
      }

      sigs = Promote.scan_existing_signatures(out_dir)
      r1 = Promote.promote_one(divergent, base_opts, sigs)
      assert.call(r1.ok, "emits on a known divergence (#{r1.reason})")

      rb = File.join(out_dir, "selftest_case.rb")
      exp = File.join(out_dir, "selftest_case.rb.expected")
      assert.call(File.file?(rb), "emitted .rb")
      assert.call(File.file?(exp), "emitted .rb.expected")
      assert.call(File.read(rb).include?("# Upstream-issue: #738"), "header carries issue")
      assert.call(File.read(rb).include?("puts Pt.new(5).x"), "repro source preserved")
      assert.call(!File.read(rb).include?("# fuzz-seed"), "fuzz header stripped")

      # Idempotent: re-run is byte-stable.
      before = File.read(rb)
      mtime_before = File.mtime(rb)
      sleep 0.01
      r2 = Promote.promote_one(divergent, base_opts, Promote.scan_existing_signatures(out_dir))
      assert.call(r2.ok, "re-run still exports")
      assert.call(File.read(rb) == before, "re-run is byte-stable")
      assert.call(File.mtime(rb) == mtime_before, "re-run does not rewrite (mtime stable)")

      # .expected holds CRuby stdout (matches what the bug violates).
      ref_out = `ruby #{Shellwords.escape(divergent)}`
      assert.call(File.read(exp) == Promote.normalize_stdout(ref_out), ".expected == CRuby stdout")

      # REFUSE on a non-divergence: a program spinel handles identically.
      match = File.join(dir, "match.rb")
      File.write(match, "puts 1 + 1\n")
      rm = Promote.promote_one(match, base_opts.merge(name: "should_refuse"), {})
      assert.call(!rm.ok && rm.reason.include?("not a divergence"),
                  "REFUSE when spinel == CRuby (#{rm.reason})")
      assert.call(!File.exist?(File.join(out_dir, "should_refuse.rb")), "no file on refusal")

      # REFUSE when CRuby itself fails (no sound oracle).
      bad = File.join(dir, "bad.rb")
      File.write(bad, "raise 'nope'\n")
      rb2 = Promote.promote_one(bad, base_opts.merge(name: "bad_oracle"), {})
      assert.call(!rb2.ok && rb2.reason.include?("CRuby reference failed"),
                  "REFUSE on failing oracle (#{rb2.reason})")

      # Dedup: same source under a second name refuses.
      sigs2 = Promote.scan_existing_signatures(out_dir)
      rdup = Promote.promote_one(divergent, base_opts.merge(name: "second_name"), sigs2)
      assert.call(!rdup.ok && rdup.reason.include?("duplicate bug"),
                  "REFUSE duplicate signature (#{rdup.reason})")
    end
  else
    warn "\n[selftest] spinel or ruby unavailable; ran pure-unit checks only " \
         "(spinel=#{have_spinel} ruby=#{have_ruby})"
  end

  puts
  if failures.empty?
    puts "promote selftest: ALL PASS"
    exit 0
  else
    puts "promote selftest: #{failures.size} FAILURE(S)"
    failures.each { |m| puts "  - #{m}" }
    exit 1
  end
elsif __FILE__ == $PROGRAM_NAME
  exit Promote.main(ARGV)
end
