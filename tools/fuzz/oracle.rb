#!/usr/bin/env ruby
# frozen_string_literal: true

# Differential + sanitizer oracle for the hardened Spinel fuzzer.
#
# Two lanes:
#   1. Differential lane: run reference CRuby and spinel on the same source and
#      compare normalized stdout, exit status, exception class+message (when both
#      raise), and crash-signal classification. Cases where the reference itself
#      fails (non-zero / crash / timeout) are SKIPPED to keep the oracle sound.
#   2. Sanitizer lane: emit C (phase A), compile an ASan+UBSan instrumented binary
#      (phase B) using spinel's EXACT include/link recipe, then RUN it via the
#      Runner with the mandated ASAN_OPTIONS/UBSAN_OPTIONS and NO rlimit_as. Any
#      sanitizer report (SIGABRT or exit 99 with the marker regex) is a FAILURE
#      even when stdout matches the reference.
#
# Pure stdlib. Depends only on runner.rb (require_relative 'runner').

require "fileutils"
require "shellwords"
require "tmpdir"

require_relative "runner"
require_relative "capabilities"

# Structured result of an oracle check.
#
# status:    :pass | :fail | :skip
# reason:    Symbol describing the verdict, e.g.
#            :ok, :stdout_mismatch, :exit_mismatch, :exception_class_mismatch,
#            :exception_message_mismatch, :signal_mismatch, :spinel_timeout,
#            :sanitizer_report, :reference_failed,
#            :degradation_gap, :intentional_incompat  (filtered-out divergences)
# reference: RunResult for the reference CRuby run (or nil)
# spinel:    RunResult for the spinel run (or nil)
# sanitizer: RunResult for the sanitizer run (or nil when sanitize disabled / not run)
# gap_class: divergence classification (always set when a divergence was observed,
#            even if the verdict was downgraded to :skip by --supported-only):
#              :supported_divergence-> not a known gap/intentional incompat (KEEP)
#              :degradation_gap     -> spinel WARNED it was degrading (a known gap)
#              :intentional_incompat-> hit a documented-intentional divergence
#            nil when there was no divergence (pass / reference-failed skip).
Verdict = Struct.new(:status, :reason, :reference, :spinel, :sanitizer, :gap_class, keyword_init: true) do
  def pass?
    status == :pass
  end

  def fail?
    status == :fail
  end

  def skip?
    status == :skip
  end

  def supported_divergence?
    gap_class == :supported_divergence
  end
end

# GapFilter: the supported-territory gap filter.
#
# Classifies a *confirmed* differential divergence (spinel output disagrees with
# the CRuby reference) into one of three buckets so the campaign can surface only
# the cases that are not already explained by known gaps:
#
#   :supported_divergence spinel did not emit a give-up/degradation marker and the
#                         source is not a documented intentional incompatibility.
#                         classify_run.rb refines these into review buckets such
#                         as supported divergence, markerless build failure, or
#                         robustness failure.
#   :degradation_gap      spinel WARNED it was degrading ("cannot resolve call",
#                         "(emitting 0)", "unsupported Ruby syntax", "falling
#                         through/back", "did not converge", ...). A known gap.
#   :intentional_incompat the program exercises a DOCUMENTED-intentional divergence
#                         (Hash/Range/Struct#inspect, Float round/ceil/floor with a
  #                         non-literal ndigits, Integer#** with a negative
  #                         exponent, ...). Not a bug. Source filters are narrow
  #                         by design so they do not mask real inspect/render bugs.
#
# Only :supported_divergence survives the --supported-only filter; the other two
# are downgraded to :skip but their gap_class is retained on the Verdict so
# nothing is lost (the campaign reports per-class filtered counts).
module GapFilter
  module_function

  # Degradation markers: literal substrings spinel prints to stderr the moment it
  # gives up and emits the historical no-op `0` (or otherwise widens /
  # falls through). The authoritative list — tiered into stable PRIMARY markers
  # (pinned to spinel_codegen.rb / spinel_analyze.rb literal warning text) and
  # looser SECONDARY heuristics — now lives in Capabilities::DEGRADATION_MARKERS
  # so the fuzzer is configurable and grows with Spinel. Here we compile the
  # union (primary + secondary) into one case-insensitive regex, matched against
  # normalized (CRLF->LF) stderr.
  #
  # SUPERSET-PRESERVING: this is the exact union of the previous inline
  # alternatives, just relocated + tiered. The two line-anchored / word-boundary
  # alternatives that cannot be expressed as plain substrings
  # (/^unhandled\b/, /^warning:.*\bunresolved\b/) are carried verbatim in
  # Capabilities::SECONDARY_REGEXPS and OR'd in below.
  DEGRADATION_MARKER = Regexp.union(
    *Capabilities.degradation_marker_substrings.map { |s| /#{Regexp.escape(s)}/i },
    *Capabilities::SECONDARY_REGEXPS
  ).freeze

  # Documented-intentional divergences (the EXCLUDE list). The generator should
  # not emit these, but we guard anyway: if a divergence is traceable to one of
  # these constructs (by a marker in stderr OR a syntactic signature in source),
  # it is an :intentional_incompat, never a bug. Conservative — only fires on
  # strong, specific signals so it never masks a real supported divergence. Sourced
  # from Capabilities::INTENTIONAL (lifted from Spinel's NOT-BUGS.md).
  INTENTIONAL_SOURCE_SIGNATURES = Capabilities::INTENTIONAL[:signatures]

  # Returns true iff spinel's stderr contains a degradation / give-up marker.
  def degraded?(spinel_stderr)
    text = Oracle.normalize_stdout(spinel_stderr.to_s)
    !!(text =~ DEGRADATION_MARKER)
  end

  # Returns true iff the SOURCE exercises a documented-intentional construct.
  def intentional?(source)
    return false if source.nil?

    src = source.to_s
    INTENTIONAL_SOURCE_SIGNATURES.any? { |re| src =~ re }
  end

  # Classify a confirmed divergence. `source` may be nil (then intentional
  # detection relies solely on stderr markers, of which there currently are none
  # — intentional constructs are stderr-clean — so a nil source can only yield
  # :degradation_gap or :supported_divergence).
  #
  #   spinel_stderr: spinel run's stderr (String)
  #   source:        the program source (String or nil)
  # Returns one of :degradation_gap, :intentional_incompat, :supported_divergence.
  def classify(spinel_stderr:, source: nil)
    return :degradation_gap if degraded?(spinel_stderr)
    return :intentional_incompat if intentional?(source)

    :supported_divergence
  end
end

class Oracle
  # Marker that must appear in (normalized) stderr for a run to count as a real
  # sanitizer report. Verified empirically against captured ASan/UBSan output.
  SANITIZER_MARKER = /SUMMARY:\s+(Address|UndefinedBehavior|Memory|Leak)Sanitizer|==\d+==ERROR: AddressSanitizer:|: runtime error:/.freeze

  # Exit code configured via ASAN_OPTIONS/UBSAN_OPTIONS exitcode=99.
  SANITIZER_EXITCODE = 99

  # Mandated sanitizer runtime options (see contract HARD CONSTRAINTS):
  #   detect_leaks=0 is MANDATORY on arm64 Darwin (otherwise every case aborts).
  #   abort_on_error=1 so reports surface as SIGABRT.
  #   exitcode=99 gives a second, signal-independent detection path.
  ASAN_OPTIONS = "detect_leaks=0:abort_on_error=1:exitcode=99:disable_coredump=1"
  UBSAN_OPTIONS = "halt_on_error=1:print_stacktrace=1:exitcode=99"

  # Map an int-overflow mode to the spinel -D define suffix.
  OVERFLOW_DEFINES = {
    "raise" => "RAISE",
    "wrap" => "WRAP",
    "promote" => "PROMOTE"
  }.freeze

  attr_reader :int_overflow, :opt_level, :supported_only

  def initialize(spinel:, ref_ruby:, runner:, spinel_dir:,
                 opt_level: 0, int_overflow: "raise",
                 sanitize: true, sanitizer_cc: "clang",
                 sanitizer_flags: "-fsanitize=address,undefined -fno-sanitize-recover=all",
                 overflow_ubsan_lane: false, supported_only: true)
    @spinel = spinel
    # ref_ruby may be a String ("ruby") or pre-split argv (["ruby"]).
    @ref_ruby = ref_ruby.is_a?(Array) ? ref_ruby : Shellwords.split(ref_ruby.to_s)
    @runner = runner
    @spinel_dir = spinel_dir
    @opt_level = opt_level
    @int_overflow = int_overflow.to_s
    @sanitize = sanitize
    @sanitizer_cc = sanitizer_cc
    @sanitizer_flags = sanitizer_flags
    @overflow_ubsan_lane = overflow_ubsan_lane
    # --supported-only (default ON): downgrade degradation-gap and
    # intentional-incompat divergences to :skip so the campaign surfaces only
    # supported-territory divergences. Turn OFF to restore the original behavior
    # (every divergence is a :fail).
    @supported_only = supported_only

    unless OVERFLOW_DEFINES.key?(@int_overflow)
      raise ArgumentError, "unknown int_overflow mode: #{@int_overflow.inspect} (known: #{OVERFLOW_DEFINES.keys.join(', ')})"
    end
  end

  # Full check: differential lane, then (unless disabled) the sanitizer lane.
  # The sanitizer lane only runs when the differential lane did NOT already skip
  # (reference failed) — a sanitizer report is meaningless when the reference
  # itself is broken.
  def check(source_path)
    verdict = diff_only(source_path)
    return verdict if verdict.status == :skip
    return verdict if verdict.status == :fail
    return verdict unless @sanitize

    clean, san_run = sanitizer_check(source_path)
    if clean
      verdict
    else
      Verdict.new(
        status: :fail,
        reason: :sanitizer_report,
        reference: verdict.reference,
        spinel: verdict.spinel,
        sanitizer: san_run,
        gap_class: verdict.gap_class
      )
    end
  end

  # Differential lane only (no sanitizer build). Used by the shrinker predicate
  # for speed.
  def diff_only(source_path)
    reference = run_reference(source_path)

    # Reference must produce a clean, reproducible baseline. If it fails, crashes,
    # or times out, we cannot soundly compare — skip.
    unless reference_baseline_ok?(reference)
      return Verdict.new(status: :skip, reason: :reference_failed, reference: reference, spinel: nil, sanitizer: nil)
    end

    spinel = run_spinel(source_path)

    reason = differential_reason(reference, spinel)
    if reason.nil?
      return Verdict.new(status: :pass, reason: :ok, reference: reference, spinel: spinel, sanitizer: nil, gap_class: nil)
    end

    # A real divergence. Classify it with the gap filter, then (when
    # --supported-only) downgrade degradation-gaps and intentional-incompats to a
    # :skip. gap_class is ALWAYS retained on the record so nothing is lost.
    source = read_source(source_path)
    gap_class = GapFilter.classify(spinel_stderr: spinel && spinel.stderr, source: source)

    if @supported_only && gap_class != :supported_divergence
      Verdict.new(status: :skip, reason: gap_class, reference: reference, spinel: spinel, sanitizer: nil, gap_class: gap_class)
    else
      Verdict.new(status: :fail, reason: reason, reference: reference, spinel: spinel, sanitizer: nil, gap_class: gap_class)
    end
  end

  def read_source(source_path)
    File.read(source_path)
  rescue StandardError
    nil
  end

  # Sanitizer lane. Returns [clean?, RunResult].
  #   clean? == true  -> no sanitizer report (RunResult may still be present)
  #   clean? == false -> RunResult.stderr holds the sanitizer report
  # Builds the .asan binary lazily; if the build itself fails, the lane is
  # treated as clean (a build failure is not a sanitizer finding — the
  # differential lane is responsible for compile-level discrepancies).
  def sanitizer_check(source_path)
    build = build_sanitizer_binary(source_path, int_overflow: @int_overflow)
    return [true, build[:run]] unless build[:ok]

    run = run_sanitizer_binary(build[:binary])
    [!self.class.sanitizer_report?(run), run]
  ensure
    FileUtils.remove_entry(build[:workdir]) if build && build[:workdir] && Dir.exist?(build[:workdir])
  end

  # Opt-in extra lane: compile with --int-overflow=wrap to surface UBSan
  # signed-overflow as findings. Returns [clean?, RunResult] like sanitizer_check.
  def overflow_ubsan_check(source_path)
    build = build_sanitizer_binary(source_path, int_overflow: "wrap")
    return [true, build[:run]] unless build[:ok]

    run = run_sanitizer_binary(build[:binary])
    [!self.class.sanitizer_report?(run), run]
  ensure
    FileUtils.remove_entry(build[:workdir]) if build && build[:workdir] && Dir.exist?(build[:workdir])
  end

  # True iff a RunResult constitutes a sanitizer report:
  #   (SIGABRT signal OR exit status == 99) AND stderr matches the marker.
  def self.sanitizer_report?(run_result)
    return false if run_result.nil?

    sig = run_result.signal
    aborted = (sig == :sigabrt) || (sig.to_s == "SIGABRT") || (sig.to_s == "ABRT")
    exit99 = run_result.status == SANITIZER_EXITCODE
    return false unless aborted || exit99

    !!(normalize_stdout(run_result.stderr.to_s) =~ SANITIZER_MARKER)
  end

  # Normalize text for stable comparison: CRLF/CR -> LF.
  def self.normalize_stdout(text)
    text.to_s.gsub(/\r\n?/, "\n")
  end

  # Parse an exception (class, message) from a RunResult, per engine.
  #   engine: :ruby   -> CRuby stderr "<file>:<n>:in '...': <msg> (<Class>)"
  #   engine: :spinel -> spinel stderr "unhandled exception: <Class>: <msg>"
  #                      (also tolerates "unhandled exception: <msg>" w/o class)
  # Returns [class_string, message_string] or nil.
  def self.parse_exception(run_result, engine)
    return nil if run_result.nil?

    stderr = normalize_stdout(run_result.stderr.to_s)
    case engine
    when :spinel
      parse_spinel_exception(stderr)
    when :ruby
      parse_ruby_exception(stderr)
    else
      raise ArgumentError, "unknown engine: #{engine.inspect}"
    end
  end

  # --- spinel exception format ------------------------------------------------
  # "unhandled exception: ZeroDivisionError: divided by 0"
  # "unhandled exception: integer overflow"   (no explicit class)
  def self.parse_spinel_exception(stderr)
    line = stderr.lines.reverse_each.find { |l| l =~ /unhandled exception:/ }
    return nil if line.nil?

    body = line.sub(/.*unhandled exception:\s*/, "").rstrip
    if (m = body.match(/\A([A-Z][A-Za-z0-9_:]*Error|[A-Z][A-Za-z0-9_:]*Exception):\s*(.*)\z/m))
      [m[1], m[2].strip]
    else
      [nil, body.strip]
    end
  end

  # --- CRuby exception format -------------------------------------------------
  # "case.rb:5:in '<main>': divided by 0 (ZeroDivisionError)"
  # (older form) "case.rb:5:in `<main>': divided by 0 (ZeroDivisionError)"
  def self.parse_ruby_exception(stderr)
    line = stderr.lines.reverse_each.find { |l| l =~ /\([A-Z][A-Za-z0-9_:]*(Error|Exception)\)\s*\z/ }
    return nil if line.nil?
    line = line.rstrip

    # Extract trailing "(<Class>)".
    cm = line.match(/\(([A-Z][A-Za-z0-9_:]*(?:Error|Exception))\)\z/)
    return nil if cm.nil?
    klass = cm[1]

    body = line[0...cm.begin(0)].rstrip

    # Strip the leading location prefix:
    #   "<file>:<line>:in '<scope>': "  (Ruby 3.4+ uses single quotes)
    #   "<file>:<line>:in `<scope>': "  (older Ruby uses backticks)
    # Fall back to stripping a bare "<file>:<line>: " prefix.
    if (pm = body.match(/\Ain\s+['`][^']*':\s*/)) ||
       (pm = body.match(/:in\s+['`][^']*':\s*/)) ||
       (pm = body.match(/\A[^:]*:\d+:in\s+['`][^']*':\s*/))
      msg = body[pm.end(0)..]
    elsif (pm = body.match(/\A[^:]*:\d+:\s*/))
      msg = body[pm.end(0)..]
    else
      msg = body
    end

    [klass, msg.to_s.strip]
  end

  private

  # ---- differential helpers --------------------------------------------------

  def reference_baseline_ok?(reference)
    return false if reference.nil?
    return false if reference.timed_out
    return false if reference.signal
    reference.status == 0
  end

  # Returns nil when reference and spinel agree, else a Symbol reason.
  def differential_reason(reference, spinel)
    return :spinel_timeout if spinel.timed_out

    # Crash-signal classification. Reference baseline never crashes (filtered),
    # so any spinel crash is a divergence.
    if spinel.signal
      return :signal_mismatch
    end

    ref_out = self.class.normalize_stdout(reference.stdout)
    sp_out = self.class.normalize_stdout(spinel.stdout)

    # Exit status comparison.
    if reference.status != spinel.status
      # Both non-zero -> compare exception class/message rather than raw codes.
      if reference.status != 0 && spinel.status && spinel.status != 0
        return exception_reason(reference, spinel) || :exit_mismatch
      end
      return :exit_mismatch
    end

    # Same exit status. If both raised (status != 0) compare exceptions.
    if reference.status != 0
      exc = exception_reason(reference, spinel)
      return exc if exc
    end

    return :stdout_mismatch if ref_out != sp_out

    nil
  end

  # Compare parsed exceptions. Returns a Symbol reason or nil (agree / unparsable).
  def exception_reason(reference, spinel)
    ref_exc = self.class.parse_exception(reference, :ruby)
    sp_exc = self.class.parse_exception(spinel, :spinel)
    return nil if ref_exc.nil? || sp_exc.nil?

    ref_class, ref_msg = ref_exc
    sp_class, sp_msg = sp_exc

    # Class mismatch only meaningful when both sides provided a class.
    if ref_class && sp_class && ref_class != sp_class
      return :exception_class_mismatch
    end

    if normalize_message(ref_msg) != normalize_message(sp_msg)
      return :exception_message_mismatch
    end

    nil
  end

  def normalize_message(msg)
    msg.to_s.strip.downcase
  end

  # ---- run helpers -----------------------------------------------------------

  def run_reference(source_path)
    @runner.run(@ref_ruby + [source_path])
  end

  def run_spinel(source_path)
    argv = [@spinel, "-O", @opt_level.to_s, "--int-overflow=#{@int_overflow}", "-E", source_path]
    @runner.run(argv)
  end

  # ---- sanitizer two-phase build ---------------------------------------------

  # Phase A: emit C with spinel (no cc). Phase B: compile with sanitizers using
  # spinel's exact include/link recipe. Returns a hash:
  #   {ok: Boolean, binary: String|nil, workdir: String, run: RunResult|nil}
  # run holds the failing phase's RunResult when ok==false.
  def build_sanitizer_binary(source_path, int_overflow:)
    define = OVERFLOW_DEFINES.fetch(int_overflow)
    workdir = Dir.mktmpdir("spinel-asan-")
    c_file = File.join(workdir, "case.c")
    bin_file = File.join(workdir, "case.asan")

    # Phase A: spinel emits C. SPINEL_INT_OVERFLOW must match the -D define used
    # in phase B, so export it during analysis.
    emit = @runner.run(
      [@spinel, "--int-overflow=#{int_overflow}", "-O", @opt_level.to_s, "-c", "-o", c_file, source_path],
      env: { "SPINEL_INT_OVERFLOW" => int_overflow }
    )
    unless emit.success? && File.exist?(c_file)
      return { ok: false, binary: nil, workdir: workdir, run: emit }
    end

    # Phase B: compile with sanitizers. Platform-correct dead-strip flag.
    gc_flag = darwin? ? "-Wl,-dead_strip" : "-Wl,--gc-sections"
    rt_lib = File.join(@spinel_dir, "lib", "libspinel_rt.a")

    cc_argv = Shellwords.split(@sanitizer_cc) + [
      "-O0", "-Wno-all", "-ffunction-sections", "-fdata-sections",
      "-I#{File.join(@spinel_dir, 'lib')}",
      "-I#{File.join(@spinel_dir, 'lib', 'regexp')}"
    ]
    cc_argv.concat(Shellwords.split(@sanitizer_flags))
    cc_argv.concat([c_file, "-lm", rt_lib, "-DSP_INT_OVERFLOW_MODE_#{define}", gc_flag, "-o", bin_file])

    compile = @runner.run(cc_argv)
    unless compile.success? && File.exist?(bin_file)
      return { ok: false, binary: nil, workdir: workdir, run: compile }
    end

    { ok: true, binary: bin_file, workdir: workdir, run: compile }
  end

  # Phase C: run the instrumented binary directly via the runner, with the
  # mandated sanitizer env and NO rlimit_as (ASan reserves multi-TB shadow VM,
  # incompatible with RLIMIT_AS).
  def run_sanitizer_binary(binary)
    @runner.run(
      [binary],
      env: { "ASAN_OPTIONS" => ASAN_OPTIONS, "UBSAN_OPTIONS" => UBSAN_OPTIONS },
      rlimit_as: false
    )
  end

  def darwin?
    RbConfig::CONFIG["host_os"] =~ /darwin/i
  end
end

# ---------------------------------------------------------------------------
# Self-test (guarded; does not run on require).
# ---------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  require "minitest/autorun" if false # avoid gem dep; hand-rolled asserts below

  failures = []
  assert = lambda do |cond, msg|
    if cond
      print "."
    else
      print "F"
      failures << msg
    end
  end

  # --- normalize_stdout -------------------------------------------------------
  assert.call(Oracle.normalize_stdout("a\r\nb\rc\n") == "a\nb\nc\n", "normalize CRLF/CR -> LF")

  # --- parse_exception (spinel) ----------------------------------------------
  FakeRun = Struct.new(:status, :stdout, :stderr, :signal, :timed_out) do
    def success?
      !timed_out && !signal && status == 0
    end
  end

  sp = FakeRun.new(1, "", "unhandled exception: ZeroDivisionError: divided by 0\n", nil, false)
  cls, msg = Oracle.parse_exception(sp, :spinel)
  assert.call(cls == "ZeroDivisionError", "spinel exc class parsed (#{cls.inspect})")
  assert.call(msg == "divided by 0", "spinel exc msg parsed (#{msg.inspect})")

  sp_noclass = FakeRun.new(1, "", "unhandled exception: integer overflow\n", nil, false)
  cls2, msg2 = Oracle.parse_exception(sp_noclass, :spinel)
  assert.call(cls2.nil?, "spinel no-class exc -> nil class (#{cls2.inspect})")
  assert.call(msg2 == "integer overflow", "spinel no-class exc msg (#{msg2.inspect})")

  # --- parse_exception (ruby) -------------------------------------------------
  rb = FakeRun.new(1, "", "case.rb:5:in '<main>': divided by 0 (ZeroDivisionError)\n", nil, false)
  rcls, rmsg = Oracle.parse_exception(rb, :ruby)
  assert.call(rcls == "ZeroDivisionError", "ruby exc class parsed (#{rcls.inspect})")
  assert.call(rmsg == "divided by 0", "ruby exc msg parsed (#{rmsg.inspect})")

  rb_legacy = FakeRun.new(1, "", "case.rb:5:in `<main>': undefined method (NoMethodError)\n", nil, false)
  lcls, _ = Oracle.parse_exception(rb_legacy, :ruby)
  assert.call(lcls == "NoMethodError", "ruby legacy backtick form (#{lcls.inspect})")

  # --- sanitizer_report? detection logic against CAPTURED sample stderr -------
  # Captured UBSan signed-overflow (wrap mode), shell-mediated SIGABRT.
  ubsan_stderr = <<~ERR
    case.c:42:7: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
    SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior case.c:42:7 in
  ERR
  ubsan_run = FakeRun.new(nil, "", ubsan_stderr, :sigabrt, false)
  assert.call(Oracle.sanitizer_report?(ubsan_run), "UBSan SIGABRT report detected (symbol form)")

  # runner.rb emits the short string name "ABRT" (no SIG prefix) — verify that form too.
  ubsan_run_str = FakeRun.new(nil, "", ubsan_stderr, "ABRT", false)
  assert.call(Oracle.sanitizer_report?(ubsan_run_str), "UBSan report detected (runner string form 'ABRT')")

  # Captured ASan stack-overflow.
  asan_stderr = <<~ERR
    ==12345==ERROR: AddressSanitizer: stack-overflow on address 0x16f603f c0
        #0 0x102a in spinel_main case.c:10
    SUMMARY: AddressSanitizer: stack-overflow case.c:10 in spinel_main
  ERR
  asan_run = FakeRun.new(nil, "", asan_stderr, :sigabrt, false)
  assert.call(Oracle.sanitizer_report?(asan_run), "ASan stack-overflow report detected")

  # Detection via exit code 99 (signal-independent path).
  asan_exit99 = FakeRun.new(99, "", asan_stderr, nil, false)
  assert.call(Oracle.sanitizer_report?(asan_exit99), "ASan exit-99 report detected")

  # NEGATIVE: raise-mode overflow -> plain exception, no marker, exit 1. Must NOT
  # be flagged as a sanitizer report (avoids false positives).
  raise_stderr = "unhandled exception: integer overflow\n"
  raise_run = FakeRun.new(1, "", raise_stderr, nil, false)
  assert.call(!Oracle.sanitizer_report?(raise_run), "raise-mode overflow NOT a sanitizer report")

  # NEGATIVE: benign clean run (exit 0).
  clean_run = FakeRun.new(0, "42\n", "", nil, false)
  assert.call(!Oracle.sanitizer_report?(clean_run), "clean run NOT a sanitizer report")

  # NEGATIVE: SIGABRT but NO marker (e.g. unrelated abort) -> not a sanitizer report.
  bare_abort = FakeRun.new(nil, "", "Abort trap: 6\n", :sigabrt, false)
  assert.call(!Oracle.sanitizer_report?(bare_abort), "bare SIGABRT w/o marker NOT a report")

  # --- differential lane against a STUB runner --------------------------------
  # Stub runner returns canned RunResults keyed by argv signature, so we exercise
  # the diff logic end-to-end without invoking real spinel/ruby/clang.
  StubRunResult = Struct.new(:argv, :status, :stdout, :stderr, :timed_out, :signal, keyword_init: true) do
    def success?
      !timed_out && !signal && status == 0
    end

    def crashed?
      !!signal
    end
  end

  class StubRunner
    def initialize(responses)
      @responses = responses
      @sanitizer_clean = true
    end

    attr_accessor :sanitizer_clean

    def run(argv, stdin: nil, env: {}, chdir: nil, rlimit_as: false)
      key =
        if argv.any? { |a| a.to_s.include?("ruby") || a.to_s == "ruby" }
          :ref
        elsif argv.first.to_s.end_with?(".asan")
          :asan
        elsif argv.include?("-c")
          :emit
        elsif Shellwords.split("clang").any? { |c| argv.first.to_s.include?(c) } && argv.include?("-fsanitize=address,undefined") || argv.any? { |a| a.to_s.include?("-fsanitize") }
          :cc
        else
          :spinel
        end
      @responses.fetch(key).call(argv)
    end
  end

  # Build an oracle whose runner is a stub. sanitize:false for pure diff tests.
  # Pass :__supported_only__ to exercise the gap filter (default ON).
  make_oracle = lambda do |responses|
    Oracle.new(
      spinel: "/fake/spinel",
      ref_ruby: "ruby",
      runner: StubRunner.new(responses),
      spinel_dir: "/fake/dir",
      sanitize: responses.fetch(:__sanitize__, false),
      supported_only: responses.fetch(:__supported_only__, true)
    )
  end

  ok_run = ->(out) { ->(a) { StubRunResult.new(argv: a, status: 0, stdout: out, stderr: "", timed_out: false, signal: nil) } }
  emit_ok = ->(a) { File.write(a[a.index("-o") + 1], "/* c */\n"); StubRunResult.new(argv: a, status: 0, stdout: "", stderr: "", timed_out: false, signal: nil) }
  cc_ok = ->(a) { File.write(a[a.index("-o") + 1], "binary"); StubRunResult.new(argv: a, status: 0, stdout: "", stderr: "", timed_out: false, signal: nil) }

  Dir.mktmpdir do |dir|
    src = File.join(dir, "case.rb")
    File.write(src, "puts 1+1\n")

    # PASS: identical stdout, exit 0.
    o = make_oracle.call({
      ref: ok_run.call("2\n"),
      spinel: ok_run.call("2\n")
    })
    v = o.diff_only(src)
    assert.call(v.status == :pass && v.reason == :ok, "diff PASS (#{v.status}/#{v.reason})")

    # SKIP: reference itself fails.
    o = make_oracle.call({
      ref: ->(a) { StubRunResult.new(argv: a, status: 1, stdout: "", stderr: "boom (StandardError)\n", timed_out: false, signal: nil) },
      spinel: ok_run.call("2\n")
    })
    v = o.diff_only(src)
    assert.call(v.status == :skip && v.reason == :reference_failed, "diff SKIP on ref fail (#{v.status}/#{v.reason})")

    # FAIL: stdout mismatch.
    o = make_oracle.call({
      ref: ok_run.call("2\n"),
      spinel: ok_run.call("3\n")
    })
    v = o.diff_only(src)
    assert.call(v.status == :fail && v.reason == :stdout_mismatch, "diff FAIL stdout_mismatch (#{v.status}/#{v.reason})")

    # FAIL: spinel timed out.
    o = make_oracle.call({
      ref: ok_run.call("2\n"),
      spinel: ->(a) { StubRunResult.new(argv: a, status: nil, stdout: "", stderr: "", timed_out: true, signal: nil) }
    })
    v = o.diff_only(src)
    assert.call(v.status == :fail && v.reason == :spinel_timeout, "diff FAIL spinel_timeout (#{v.status}/#{v.reason})")

    # FAIL: spinel crashed (signal, runner string form).
    o = make_oracle.call({
      ref: ok_run.call("2\n"),
      spinel: ->(a) { StubRunResult.new(argv: a, status: nil, stdout: "", stderr: "", timed_out: false, signal: "SEGV") }
    })
    v = o.diff_only(src)
    assert.call(v.status == :fail && v.reason == :signal_mismatch, "diff FAIL signal_mismatch (#{v.status}/#{v.reason})")

    # ===================================================================
    # GAP FILTER (--supported-only): supported divergence vs degradation-gap
    # ===================================================================

    # KEEP: SUPPORTED DIVERGENCE — spinel stderr CLEAN but stdout wrong (e.g. the
    # documented float %g formatting divergence). Filter must NOT discard it.
    wrong_output_src = File.join(dir, "wrong_output.rb")
    File.write(wrong_output_src, %(printf("%g\\n", 0.1 + 0.2)\n))
    o = make_oracle.call({
      ref: ok_run.call("0.3\n"),
      # wrong output, EMPTY stderr -> supported-territory divergence.
      spinel: ->(a) { StubRunResult.new(argv: a, status: 0, stdout: "0.300000\n", stderr: "", timed_out: false, signal: nil) }
    })
    v = o.diff_only(wrong_output_src)
    assert.call(v.status == :fail && v.reason == :stdout_mismatch && v.gap_class == :supported_divergence,
                "gap filter KEEPS supported divergence (#{v.status}/#{v.reason}/#{v.gap_class})")
    assert.call(v.supported_divergence?, "verdict.supported_divergence? true for clean-stderr wrong output")

    # DISCARD: DEGRADATION GAP — spinel WARNED "cannot resolve call ... (emitting 0)"
    # (the canonical Range#sum-style give-up). Filter downgrades it to :skip but
    # retains gap_class so the count is auditable.
    degr_src = File.join(dir, "degradation.rb")
    File.write(degr_src, "puts (1..10).sum\n")
    degr_stderr = "warning: in <main>: cannot resolve call to 'sum' on Range (emitting 0)\n"
    o = make_oracle.call({
      ref: ok_run.call("55\n"),
      spinel: ->(a) { StubRunResult.new(argv: a, status: 0, stdout: "0\n", stderr: degr_stderr, timed_out: false, signal: nil) }
    })
    v = o.diff_only(degr_src)
    assert.call(v.status == :skip && v.reason == :degradation_gap && v.gap_class == :degradation_gap,
                "gap filter DISCARDS degradation gap as skip (#{v.status}/#{v.reason}/#{v.gap_class})")

    # Same degradation case with the filter OFF (--all-divergences): becomes a
    # normal :fail again, but gap_class is still recorded for the report.
    o = make_oracle.call({
      __supported_only__: false,
      ref: ok_run.call("55\n"),
      spinel: ->(a) { StubRunResult.new(argv: a, status: 0, stdout: "0\n", stderr: degr_stderr, timed_out: false, signal: nil) }
    })
    v = o.diff_only(degr_src)
    assert.call(v.status == :fail && v.reason == :stdout_mismatch && v.gap_class == :degradation_gap,
                "filter OFF keeps degradation as fail but records gap_class (#{v.status}/#{v.reason}/#{v.gap_class})")

    # DISCARD: INTENTIONAL INCOMPAT — source hits a narrow documented-intentional
    # construct. Spinel may have clean stderr, but it is NOT a bug.
    intent_src = File.join(dir, "intentional.rb")
    File.write(intent_src, "puts 2 ** -3\n")
    o = make_oracle.call({
      ref: ok_run.call("(1/8)\n"),
      spinel: ->(a) { StubRunResult.new(argv: a, status: 0, stdout: "0\n", stderr: "", timed_out: false, signal: nil) }
    })
    v = o.diff_only(intent_src)
    assert.call(v.status == :skip && v.reason == :intentional_incompat && v.gap_class == :intentional_incompat,
                "gap filter DISCARDS intentional incompat (#{v.status}/#{v.reason}/#{v.gap_class})")

    # GapFilter.classify unit checks against captured spinel warning strings.
    assert.call(GapFilter.classify(spinel_stderr: degr_stderr, source: "puts (1..10).sum") == :degradation_gap,
                "GapFilter: cannot-resolve-call -> degradation_gap")
    assert.call(GapFilter.classify(spinel_stderr: "Spinel: cannot compile XNode at line 3 (unsupported Ruby syntax)\n", source: nil) == :degradation_gap,
                "GapFilter: unsupported Ruby syntax -> degradation_gap")
    assert.call(GapFilter.classify(spinel_stderr: "warning: call to 'f' is missing required arg #1 (x); emitting 0 (this is wrong)\n", source: nil) == :degradation_gap,
                "GapFilter: ; emitting 0 -> degradation_gap")
    assert.call(GapFilter.classify(spinel_stderr: "", source: %(printf("%g\\n", 0.3))) == :supported_divergence,
                "GapFilter: clean stderr + non-intentional source -> supported_divergence")
    assert.call(GapFilter.classify(spinel_stderr: "", source: "puts x.inspect") == :supported_divergence,
                "GapFilter: .inspect is not broadly source-filtered")
    assert.call(GapFilter.classify(spinel_stderr: "", source: "puts 2 ** -3") == :intentional_incompat,
                "GapFilter: negative-exponent ** -> intentional_incompat")
    assert.call(!GapFilter.degraded?("clean output only\n"), "GapFilter.degraded? false on clean stderr")
    assert.call(GapFilter.degraded?("warning: ... cannot resolve call to 'foo' on Integer (emitting 0)"),
                "GapFilter.degraded? true on cannot-resolve marker")

    # SKIP: reference status 1 => baseline not ok => skip (sound), never mis-report.
    o = make_oracle.call({
      ref: ->(a) { StubRunResult.new(argv: a, status: 1, stdout: "", stderr: "case.rb:1:in '<main>': divided by 0 (ZeroDivisionError)\n", timed_out: false, signal: nil) },
      spinel: ->(a) { StubRunResult.new(argv: a, status: 1, stdout: "", stderr: "unhandled exception: RuntimeError: divided by 0\n", timed_out: false, signal: nil) }
    })
    v = o.diff_only(src)
    assert.call(v.status == :skip, "diff SKIP when reference raises (#{v.status}/#{v.reason})")

    # SANITIZER lane PASS: emit ok, cc ok, asan run clean.
    o2 = make_oracle.call({
      __sanitize__: true,
      ref: ok_run.call("2\n"),
      spinel: ok_run.call("2\n"),
      emit: emit_ok,
      cc: cc_ok,
      asan: ok_run.call("2\n")
    })
    v = o2.check(src)
    assert.call(v.status == :pass, "sanitizer lane PASS on clean asan run (#{v.status}/#{v.reason})")

    # SANITIZER lane FAIL: asan run reports (runner string signal 'ABRT').
    o3 = make_oracle.call({
      __sanitize__: true,
      ref: ok_run.call("2\n"),
      spinel: ok_run.call("2\n"),
      emit: emit_ok,
      cc: cc_ok,
      asan: ->(a) { StubRunResult.new(argv: a, status: nil, stdout: "2\n", stderr: asan_stderr, timed_out: false, signal: "ABRT") }
    })
    v = o3.check(src)
    assert.call(v.status == :fail && v.reason == :sanitizer_report, "sanitizer lane FAIL on asan report (#{v.status}/#{v.reason})")

    # sanitizer_check returns [clean?, run] directly.
    clean, run = o2.sanitizer_check(src)
    assert.call(clean == true && run, "sanitizer_check clean -> [true, run]")
    bad_clean, bad_run = o3.sanitizer_check(src)
    assert.call(bad_clean == false && bad_run, "sanitizer_check report -> [false, run]")

    # Build failure (emit fails) is treated as clean (not a finding).
    o4 = make_oracle.call({
      __sanitize__: true,
      ref: ok_run.call("2\n"),
      spinel: ok_run.call("2\n"),
      emit: ->(a) { StubRunResult.new(argv: a, status: 1, stdout: "", stderr: "spinel: error\n", timed_out: false, signal: nil) },
      cc: cc_ok,
      asan: ok_run.call("")
    })
    bclean, _ = o4.sanitizer_check(src)
    assert.call(bclean == true, "sanitizer build failure treated as clean")
  end

  # --- unknown int_overflow rejected -----------------------------------------
  begin
    Oracle.new(spinel: "x", ref_ruby: "ruby", runner: Object.new, spinel_dir: "/d", int_overflow: "bogus")
    assert.call(false, "unknown int_overflow should raise")
  rescue ArgumentError
    assert.call(true, "unknown int_overflow raises ArgumentError")
  end

  puts
  if failures.empty?
    puts "oracle self-test: ALL PASS"
    exit 0
  else
    puts "oracle self-test FAILURES:"
    failures.each { |f| puts "  - #{f}" }
    exit 1
  end
end
