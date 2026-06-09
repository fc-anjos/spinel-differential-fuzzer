#!/usr/bin/env ruby
# frozen_string_literal: true

# Cross-optimization lane for the standalone Spinel fuzzer.
#
# This compares Spinel against itself at -O0/-O2/-O3 after first establishing a
# clean CRuby baseline. It is intentionally separate from the main CRuby-vs-Spinel
# differential lane: a finding here means Spinel behavior changes with optimizer
# level while the case is clean of self-announced degradation markers.

require "fileutils"
require "json"
require "optparse"
require "shellwords"
require "tmpdir"

require_relative "generator"
require_relative "oracle"
require_relative "runner"

ROOT = File.expand_path("../..", __dir__)
DEFAULT_SPINEL = File.join(ROOT, "vendor", "spinel", "spinel")
OPTS = %w[0 2 3].freeze

def normalize(text)
  Oracle.normalize_stdout(text.to_s)
end

def result_hash(result)
  return nil if result.nil?

  {
    "argv" => result.argv,
    "status" => result.status,
    "stdout" => result.stdout.to_s,
    "stderr" => result.stderr.to_s,
    "timed_out" => result.timed_out,
    "signal" => result.signal
  }
end

def reference_ok?(result)
  result && !result.timed_out && !result.signal && result.status == 0
end

def run_signature(run)
  return ["missing"] if run.nil?
  return ["timeout"] if run.timed_out
  return ["signal", run.signal] if run.signal

  ["run", run.status, normalize(run.stdout)]
end

def opt_signature(entry)
  compile = entry.fetch(:compile)
  return ["compile_timeout"] if compile.timed_out
  return ["compile_signal", compile.signal] if compile.signal
  return ["compile_fail", compile.status, normalize(compile.stdout)] unless compile.success? && entry[:run]

  run_signature(entry[:run])
end

def run_matches_ref?(run, reference)
  return false if run.nil? || run.timed_out || run.signal

  run.status == reference.status && normalize(run.stdout) == normalize(reference.stdout)
end

def finding_kind(entries, reference)
  compile_successes = entries.values.map { |entry| entry[:compile].success? }.uniq
  return "opt_dependent_build_failure" if compile_successes.length > 1

  matches = entries.values.map { |entry| run_matches_ref?(entry[:run], reference) }
  return "optimizer_regression" if matches.any? && !matches.all?

  "cross_opt_inconsistent"
end

options = {
  seed: 3002,
  cases: 500,
  out: File.join(ROOT, "tmp", "cross-opt"),
  spinel: DEFAULT_SPINEL,
  ref_ruby: ENV.fetch("REF_RUBY", "ruby"),
  int_overflow: "raise",
  timeout: 15,
  families: nil,
  exclude_families: [],
  mode: :typed,
  stop_after: nil
}

OptionParser.new do |parser|
  parser.banner = "Usage: ruby tools/fuzz/cross_opt.rb [options]"
  parser.on("--seed N", Integer, "Top-level random seed") { |value| options[:seed] = value }
  parser.on("--cases N", Integer, "Number of generated cases") { |value| options[:cases] = value }
  parser.on("--out DIR", "Output directory") { |value| options[:out] = value }
  parser.on("--spinel PATH", "Path to spinel executable") { |value| options[:spinel] = value }
  parser.on("--ref-ruby CMD", "Reference Ruby command") { |value| options[:ref_ruby] = value }
  parser.on("--int-overflow MODE", "Int overflow mode: raise|wrap|promote") { |value| options[:int_overflow] = value }
  parser.on("--timeout SEC", Integer, "Per-command timeout") { |value| options[:timeout] = value }
  parser.on("--families LIST", "Comma-separated family allow-list") { |value| options[:families] = value }
  parser.on("--exclude-family NAME", "Family to exclude; may be repeated") { |value| options[:exclude_families] << value }
  parser.on("--templates", "Use legacy template families") { options[:mode] = :templates }
  parser.on("--stop-after N", Integer, "Stop after N findings") { |value| options[:stop_after] = value }
end.parse!

FileUtils.mkdir_p(options[:out])
runner = Runner.new(
  timeout: options[:timeout],
  cpu_seconds: [options[:timeout] * 4, options[:timeout] + 30].max,
  fsize_bytes: Runner::DEFAULT_FSIZE_BYTES
)
ref_ruby = Shellwords.split(options[:ref_ruby])

summary = {
  "seed" => options[:seed],
  "cases" => options[:cases],
  "generated" => 0,
  "reference_skipped" => 0,
  "stable" => 0,
  "filtered_degradation_gap" => 0,
  "filtered_intentional_incompat" => 0,
  "findings" => 0,
  "findings_by_kind" => Hash.new(0),
  "errors" => []
}
findings = []
stop = false

(0...options[:cases]).each do |index|
  generated =
    begin
      Generator.replay(
        options[:seed],
        index,
        families: options[:families],
        exclude_families: options[:exclude_families],
        mode: options[:mode]
      )
    rescue StandardError => e
      summary["errors"] << "replay #{index}: #{e.class}: #{e.message}"
      next
    end

  summary["generated"] += 1

  Dir.mktmpdir("spinel-cross-opt-") do |dir|
    source_path = File.join(dir, "case.rb")
    File.write(source_path, generated.source)

    reference = runner.run(ref_ruby + [source_path])
    unless reference_ok?(reference)
      summary["reference_skipped"] += 1
      next
    end

    entries = {}
    OPTS.each do |opt|
      bin_path = File.join(dir, "case-O#{opt}")
      compile = runner.run([
        options[:spinel],
        "-O", opt,
        "--int-overflow=#{options[:int_overflow]}",
        "-o", bin_path,
        source_path
      ])
      run = compile.success? && File.exist?(bin_path) ? runner.run([bin_path]) : nil
      entries[opt] = { compile: compile, run: run }
    end

    combined_stderr = entries.values.map do |entry|
      [entry[:compile]&.stderr, entry[:run]&.stderr].compact.join("\n")
    end.join("\n")

    if GapFilter.degraded?(combined_stderr)
      summary["filtered_degradation_gap"] += 1
      next
    end

    if GapFilter.intentional?(generated.source)
      summary["filtered_intentional_incompat"] += 1
      next
    end

    signatures = OPTS.map { |opt| opt_signature(entries.fetch(opt)) }
    if signatures.uniq.length == 1
      summary["stable"] += 1
      next
    end

    kind = finding_kind(entries, reference)
    out_base = "case-%06d-%s-%s" % [index, generated.family, kind]
    saved_source = File.join(options[:out], "#{out_base}.rb")
    saved_json = File.join(options[:out], "#{out_base}.json")

    record = {
      "index" => index,
      "family" => generated.family.to_s,
      "kind" => kind,
      "source" => generated.source,
      "source_path" => saved_source,
      "reference" => result_hash(reference),
      "by_opt" => OPTS.to_h do |opt|
        entry = entries.fetch(opt)
        [
          opt,
          {
            "signature" => opt_signature(entry),
            "matches_ref" => run_matches_ref?(entry[:run], reference),
            "compile" => result_hash(entry[:compile]),
            "run" => result_hash(entry[:run])
          }
        ]
      end
    }

    File.write(saved_source, generated.source.end_with?("\n") ? generated.source : "#{generated.source}\n")
    File.write(saved_json, "#{JSON.pretty_generate(record)}\n")
    findings << record
    summary["findings"] += 1
    summary["findings_by_kind"][kind] += 1
    stop = true if options[:stop_after] && summary["findings"] >= options[:stop_after]
  end
  break if stop
rescue StandardError => e
  summary["errors"] << "case #{index}: #{e.class}: #{e.message}"
end

summary["findings_by_kind"] = summary["findings_by_kind"].sort.to_h
File.write(
  File.join(options[:out], "cross_opt_findings.json"),
  "#{JSON.pretty_generate({ "summary" => summary, "findings" => findings })}\n"
)
puts JSON.pretty_generate(summary)
