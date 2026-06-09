#!/usr/bin/env ruby
# frozen_string_literal: true

# Post-run classifier for saved fuzz artifacts.
#
# Reads case-* directories from a tools/fuzz_spinel.rb run and summarizes the
# persisted verdicts into review buckets. This is intentionally conservative: the
# main oracle finds divergences, while this script helps decide which artifacts
# are issue-ready, gap documentation, robustness failures, or reference skips.

require "json"
require "optparse"

require_relative "oracle"

BUCKETS = %w[
  supported_divergence
  markerless_build_failure
  robustness_crash_or_sanitizer
  degradation_gap
  intentional_incompat
  reference_failed
  pass_or_unknown
].freeze

# spinelgems interop (additive, opt-in via --spinelgems). Maps each of our review
# buckets to the spinelgems {verdict, reason} pair we would emit for it, using
# their vocabulary (rejected/clean/risky/loaded/verified + reason strings). See
# spinel-diff-fuzz-notes/spinelgems-alignment.md and Capabilities::SPINELGEMS_VERDICT.
# nil => no spinelgems finding emitted for that bucket (not a divergence, or no
# equivalent in their model — e.g. intentional_incompat, pass_or_unknown).
BUCKET_SPINELGEMS_VERDICT = {
  "supported_divergence"          => { verdict: "rejected", reason: "miscompile" },
  "markerless_build_failure"      => { verdict: "rejected", reason: "build-or-run-error" },
  "robustness_crash_or_sanitizer" => { verdict: "rejected", reason: "build-or-run-error" },
  "degradation_gap"               => { verdict: "rejected", reason: "unresolved" },
  "intentional_incompat"          => nil,
  "reference_failed"              => nil,
  "pass_or_unknown"               => nil
}.freeze

def read_json(path)
  JSON.parse(File.read(path))
rescue JSON::ParserError
  nil
end

def read_file(path)
  File.file?(path) ? File.read(path) : ""
end

def enrich_run(case_dir, name, data)
  run = (data || {}).dup
  stdout = read_file(File.join(case_dir, "#{name}.stdout"))
  stderr = read_file(File.join(case_dir, "#{name}.stderr"))
  run["stdout"] = stdout unless stdout.empty?
  run["stderr"] = stderr unless stderr.empty?
  run
end

def source_for(case_dir)
  min = File.join(case_dir, "min.rb")
  return File.read(min) if File.file?(min)

  read_file(File.join(case_dir, "case.rb"))
end

def nonzero_empty_output?(run)
  return false unless run
  return true if run["status"].nil? && !run["signal"].nil?

  run["status"].to_i != 0 && run["stdout"].to_s.empty?
end

def robustness?(reason, spinel, sanitizer)
  return true if reason == "sanitizer_report"
  return true if reason == "spinel_timeout"
  return true if spinel && (spinel["timed_out"] || spinel["signal"])
  return true if sanitizer && (sanitizer["timed_out"] || sanitizer["signal"])

  false
end

def classify_case(case_dir, meta)
  source = source_for(case_dir)
  reason = (meta["reason"] || meta["skip"]).to_s
  persisted_gap = meta["gap_class"].to_s
  spinel = enrich_run(case_dir, "spinel", meta["spinel"])
  sanitizer = enrich_run(case_dir, "sanitizer", meta["sanitizer"])
  spinel_stderr = spinel["stderr"].to_s

  return "reference_failed" if reason == "reference_failed"
  return persisted_gap if %w[degradation_gap intentional_incompat].include?(persisted_gap)
  return "degradation_gap" if GapFilter.degraded?(spinel_stderr)
  return "intentional_incompat" if GapFilter.intentional?(source)
  return "robustness_crash_or_sanitizer" if robustness?(reason, spinel, sanitizer)
  return "markerless_build_failure" if nonzero_empty_output?(spinel)
  return "supported_divergence" if persisted_gap == "supported_divergence"
  return "supported_divergence" unless reason.empty? || reason == "ok"

  "pass_or_unknown"
end

# Build a spinelgems-shaped finding record for a surfaced case, or nil when the
# bucket maps to no spinelgems finding. Shape follows their test-results.jsonl
# (gem/program, version, rev, result, verdict, note) with a `provenance` tag so a
# folded finding stays distinguishable from a gem-sourced one. `rev` is the Spinel
# engine revision stamped into meta.json at run time by fuzz_spinel.rb
# (git:<sha>[+dirty]/<arch-os>); nil only for legacy runs predating the stamp.
def spinelgems_record(case_dir, meta, bucket)
  mapped = BUCKET_SPINELGEMS_VERDICT.fetch(bucket, nil)
  return nil if mapped.nil?

  reason = (meta["reason"] || meta["skip"]).to_s
  note = mapped[:reason].dup
  note << "; #{reason}" unless reason.empty? || reason == mapped[:reason]
  {
    "program" => meta["case"] || File.basename(case_dir),
    "version" => nil,
    "rev" => meta["spinel_rev"],
    "result" => "fail",
    "verdict" => mapped[:verdict],
    "reason" => mapped[:reason],
    "note" => note,
    "gap_class" => meta["gap_class"].to_s,
    "provenance" => "spinel-diff-fuzz",
    "probe" => "diff",
    "case_dir" => case_dir
  }
end

options = {
  json: false,
  limit: 5,
  spinelgems: false
}

parser = OptionParser.new do |opts|
  opts.banner = "Usage: ruby tools/fuzz/classify_run.rb [options] RUN_DIR"
  opts.on("--json", "Emit JSON only") { options[:json] = true }
  opts.on("--limit N", Integer, "Sample paths per bucket (default 5)") { |value| options[:limit] = value }
  opts.on("--spinelgems", "Emit spinelgems-shaped finding records (JSONL) instead of the summary") { options[:spinelgems] = true }
end
parser.parse!

run_dir = ARGV.shift
unless run_dir && File.directory?(run_dir)
  warn parser
  exit 2
end

cases = Dir.glob(File.join(run_dir, "case-*", "meta.json")).sort
summary = BUCKETS.to_h { |bucket| [bucket, 0] }
samples = BUCKETS.to_h { |bucket| [bucket, []] }
records = []
spinelgems_records = []

cases.each do |meta_path|
  case_dir = File.dirname(meta_path)
  meta = read_json(meta_path)
  next unless meta

  bucket = classify_case(case_dir, meta)
  summary[bucket] ||= 0
  samples[bucket] ||= []
  summary[bucket] += 1
  samples[bucket] << case_dir if samples[bucket].length < options[:limit]
  records << {
    "case_dir" => case_dir,
    "bucket" => bucket,
    "reason" => (meta["reason"] || meta["skip"]).to_s,
    "gap_class" => meta["gap_class"].to_s,
    "case" => meta["case"]
  }
  if options[:spinelgems] && (rec = spinelgems_record(case_dir, meta, bucket))
    spinelgems_records << rec
  end
end

# --spinelgems: emit one JSONL finding per surfaced case, in spinelgems'
# vocabulary, and nothing else. Default behaviour (summary / --json) is untouched.
if options[:spinelgems]
  spinelgems_records.each { |rec| puts JSON.generate(rec) }
  exit 0
end

payload = {
  "run_dir" => run_dir,
  "cases" => cases.length,
  "summary" => summary.select { |_, count| count.positive? },
  "samples" => samples.select { |_, paths| paths.any? },
  "records" => records
}

if options[:json]
  puts JSON.pretty_generate(payload)
else
  puts "Run: #{run_dir}"
  puts "Cases with metadata: #{cases.length}"
  puts
  payload.fetch("summary").sort_by { |bucket, count| [-count, bucket] }.each do |bucket, count|
    puts "#{count}\t#{bucket}"
    payload.fetch("samples").fetch(bucket, []).each { |path| puts "  #{path}" }
  end
end
