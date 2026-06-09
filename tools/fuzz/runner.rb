#!/usr/bin/env ruby
# frozen_string_literal: true

# Hardened subprocess execution + parallel map for the Spinel fuzzer.
#
# Pure stdlib only. No require of other fuzz modules.
#
# Design highlights:
#   * Each child runs as the leader of its own process group (Process.spawn
#     pgroup: true) so a runaway child that forks helpers can be killed wholesale
#     via Process.kill("-KILL", pgid).
#   * rlimits: RLIMIT_CPU (seconds), RLIMIT_FSIZE (bytes), RLIMIT_CORE = 0 always;
#     RLIMIT_AS only when platform == linux AND caller opts in AND it is not a
#     sanitizer run (ASan reserves multi-TB shadow VM; on Darwin rlimit_as even
#     raises Errno::EINVAL at spawn time).
#   * Per-call scratch tmpdir (Dir.mktmpdir), child chdirs into it unless an
#     explicit chdir is given; cleaned up unless :keep.
#   * stdout/stderr captured to temp FILES (not pipes) so runaway output bounded
#     by RLIMIT_FSIZE cannot deadlock on a full pipe buffer.
#   * Timeout enforced by a watchdog thread that escalates SIGTERM -> grace ->
#     SIGKILL to the whole group, then reaps with Process.wait.

require "fileutils"
require "tmpdir"
require "tempfile"
require "etc"

# Result of a single hardened child run.
#
# Back-compat with the legacy RunResult in tools/fuzz_spinel.rb: keeps
# argv/status/stdout/stderr/timed_out, and ADDS :signal (termsig name string or
# nil).
RunResult = Struct.new(
  :argv, :status, :stdout, :stderr, :timed_out, :signal,
  keyword_init: true
) do
  # Clean success: not timed out, not signalled, exit status 0.
  def success?
    !timed_out && !signal && status == 0
  end

  # True when the child died from a signal (crash).
  def crashed?
    !!signal
  end

  def to_h
    {
      "argv" => argv,
      "status" => status,
      "timed_out" => timed_out,
      "signal" => signal
    }
  end
end

class Runner
  DEFAULT_FSIZE_BYTES = 64 * 1024 * 1024

  # Map a signal number to a coarse symbol used by the oracle for crash
  # classification.
  SIGNAL_SYMBOLS = {
    "SEGV" => :sigsegv,
    "ABRT" => :sigabrt,
    "BUS"  => :sigbus,
    "KILL" => :sigkill,
    "FPE"  => :sigfpe
  }.freeze

  attr_reader :timeout, :cpu_seconds, :fsize_bytes, :address_space_bytes,
              :scratch_root, :base_env

  # timeout:             wall-clock seconds before the group is killed.
  # cpu_seconds:         RLIMIT_CPU soft/hard (defaults to nil -> derived as
  #                      ceil(timeout)+1 when not supplied so CPU spins die too).
  # fsize_bytes:         RLIMIT_FSIZE (bounds runaway output files).
  # address_space_bytes: RLIMIT_AS value used ONLY on linux + opt-in + non-sanitizer.
  # scratch_root:        parent dir for per-call scratch tmpdirs (default: system tmp).
  # env:                 base environment merged into every run.
  def initialize(timeout:, cpu_seconds: nil, fsize_bytes: DEFAULT_FSIZE_BYTES,
                 address_space_bytes: nil, scratch_root: nil, env: {})
    @timeout = timeout
    @cpu_seconds = cpu_seconds || (timeout ? timeout.ceil + 1 : nil)
    @fsize_bytes = fsize_bytes
    @address_space_bytes = address_space_bytes
    @scratch_root = scratch_root
    @base_env = env || {}
  end

  # Run argv as a hardened child and return a RunResult.
  #
  # stdin:      String fed to the child's stdin (optional).
  # env:        per-run env overrides, merged over base_env.
  # chdir:      working dir for the child; default is a fresh scratch tmpdir.
  # rlimit_as:  request RLIMIT_AS (only honored on linux + non-sanitizer below).
  #
  # Extra (non-contract) keyword:
  #   sanitizer:  when true, RLIMIT_AS is suppressed regardless of rlimit_as.
  #   keep:       keep the scratch tmpdir after the run (for triage).
  def run(argv, stdin: nil, env: {}, chdir: nil, rlimit_as: false,
          sanitizer: false, keep: false)
    argv = Array(argv).map(&:to_s)

    scratch = Dir.mktmpdir("spinel-fuzz-run-", @scratch_root)
    workdir = chdir || scratch

    out_file = File.join(scratch, "stdout.log")
    err_file = File.join(scratch, "stderr.log")
    in_file = nil

    out_io = File.open(out_file, "w")
    err_io = File.open(err_file, "w")

    spawn_opts = {
      pgroup: true,
      out: out_io,
      err: err_io,
      chdir: workdir,
      close_others: true
    }
    apply_rlimits!(spawn_opts, rlimit_as: rlimit_as, sanitizer: sanitizer)

    if stdin
      in_tmp = Tempfile.new("spinel-fuzz-stdin-", scratch)
      in_tmp.binmode
      in_tmp.write(stdin)
      in_tmp.flush
      in_tmp.rewind
      in_file = in_tmp
      spawn_opts[:in] = in_tmp
    else
      spawn_opts[:in] = File::NULL
    end

    # Default TMPDIR to this call's private scratch dir so concurrent children
    # (e.g. parallel spinel/cc invocations) do not collide on shared $TMPDIR
    # intermediate filenames. An explicit TMPDIR in base_env/env still wins.
    merged_env = @base_env.merge(env || {})
    unless merged_env.key?("TMPDIR") || merged_env.key?(:TMPDIR)
      merged_env = merged_env.merge("TMPDIR" => scratch)
    end
    full_env = stringify_env(merged_env)

    pid = nil
    timed_out = false
    wait_status = nil

    begin
      pid = Process.spawn(full_env, *argv, **spawn_opts)
    rescue SystemCallError => e
      # Spawn itself failed (e.g. Errno::EINVAL from rlimit_as on Darwin, or
      # ENOENT for a missing binary). Surface as a failed RunResult rather than
      # raising into the caller's loop.
      out_io.close unless out_io.closed?
      err_io.close unless err_io.closed?
      stderr = safe_read(err_file)
      stderr = +"" if stderr.empty?
      stderr << "spinel-runner: spawn failed: #{e.class}: #{e.message}\n"
      cleanup(scratch, in_file, keep)
      return RunResult.new(
        argv: argv, status: nil, stdout: safe_read(out_file),
        stderr: stderr, timed_out: false, signal: nil
      )
    ensure
      # Parent no longer needs its write ends; the child inherited copies.
      out_io.close unless out_io.closed?
      err_io.close unless err_io.closed?
    end

    pgid = child_pgid(pid)

    # Watchdog: wait up to @timeout, else kill the whole group.
    reaped = false
    if @timeout
      deadline = monotonic + @timeout
      loop do
        finished = Process.wait(pid, Process::WNOHANG)
        if finished
          wait_status = $?
          reaped = true
          break
        end
        break if monotonic >= deadline

        sleep_interval(deadline)
      end

      unless reaped
        timed_out = true
        self.class.kill_group(pgid)
        # Reap the (now killed) leader so we collect its status and avoid a zombie.
        begin
          Process.wait(pid)
          wait_status = $?
        rescue Errno::ECHILD
          wait_status = nil
        end
      end
    else
      Process.wait(pid)
      wait_status = $?
    end

    status, signal = interpret_status(wait_status)

    stdout = safe_read(out_file)
    stderr = safe_read(err_file)

    cleanup(scratch, in_file, keep)

    RunResult.new(
      argv: argv,
      status: status,
      stdout: stdout,
      stderr: stderr,
      timed_out: timed_out,
      signal: signal
    )
  end

  # Map items to results, optionally across a pool of forked workers.
  #
  # jobs:      pool size. jobs <= 1 -> sequential. jobs > 1 -> fork pool when
  #            fork is available, otherwise a thread pool.
  # on_result: optional callback invoked IN THE PARENT as each result arrives
  #            (in completion order, not input order). Lets the caller ingest
  #            results incrementally instead of waiting for the whole batch.
  # block:     block.call(item) -> result (must be Marshal-able for the fork path).
  #
  # Returns the results in INPUT order. Each worker gets an isolated scratch
  # namespace and a reseeded RNG (srand) so sharded generation stays reproducible
  # and workers do not share RNG state.
  def parallel_map(items, jobs:, on_result: nil, &block)
    items = items.to_a
    if jobs.nil? || jobs <= 1 || items.empty?
      return items.map.with_index do |item, i|
        result = with_worker_isolation(i) { block.call(item) }
        on_result&.call(result)
        result
      end
    end

    if fork_available?
      parallel_map_fork(items, jobs, on_result, &block)
    else
      parallel_map_threads(items, jobs, on_result, &block)
    end
  end

  # ---- class-level helpers -------------------------------------------------

  # Map a termsig integer to a coarse classification symbol.
  def self.classify_signal(termsig_int)
    return :other if termsig_int.nil?

    name = signal_name(termsig_int)
    SIGNAL_SYMBOLS.fetch(name, :other)
  end

  # Best-effort signal-number -> short name (without "SIG" prefix).
  def self.signal_name(termsig_int)
    list = Signal.list
    list.each do |name, num|
      return name if num == termsig_int
    end
    nil
  end

  # Kill an entire process group: SIGTERM, brief grace, then SIGKILL.
  # Tolerant of races where the group is already gone (Errno::ESRCH).
  def self.kill_group(pgid, term_grace_seconds: 0.5)
    return if pgid.nil?

    signal_group(pgid, "TERM")
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + term_grace_seconds
    while Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
      return unless group_alive?(pgid)

      sleep 0.02
    end
    signal_group(pgid, "KILL")
    nil
  end

  def self.signal_group(pgid, sig)
    Process.kill("-#{sig}", pgid)
  rescue Errno::ESRCH, Errno::EPERM, RangeError
    # ESRCH: group already gone. EPERM: nothing we can do. RangeError: bad pgid.
    nil
  end

  def self.group_alive?(pgid)
    # signal 0 probes existence without delivering a signal.
    Process.kill(0, -pgid)
    true
  rescue Errno::ESRCH
    false
  rescue Errno::EPERM
    true
  rescue RangeError
    false
  end

  private

  # ---- rlimits -------------------------------------------------------------

  def apply_rlimits!(spawn_opts, rlimit_as:, sanitizer:)
    # RLIMIT_CPU is a CPU-time backstop for runaway loops, but on Darwin it is
    # broken: the kernel delivers SIGXCPU almost immediately to any child that
    # sleeps/blocks, regardless of the limit value — so a *hanging* program (the
    # exact case the wall-clock watchdog exists for) gets misclassified as a
    # SIGXCPU crash instead of a clean timeout. Apply it only on Linux, where it
    # works; elsewhere the wall watchdog (below, in #run) is the timeout
    # mechanism and still group-kills CPU-bound runaways.
    if @cpu_seconds && defined?(Process::RLIMIT_CPU) && linux?
      cpu = @cpu_seconds.to_i
      spawn_opts[:rlimit_cpu] = [cpu, cpu]
    end

    if @fsize_bytes && defined?(Process::RLIMIT_FSIZE)
      f = @fsize_bytes.to_i
      spawn_opts[:rlimit_fsize] = [f, f]
    end

    if defined?(Process::RLIMIT_CORE)
      spawn_opts[:rlimit_core] = [0, 0]
    end

    # RLIMIT_AS is incompatible with ASan (multi-TB shadow VM) and on Darwin the
    # spawn itself raises Errno::EINVAL. Honor it only on linux, only when the
    # caller opts in, and never for sanitizer runs.
    if rlimit_as && !sanitizer && @address_space_bytes && linux? &&
       defined?(Process::RLIMIT_AS)
      as = @address_space_bytes.to_i
      spawn_opts[:rlimit_as] = [as, as]
    end
  end

  def linux?
    self.class.linux?
  end

  def self.linux?
    RbConfig::CONFIG["host_os"] =~ /linux/i ? true : false
  end

  # ---- status / io ---------------------------------------------------------

  def interpret_status(wait_status)
    return [nil, nil] if wait_status.nil?

    if wait_status.signaled?
      name = self.class.signal_name(wait_status.termsig)
      [nil, name]
    else
      [wait_status.exitstatus, nil]
    end
  end

  def child_pgid(pid)
    # The child was spawned with pgroup: true, so its pgid == its pid. Confirm
    # via getpgid where available, falling back to pid.
    Process.getpgid(pid)
  rescue Errno::ESRCH, NotImplementedError
    pid
  end

  def safe_read(path)
    File.binread(path).to_s
  rescue SystemCallError
    +""
  end

  def cleanup(scratch, in_file, keep)
    begin
      in_file&.close
      in_file&.unlink
    rescue StandardError
      nil
    end
    return if keep

    FileUtils.remove_entry(scratch)
  rescue StandardError
    nil
  end

  def monotonic
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  def sleep_interval(deadline)
    remaining = deadline - monotonic
    return if remaining <= 0

    # Poll reasonably often but never sleep so long we badly overshoot a short
    # timeout.
    sleep([0.05, remaining].min)
  end

  # ---- parallel map internals ---------------------------------------------

  def fork_available?
    Process.respond_to?(:fork) && !RbConfig::CONFIG["host_os"].match?(/mswin|mingw/i)
  end

  def with_worker_isolation(index)
    # Reseed so each item/worker has a distinct, deterministic RNG stream keyed
    # by its index; restore afterwards so we do not perturb the caller globally.
    previous = srand(derive_seed(index))
    begin
      yield
    ensure
      srand(previous)
    end
  end

  def derive_seed(index)
    # Stable, index-derived seed. Callers that need full reproducibility
    # re-derive their own case seed (e.g. Generator.replay); this only isolates
    # incidental RNG use inside a worker.
    (0x9E3779B97F4A7C15 * (index + 1)) & ((1 << 62) - 1)
  end

  def parallel_map_threads(items, jobs, on_result, &block)
    results = Array.new(items.length)
    queue = (0...items.length).to_a
    mutex = Mutex.new

    workers = Array.new([jobs, items.length].min) do
      Thread.new do
        loop do
          idx = mutex.synchronize { queue.shift }
          break if idx.nil?

          value = with_worker_isolation(idx) { block.call(items[idx]) }
          # Serialize result delivery so on_result (parent-side ingest) never
          # runs concurrently with itself.
          mutex.synchronize do
            results[idx] = value
            on_result&.call(value)
          end
        end
      end
    end
    workers.each(&:join)
    results
  end

  def parallel_map_fork(items, jobs, on_result, &block)
    results = Array.new(items.length)
    pool_size = [jobs, items.length].min

    # Static round-robin sharding keeps generation deterministic and avoids any
    # shared-queue IPC: worker w handles indices w, w+pool_size, ...
    #
    # Each worker STREAMS one length-framed [idx, value] message per item as soon
    # as it is computed (rather than buffering the whole shard and writing once at
    # exit). A reader thread per pipe drains messages into a shared queue, so the
    # parent (a) ingests results incrementally via on_result and (b) never blocks
    # a producing worker on a full pipe buffer while serially reading another --
    # the deadlock/serialization that made --jobs effectively single-threaded.
    pipes = []
    pids = []

    (0...pool_size).each do |worker|
      reader, writer = IO.pipe
      pid = Process.fork do
        reader.close
        writer.binmode
        idx = worker
        while idx < items.length
          value =
            begin
              with_worker_isolation(idx) { block.call(items[idx]) }
            rescue StandardError => e
              # Propagate a structured error placeholder rather than killing the
              # whole map; the parent re-raises after draining.
              WorkerError.new(e.class.name, e.message)
            end
          write_frame(writer, Marshal.dump([idx, value]))
          idx += pool_size
        end
        writer.close
        # Use exit! to skip at_exit hooks / buffered IO of the parent runtime.
        exit!(0)
      end
      writer.close
      pipes << reader
      pids << pid
    end

    # One reader thread per pipe keeps every worker's pipe drained concurrently.
    # Decoded [idx, value] pairs land on a queue; the main thread applies them
    # (and runs on_result) so ingest never runs concurrently with itself.
    queue = Queue.new
    readers = pipes.map do |reader|
      Thread.new do
        while (data = read_frame(reader))
          queue << Marshal.load(data)
        end
      ensure
        reader.close
      end
    end

    delivered = 0
    while delivered < items.length
      idx, value = queue.pop
      results[idx] = value
      on_result&.call(value) unless value.is_a?(WorkerError)
      delivered += 1
    end

    readers.each(&:join)
    pids.each { |pid| Process.wait(pid) rescue Errno::ECHILD }

    results.each_with_index do |value, idx|
      raise StandardError, "worker error at #{idx}: #{value.klass}: #{value.message}" if value.is_a?(WorkerError)
    end

    results
  end

  # Length-framed message IO over a pipe: 4-byte big-endian length prefix then
  # the payload. Framing lets the parent read discrete per-result messages off a
  # stream instead of one terminal blob.
  def write_frame(io, data)
    io.write([data.bytesize].pack("N"))
    io.write(data)
    io.flush
  end

  # Read one framed message, or nil at clean EOF. On a blocking pipe IO#read(n)
  # returns fewer than n bytes only at EOF, so a short/empty header means done.
  def read_frame(io)
    header = io.read(4)
    return nil if header.nil? || header.bytesize < 4

    len = header.unpack1("N")
    return "".b if len.zero?

    body = io.read(len)
    return nil if body.nil? || body.bytesize < len

    body
  end

  # Marshal-able carrier for an exception raised inside a forked worker.
  WorkerError = Struct.new(:klass, :message)

  def stringify_env(env)
    out = {}
    env.each { |k, v| out[k.to_s] = v.nil? ? nil : v.to_s }
    out
  end
end

# --------------------------------------------------------------------------
# Self-test (only runs when executed directly, never on require).
# --------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  require "rbconfig"

  failures = []
  check = lambda do |name, ok|
    puts "#{ok ? 'ok  ' : 'FAIL'} - #{name}"
    failures << name unless ok
  end

  ruby = RbConfig.ruby

  # 1) A quick child that exits 0 and prints to stdout.
  r = Runner.new(timeout: 10)
  res = r.run([ruby, "-e", "STDOUT.print 'hello'; STDOUT.flush"])
  check.call("quick child success?", res.success?)
  check.call("quick child status 0", res.status == 0)
  check.call("quick child stdout captured", res.stdout.include?("hello"))
  check.call("quick child not crashed", !res.crashed?)
  check.call("quick child to_h shape", res.to_h.keys.sort == %w[argv signal status timed_out])

  # stdin plumbing
  res_in = r.run([ruby, "-e", "STDOUT.print STDIN.read"], stdin: "piped-in")
  check.call("stdin forwarded", res_in.stdout.include?("piped-in"))

  # env plumbing
  res_env = r.run([ruby, "-e", "STDOUT.print ENV.fetch('SPINEL_FUZZ_X','MISSING')"], env: { "SPINEL_FUZZ_X" => "yes" })
  check.call("env forwarded", res_env.stdout.include?("yes"))

  # 2) A sleeper that must be killed by the timeout (and its whole group).
  rt = Runner.new(timeout: 3)
  t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  # Child forks a grandchild sleeper to prove group-kill: both must die.
  sleeper = <<~RB
    STDOUT.sync = true
    pid = fork { sleep 60 }
    STDOUT.puts pid
    sleep 60
  RB
  res_sleep = rt.run([ruby, "-e", sleeper])
  dt = Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0
  check.call("sleeper timed_out flagged", res_sleep.timed_out)
  check.call("sleeper killed promptly (<6s)", dt < 6.0)
  # Verify the grandchild was reaped by the group kill (no lingering pid).
  grandchild = res_sleep.stdout.strip.to_i
  if grandchild.positive?
    sleep 0.3
    alive =
      begin
        Process.kill(0, grandchild)
        true
      rescue Errno::ESRCH
        false
      rescue Errno::EPERM
        true
      end
    check.call("grandchild killed by group kill", !alive)
  else
    check.call("grandchild pid reported", false)
  end

  # 3) A child that exceeds an rlimit (RLIMIT_FSIZE) -> dies via SIGXFSZ.
  rf = Runner.new(timeout: 20, fsize_bytes: 4096)
  big = <<~RB
    f = File.open('big.bin', 'w')
    buf = 'x' * 65536
    loop { f.write(buf); f.flush }
  RB
  res_fsize = rf.run([ruby, "-e", big])
  # The child should die from SIGXFSZ (or, on some platforms, an IOError exit).
  # Either way it must NOT be a clean success and the limit must have bitten.
  check.call("fsize-limited child not clean success", !res_fsize.success?)
  check.call("fsize-limited child terminated by signal or nonzero",
             res_fsize.crashed? || (res_fsize.status && res_fsize.status != 0))

  # 4) A CPU spinner must be killed promptly and never reported as success.
  # On Linux RLIMIT_CPU (cpu_seconds:1) fires SIGXCPU within the CPU budget; on
  # Darwin (RLIMIT_CPU disabled — see apply_rlimits!) the wall watchdog kills it
  # via group SIGKILL. A short wall timeout bounds both paths to <=2s.
  rc = Runner.new(timeout: 2, cpu_seconds: 1)
  spin = "i = 0; loop { i += 1 }"
  res_cpu = rc.run([ruby, "-e", spin])
  check.call("cpu-limited spinner not clean success", !res_cpu.success?)
  check.call("cpu-limited spinner killed (signal or timeout)", res_cpu.crashed? || res_cpu.timed_out)

  # 5) classify_signal mapping.
  segv = Signal.list["SEGV"]
  abrt = Signal.list["ABRT"]
  check.call("classify SEGV", Runner.classify_signal(segv) == :sigsegv)
  check.call("classify ABRT", Runner.classify_signal(abrt) == :sigabrt)
  check.call("classify nil -> other", Runner.classify_signal(nil) == :other)

  # 6) parallel_map preserves order and runs the block per item.
  pm = Runner.new(timeout: 10)
  squares = pm.parallel_map((1..7).to_a, jobs: 3) { |n| n * n }
  check.call("parallel_map fork order/values", squares == [1, 4, 9, 16, 25, 36, 49])
  # jobs:1 sequential path
  seq = pm.parallel_map((1..4).to_a, jobs: 1) { |n| n + 100 }
  check.call("parallel_map sequential", seq == [101, 102, 103, 104])
  # thread fallback path exercised directly
  thr = pm.send(:parallel_map_threads, (1..5).to_a, 2, nil) { |n| n * 10 }
  check.call("parallel_map threads order/values", thr == [10, 20, 30, 40, 50])

  # 6b) on_result streams every result to the parent (fork path), exactly once.
  streamed = []
  smutex = Mutex.new
  fork_results = pm.parallel_map((1..20).to_a, jobs: 4, on_result: ->(v) { smutex.synchronize { streamed << v } }) { |n| n * 2 }
  check.call("on_result fork: ordered return", fork_results == (1..20).map { |n| n * 2 })
  check.call("on_result fork: streamed all once", streamed.sort == (1..20).map { |n| n * 2 })
  # 6c) on_result streams on the thread path too.
  streamed_t = []
  tmutex = Mutex.new
  pm.send(:parallel_map_threads, (1..6).to_a, 3, ->(v) { tmutex.synchronize { streamed_t << v } }) { |n| n + 1 }
  check.call("on_result threads: streamed all once", streamed_t.sort == (2..7).to_a)
  # 6d) a worker error placeholder is NOT streamed and DOES raise on return.
  raised = false
  begin
    pm.parallel_map((1..4).to_a, jobs: 2, on_result: ->(v) { raise "should not see error placeholder" if v.is_a?(Runner::WorkerError) }) do |n|
      raise "boom-#{n}" if n == 3

      n
    end
  rescue StandardError => e
    raised = e.message.include?("worker error")
  end
  check.call("worker error raised, not streamed", raised)

  # 7) crashed child surfaces signal (SIGSEGV via Process.kill self).
  rcrash = Runner.new(timeout: 10)
  res_crash = rcrash.run([ruby, "-e", "Process.kill('SEGV', Process.pid); sleep 5"])
  check.call("crashed child reports signal", res_crash.crashed?)
  check.call("crashed child classifies", %i[sigsegv sigabrt sigbus].include?(Runner.classify_signal(Signal.list[res_crash.signal])) || res_crash.signal == "SEGV")

  puts
  if failures.empty?
    puts "SELFTEST OK (all checks passed)"
    exit 0
  else
    puts "SELFTEST FAILED: #{failures.join(', ')}"
    exit 1
  end
end
