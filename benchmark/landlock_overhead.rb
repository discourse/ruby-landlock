# frozen_string_literal: true

require "json"
require "rbconfig"
require "tmpdir"
require "fileutils"
require "open3"

root = File.expand_path("..", __dir__)
lib_dir = File.join(root, "lib")
ext_lib_dir = File.join(lib_dir, "landlock")

$LOAD_PATH.unshift(lib_dir)
$LOAD_PATH.unshift(ext_lib_dir)

require "landlock"

module LandlockBench
  ROOT = File.expand_path("..", __dir__)
  DEFAULT_SAMPLES = Integer(ENV.fetch("SAMPLES", 7))
  DEFAULT_ITERATIONS = Integer(ENV.fetch("ITERATIONS", 25_000))
  DIR_ITERATIONS = Integer(ENV.fetch("DIR_ITERATIONS", 2_000))
  SETUP_SAMPLES = Integer(ENV.fetch("SETUP_SAMPLES", 25))

  WORKLOADS = [
    ["cpu_loop", "integer arithmetic loop"],
    ["file_stat", "File.stat on an allowed file"],
    ["file_read", "File.binread of a small allowed file"],
    ["dir_scan", "Dir.foreach over an allowed directory"]
  ].freeze

  module_function

  def monotonic_ns
    Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
  end

  def measure
    started = monotonic_ns
    yield
    monotonic_ns - started
  end

  def runtime_paths
    [
      File.dirname(RbConfig.ruby),
      RbConfig::CONFIG["libdir"],
      RbConfig::CONFIG["archlibdir"],
      "/usr",
      "/lib",
      "/lib64",
      "/etc"
    ].compact.uniq.select { |path| File.exist?(path) }
  end

  def prepare_workspace
    Dir.mktmpdir("landlock-bench") do |dir|
      file = File.join(dir, "small.txt")
      entries = File.join(dir, "entries")
      Dir.mkdir(entries)
      File.binwrite(file, "x" * 1024)
      100.times { |index| File.binwrite(File.join(entries, "entry-#{index}.txt"), "x") }

      yield({ "dir" => dir, "file" => file, "entries" => entries })
    end
  end

  def child_command(payload)
    [RbConfig.ruby, __FILE__, "--child", JSON.generate(payload)]
  end

  def run_child(payload)
    stdout, stderr, status = Open3.capture3(*child_command(payload), chdir: ROOT)
    unless status.success?
      abort "bench child failed (#{status.exitstatus})\nSTDOUT:\n#{stdout}\nSTDERR:\n#{stderr}"
    end

    JSON.parse(stdout)
  end

  def run_parent
    puts "Landlock performance benchmark"
    puts "Ruby: #{RUBY_DESCRIPTION}"
    puts "Landlock ABI: #{Landlock.abi_version}"
    puts "Samples: #{DEFAULT_SAMPLES}, iterations: #{DEFAULT_ITERATIONS}"
    puts

    prepare_workspace do |workspace|
      read_paths = (runtime_paths + [workspace.fetch("dir")]).uniq
      common = {
        mode: "workloads",
        iterations: DEFAULT_ITERATIONS,
        dir_iterations: DIR_ITERATIONS,
        read_paths: read_paths,
        workspace: workspace
      }

      baseline = collect_samples(DEFAULT_SAMPLES) { run_child(common.merge(sandbox: false)) }

      unless Landlock.supported?
        puts "Landlock is not supported on this host; only baseline timings were collected."
        print_workload_table(baseline, nil)
        return
      end

      sandbox = collect_samples(DEFAULT_SAMPLES) { run_child(common.merge(sandbox: true)) }
      setup = collect_samples(SETUP_SAMPLES) do
        run_child(mode: "setup", read_paths: read_paths).fetch("setup_ns")
      end

      print_workload_table(baseline, sandbox)
      puts
      puts "Setup cost (create ruleset, add read rules, restrict current process):"
      puts "  median #{format_ms(median(setup))} (#{SETUP_SAMPLES} samples)"
      puts
      puts "Lower is better. Negative deltas mean the sandboxed sample was faster in this run."
      puts "Expect small differences to be noise; compare medians across repeated runs."
    end
  end

  def collect_samples(count)
    Array.new(count) { yield }
  end

  def print_workload_table(baseline, sandbox)
    puts format("%-12s %14s %14s %12s %10s", "workload", "baseline", "landlocked", "delta", "delta %")
    puts "-" * 68

    WORKLOADS.each do |name, description|
      base = median(baseline.map { |sample| sample.fetch(name) })
      if sandbox
        locked = median(sandbox.map { |sample| sample.fetch(name) })
        delta = locked - base
        pct = base.positive? ? (delta.to_f / base * 100.0) : 0.0
        puts format(
          "%-12s %14s %14s %12s %9.2f%%",
          name,
          format_ms(base),
          format_ms(locked),
          format_ms(delta),
          pct
        )
      else
        puts format("%-12s %14s %14s %12s %10s", name, format_ms(base), "n/a", "n/a", "n/a")
      end
      puts "  #{description}"
    end
  end

  def median(values)
    sorted = values.sort
    midpoint = sorted.length / 2
    return sorted.fetch(midpoint) if sorted.length.odd?

    (sorted.fetch(midpoint - 1) + sorted.fetch(midpoint)) / 2.0
  end

  def format_ms(ns)
    format("%.3f ms", ns.to_f / 1_000_000.0)
  end

  def run_child_mode(payload)
    case payload.fetch("mode")
    when "setup"
      puts JSON.generate("setup_ns" => measure { restrict_for(payload) })
    when "workloads"
      restrict_for(payload) if payload.fetch("sandbox")
      puts JSON.generate(run_workloads(payload))
    else
      raise ArgumentError, "unknown child mode: #{payload.fetch("mode").inspect}"
    end
  end

  def restrict_for(payload)
    Landlock.restrict!(read: payload.fetch("read_paths"))
  end

  def run_workloads(payload)
    iterations = Integer(payload.fetch("iterations"))
    dir_iterations = Integer(payload.fetch("dir_iterations"))
    workspace = payload.fetch("workspace")
    file = workspace.fetch("file")
    entries = workspace.fetch("entries")
    sink = 0

    GC.disable
    {
      "cpu_loop" => measure do
        iterations.times { |index| sink ^= ((index * 31) & 0xffff) }
      end,
      "file_stat" => measure do
        iterations.times { sink ^= File.stat(file).size }
      end,
      "file_read" => measure do
        iterations.times { sink ^= File.binread(file).bytesize }
      end,
      "dir_scan" => measure do
        dir_iterations.times do
          Dir.foreach(entries) { |entry| sink ^= entry.bytesize }
        end
      end
    }.merge("sink" => sink)
  ensure
    GC.enable
  end
end

if ARGV.first == "--child"
  LandlockBench.run_child_mode(JSON.parse(ARGV.fetch(1)))
else
  LandlockBench.run_parent
end
