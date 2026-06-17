# frozen_string_literal: true

require "minitest/autorun"
require "tmpdir"
require "rbconfig"
require "socket"
require "English"
require "open3"
require "stringio"
require "timeout"
require "landlock"

class LandlockTestCase < Minitest::Test
  private

  def assert_capture_backends_equivalent(name, argv:, **options)
    native = capture_backend_result(Landlock::Runner::Native, argv, **options)
    forked = capture_backend_result(Landlock::Runner::Fork, argv, **options)

    assert_equal forked.stdout, native.stdout, "#{name}: stdout"
    assert_equal forked.stderr, native.stderr, "#{name}: stderr"
    assert_equal forked.status.exitstatus, native.status.exitstatus, "#{name}: exitstatus"
    if forked.status.termsig.nil?
      assert_nil native.status.termsig, "#{name}: termsig"
    else
      assert_equal forked.status.termsig, native.status.termsig, "#{name}: termsig"
    end
    assert_equal forked.success?, native.success?, "#{name}: success"
    assert_equal forked.timed_out?, native.timed_out?, "#{name}: timed_out"
    assert_equal forked.output_truncated?, native.output_truncated?, "#{name}: output_truncated"
  end

  def capture_backend_result(runner, argv, **options)
    defaults = {
      read: [],
      write: [],
      execute: [],
      connect_tcp: [],
      bind_tcp: [],
      paths: [],
      scope: [],
      chdir: nil,
      env: nil,
      unsetenv_others: false,
      close_others: true,
      allow_all_known: false,
      timeout: nil,
      stdin: nil,
      rlimits: nil,
      seccomp_deny_network: false,
      max_output_bytes: nil,
      truncate_output: false
    }.merge(options)
    defaults[:rlimits] = Landlock::Rlimits.normalize(defaults[:rlimits])
    defaults[:connect_tcp] = Landlock::Validation.normalize_ports(defaults[:connect_tcp], :connect_tcp)
    defaults[:bind_tcp] = Landlock::Validation.normalize_ports(defaults[:bind_tcp], :bind_tcp)

    runner.call(argv.map(&:to_s), **defaults)
  end

  def root
    File.expand_path("..", __dir__)
  end

  def free_port
    s = TCPServer.new("127.0.0.1", 0)
    s.addr[1]
  ensure
    s&.close
  end

  def kill_process_from_file(path)
    return unless path && File.exist?(path)

    kill_process_if_alive(Integer(File.read(path)))
  rescue ArgumentError
    nil
  end

  def kill_process_if_alive(pid)
    Process.kill("KILL", pid)
    Process.wait(pid, Process::WNOHANG)
  rescue Errno::ESRCH, Errno::ECHILD
    nil
  end

  def refute_process_alive(pid)
    if File.exist?("/proc/#{pid}/stat")
      state = File.read("/proc/#{pid}/stat").split.fetch(2)
      return if state == "Z"
    end

    Process.kill(0, pid)
    Process.kill("KILL", pid)
    flunk "process #{pid} survived timeout process-group kill"
  rescue Errno::ESRCH
    nil
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

  def non_stdio_pipe
    reader, writer = IO.pipe
    while writer.fileno <= 3
      next_writer = writer.dup
      writer.close
      writer = next_writer
    end
    writer.close_on_exec = false
    [reader, writer]
  end
end
