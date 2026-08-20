# frozen_string_literal: true

require_relative "test_helper"

class LandlockResourceUsageTest < LandlockTestCase
  def test_capture_result_new_metrics_are_optional_and_inspectable
    result = Landlock::CaptureResult.new(stdout: "out", stderr: "err", status: nil)

    assert_nil result.elapsed_seconds
    assert_nil result.resource_usage
    assert_includes result.inspect, "elapsed_seconds=nil"
    assert_includes result.inspect, "resource_usage=nil"
  end

  def test_successful_capture_exposes_elapsed_time_and_resource_usage
    skip "Landlock unsupported" unless Landlock.supported?

    result = capture_command("sleep 0.05; print 'ok'")

    assert_equal "ok", result.stdout
    assert_operator result.elapsed_seconds, :>=, 0.05
    assert_operator result.elapsed_seconds, :<, 2
    assert_operator result.resource_usage.user_seconds, :>=, 0
    assert_operator result.resource_usage.system_seconds, :>=, 0
    assert_in_delta(
      result.resource_usage.user_seconds + result.resource_usage.system_seconds,
      result.resource_usage.cpu_seconds,
      0.000001
    )
    assert_operator result.resource_usage.cpu_seconds, :>, 0
    assert_operator result.resource_usage.max_rss_bytes, :>, 1024 * 1024
    assert_predicate result.resource_usage, :frozen?
  end

  def test_capture_preserves_three_value_destructuring
    skip "Landlock unsupported" unless Landlock.supported?

    result = capture_command("$stdout.print 'out'; $stderr.print 'err'; exit 7")
    stdout, stderr, status = result

    assert_equal "out", stdout
    assert_equal "err", stderr
    assert_equal 7, status.exitstatus
    assert_kind_of Landlock::ResourceUsage, result.resource_usage
  end

  def test_capture_bang_error_exposes_complete_nonzero_result
    skip "Landlock unsupported" unless Landlock.supported?

    error = assert_raises(Landlock::CommandError) { capture_command!("exit 7") }

    assert_equal 7, error.status.exitstatus
    assert_operator error.result.elapsed_seconds, :>, 0
    assert_kind_of Landlock::ResourceUsage, error.result.resource_usage
    assert_operator error.result.resource_usage.max_rss_bytes, :>, 0
  end

  def test_signal_termination_preserves_resource_usage
    skip "Landlock unsupported" unless Landlock.supported?

    result = capture_command("Process.kill('TERM', Process.pid)")

    assert_predicate result.status, :signaled?
    assert_equal Signal.list.fetch("TERM"), result.status.termsig
    assert_operator result.elapsed_seconds, :>, 0
    assert_operator result.resource_usage.cpu_seconds, :>, 0
    assert_operator result.resource_usage.max_rss_bytes, :>, 0
  end

  def test_wall_timeout_preserves_resource_usage
    skip "Landlock unsupported" unless Landlock.supported?

    result = capture_command("loop { sleep 1 }", timeout: 0.1)

    assert_predicate result, :timed_out?
    assert_operator result.elapsed_seconds, :>=, 0.1
    assert_operator result.elapsed_seconds, :<, 0.4
    assert_kind_of Landlock::ResourceUsage, result.resource_usage
    assert_operator result.resource_usage.max_rss_bytes, :>, 0
  end

  def test_output_limit_error_preserves_resource_usage_and_partial_output
    skip "Landlock unsupported" unless Landlock.supported?

    error = assert_raises(Landlock::CommandError) { capture_command!("print 'x' * 1024", max_output_bytes: 10) }

    assert_equal "x" * 10, error.result.stdout
    assert_predicate error.result, :output_truncated?
    refute_predicate error.result, :timed_out?
    refute_predicate error.result, :success?
    assert_operator error.result.elapsed_seconds, :>, 0
    assert_kind_of Landlock::ResourceUsage, error.result.resource_usage
  end

  def test_output_limit_error_preserves_metrics_reaped_before_later_output
    skip "Landlock unsupported" unless Landlock.supported?
    skip "native runner helper unavailable" unless File.executable?(Landlock::Runner::Native.helper_path)

    [Landlock::Runner::Native, Landlock::Runner::Fork].each do |runner|
      error =
        assert_raises(Landlock::OutputTooLargeError) do
          capture_backend_result(
            runner,
            [
              RbConfig.ruby,
              "--disable=gems",
              "-e",
              "Process.fork { sleep 0.2; STDOUT.write('x' * #{Landlock::READ_CHUNK_BYTES * 2}); sleep 30 }; exit 0"
            ],
            rlimits: {
              open_files: 64
            },
            max_output_bytes: Landlock::READ_CHUNK_BYTES + 1
          )
        end
      result = error.result

      assert_predicate result.status, :success?, runner.name
      assert_kind_of Landlock::ResourceUsage, result.resource_usage, runner.name
      assert_equal Landlock::READ_CHUNK_BYTES + 1, result.stdout.bytesize, runner.name
      refute_predicate result, :timed_out?, runner.name
      refute_predicate result, :success?, runner.name
    end
  end

  def test_truncated_capture_preserves_resource_usage
    skip "Landlock unsupported" unless Landlock.supported?

    result = capture_command("print 'x' * 1024", max_output_bytes: 10, truncate_output: true)

    assert_equal "x" * 10, result.stdout
    assert_predicate result, :output_truncated?
    assert_operator result.elapsed_seconds, :>, 0
    assert_kind_of Landlock::ResourceUsage, result.resource_usage
  end

  def test_cpu_limit_preserves_resource_usage
    skip "Landlock unsupported" unless Landlock.supported?

    result = capture_command("loop {}", rlimits: { cpu_seconds: 1 }, timeout: 5)

    assert_predicate result.status, :signaled?
    assert_operator result.resource_usage.cpu_seconds, :>=, 0.5
    assert_operator result.resource_usage.max_rss_bytes, :>, 0
    assert_operator result.elapsed_seconds, :<, 5
  end

  def test_file_size_limit_preserves_resource_usage
    skip "Landlock unsupported" unless Landlock.supported?

    Dir.mktmpdir do |dir|
      output_path = File.join(dir, "output")
      result =
        Landlock.capture(
          [
            "/bin/bash",
            "-c",
            "trap - XFSZ; exec /usr/bin/dd if=/dev/zero of=\"$1\" bs=4096 count=1",
            "landlock-file-size-test",
            output_path
          ],
          read: runtime_paths + ["/dev/zero"],
          write: [dir],
          execute: runtime_paths,
          rlimits: {
            file_size_bytes: 1024
          }
        )

      assert_predicate result.status, :signaled?
      assert_equal Signal.list.fetch("XFSZ"), result.status.termsig
      assert_equal 1024, File.size(output_path)
      assert_operator result.elapsed_seconds, :>, 0
      assert_kind_of Landlock::ResourceUsage, result.resource_usage
    end
  end

  def test_concurrent_captures_keep_each_child_resource_usage_separate
    skip "Landlock unsupported" unless Landlock.supported?

    start = Queue.new
    light_thread =
      Thread.new do
        start.pop
        capture_command("sleep 0.5")
      end
    heavy_thread =
      Thread.new do
        start.pop
        capture_command(
          "payload = 'x' * (64 * 1024 * 1024); deadline = Process.clock_gettime(Process::CLOCK_PROCESS_CPUTIME_ID) + 0.3; loop { break if Process.clock_gettime(Process::CLOCK_PROCESS_CPUTIME_ID) >= deadline }; print payload.bytesize"
        )
      end
    2.times { start << true }

    light_result = light_thread.value
    heavy_result = heavy_thread.value

    assert_equal "", light_result.stdout
    assert_equal (64 * 1024 * 1024).to_s, heavy_result.stdout
    assert_operator heavy_result.resource_usage.cpu_seconds, :>, light_result.resource_usage.cpu_seconds + 0.15
    assert_operator heavy_result.resource_usage.max_rss_bytes,
                    :>,
                    light_result.resource_usage.max_rss_bytes + 16 * 1024 * 1024
    assert_operator light_result.elapsed_seconds, :<, 2
    assert_operator heavy_result.elapsed_seconds, :<, 2
  end

  def test_reaped_child_metrics_survive_timeout_draining_pipes_held_by_escaped_descendant
    skip "Landlock unsupported" unless Landlock.supported?
    skip "native runner helper unavailable" unless File.executable?(Landlock::Runner::Native.helper_path)

    [Landlock::Runner::Native, Landlock::Runner::Fork].each do |runner|
      Dir.mktmpdir do |dir|
        pidfile = File.join(dir, "escaped.pid")
        started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        result =
          capture_backend_result(
            runner,
            [
              RbConfig.ruby,
              "--disable=gems",
              "-e",
              "Process.fork { Process.setsid; File.write(ARGV.fetch(0), Process.pid); sleep 30 }; exit 0",
              pidfile
            ],
            timeout: 0.3,
            rlimits: {
              open_files: 64
            }
          )
        capture_elapsed_seconds = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at

        assert_predicate result, :timed_out?, runner.name
        assert_predicate result.status, :success?, runner.name
        assert_kind_of Landlock::ResourceUsage, result.resource_usage, runner.name
        assert_operator result.elapsed_seconds, :<, 0.3, runner.name
        assert_operator capture_elapsed_seconds, :>=, 0.3, runner.name
        assert_operator capture_elapsed_seconds, :<, 0.8, runner.name
      ensure
        kill_process_from_file(pidfile)
      end
    end
  end

  def test_native_blocking_wait_allows_other_ruby_threads_to_run
    pid = Process.spawn(RbConfig.ruby, "--disable=gems", "-e", "sleep 0.5")
    ready = Queue.new
    begin_wait = Queue.new
    ticked = Queue.new
    ticker =
      Thread.new do
        ready << true
        begin_wait.pop
        sleep 0.01
        ticked << true
      end
    ready.pop
    begin_wait << true

    status, resource_usage = Landlock::Native.wait4(pid, 0)

    assert_predicate status, :success?
    assert_kind_of Landlock::ResourceUsage, resource_usage
    assert_operator resource_usage.max_rss_bytes, :>, 1024 * 1024
    refute_predicate ticked, :empty?
  ensure
    ticker&.kill
    ticker&.join
    terminate_and_reap(pid) if pid
  end

  def test_native_blocking_wait_can_be_interrupted
    started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    pid = Process.spawn(RbConfig.ruby, "--disable=gems", "-e", "sleep 5")
    waiter = Thread.new { Landlock::Native.wait4(pid, 0) }
    sleep 0.05

    waiter.kill

    assert waiter.join(0.5)
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at, :<, 1
  ensure
    waiter&.kill
    waiter&.join
    terminate_and_reap(pid) if pid
  end

  private

  def capture_command(script, rlimits: { open_files: 64 }, **options)
    Landlock.capture(
      [RbConfig.ruby, "--disable=gems", "-e", script],
      rlimits:,
      env: {
        "PATH" => ENV.fetch("PATH", "")
      },
      unsetenv_others: true,
      **options
    )
  end

  def capture_command!(script, **options)
    Landlock.capture!(
      [RbConfig.ruby, "--disable=gems", "-e", script],
      rlimits: {
        open_files: 64
      },
      env: {
        "PATH" => ENV.fetch("PATH", "")
      },
      unsetenv_others: true,
      **options
    )
  end

  def terminate_and_reap(pid)
    Process.kill("KILL", pid)
    Process.wait(pid)
  rescue Errno::ESRCH, Errno::ECHILD
    nil
  end
end
