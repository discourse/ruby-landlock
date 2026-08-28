# frozen_string_literal: true

require_relative "test_helper"

class LandlockForkTest < LandlockTestCase
  def test_fork_raises_when_landlock_is_unsupported_by_default
    Landlock.stub(:abi_version, 0) do
      assert_raises(Landlock::UnsupportedError) { Landlock.fork(rlimits: { open_files: 64 }) { print "unreachable" } }
    end
  end

  def test_fork_runs_without_landlock_when_explicitly_requested
    skip "Landlock fallback is Linux-only" if RUBY_PLATFORM !~ /linux/

    Dir.mktmpdir do |directory|
      path = File.join(directory, "secret")
      File.write(path, "secret")

      Landlock.stub(:abi_version, 0) do
        result =
          Landlock.fork(
            on_unsupported: :run_without_landlock,
            read: [],
            write: [],
            timeout: 1,
            env: {
              "LANDLOCK_FORK_FALLBACK" => "enabled"
            },
            rlimits: {
              open_files: 32
            }
          ) { print [File.read(path), ENV.fetch("LANDLOCK_FORK_FALLBACK"), Process.getrlimit(:NOFILE).first].join(":") }

        assert_equal "secret:enabled:32", result.stdout
        assert_predicate result, :success?
      end
    end
  end

  def test_fork_fallback_enforces_timeout
    skip "Landlock fallback is Linux-only" if RUBY_PLATFORM !~ /linux/

    Landlock.stub(:abi_version, 0) do
      result =
        Landlock.fork(on_unsupported: :run_without_landlock, timeout: 0.01, rlimits: { open_files: 64 }) { sleep 30 }

      assert_predicate result, :timed_out?
      refute_predicate result, :success?
    end
  end

  def test_fork_fallback_applies_seccomp
    skip "Landlock fallback is Linux-only" if RUBY_PLATFORM !~ /linux/

    Landlock.stub(:abi_version, 0) do
      result =
        Landlock.fork(on_unsupported: :run_without_landlock, seccomp_deny_network: true) do
          Socket.new(:INET, :STREAM)
        rescue Errno::EPERM
          print "denied"
        end

      assert_equal "denied", result.stdout
      assert_predicate result, :success?
    end
  end

  def test_fork_rejects_an_invalid_on_unsupported_value
    error =
      assert_raises(ArgumentError) do
        Landlock.fork(on_unsupported: :ignore, rlimits: { open_files: 64 }) { print "unreachable" }
      end

    assert_equal "on_unsupported must be :raise or :run_without_landlock", error.message
  end

  def test_fork_does_not_fallback_on_non_linux
    skip "Non-Linux behavior" if RUBY_PLATFORM.include?("linux")

    Landlock.stub(:abi_version, 0) do
      assert_raises(Landlock::UnsupportedError) do
        Landlock.fork(on_unsupported: :run_without_landlock, rlimits: { open_files: 64 }) { print "unreachable" }
      end
    end
  end

  def test_fork_captures_an_inherited_ruby_block
    skip "Landlock unsupported" unless Landlock.supported?

    inherited = "ready"
    result =
      Landlock.fork(rlimits: { open_files: 64 }) do |stdout, stderr|
        stdout.print inherited
        stderr.puts "warning"
      end

    assert_equal "ready", result.stdout
    assert_equal "warning\n", result.stderr
    assert_predicate result, :success?
  end

  def test_fork_returns_block_errors
    skip "Landlock unsupported" unless Landlock.supported?

    result = Landlock.fork(rlimits: { open_files: 64 }) { raise "failed" }

    assert_equal 1, result.status.exitstatus
    assert_match(/RuntimeError: failed/, result.stderr)
    refute_predicate result, :success?
  end

  def test_fork_discards_the_block_return_value
    skip "Landlock unsupported" unless Landlock.supported?

    result = Landlock.fork(rlimits: { open_files: 64 }) { Object.new }

    assert_empty result.stdout
    assert_predicate result, :success?
  end

  def test_fork_enforces_timeout
    skip "Landlock unsupported" unless Landlock.supported?

    result = Landlock.fork(timeout: 0.01, rlimits: { open_files: 64 }) { sleep 30 }

    assert_predicate result, :timed_out?
    refute_predicate result, :success?
  end

  def test_fork_child_exits_with_its_parent
    skip "Landlock unsupported" unless Landlock.supported?

    Dir.mktmpdir do |directory|
      pid_path = File.join(directory, "child.pid")
      supervisor_pid =
        fork do
          Landlock.fork(write: [directory]) do
            File.write(pid_path, Process.pid)
            sleep 30
          end
        end

      sleep 0.01 until File.exist?(pid_path)
      child_pid = Integer(File.read(pid_path))
      Process.kill("KILL", supervisor_pid)
      Process.waitpid(supervisor_pid)

      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 1
      sleep 0.01 while process_alive?(child_pid) && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline

      refute process_alive?(child_pid)
    end
  end

  def test_fork_descendants_exit_with_their_supervisor
    skip "Landlock unsupported" unless Landlock.supported?

    supervisor_pid = nil
    descendant_pid = nil

    Dir.mktmpdir do |directory|
      pid_path = File.join(directory, "descendant.pid")
      fork_options = { write: [directory], close_others: false }
      fork_options[:scope] = [:signal] if Landlock.abi_version >= 6
      supervisor_pid =
        fork do
          Landlock.fork(**fork_options) do
            # A nested Ruby fork needs the runtime descriptors inherited by the worker.
            fork do
              contents = [Process.pid, Process.ppid, Process.getpgrp].join(":")
              File.write("#{pid_path}.tmp", contents)
              File.rename("#{pid_path}.tmp", pid_path)
              sleep 30
            end
            sleep 30
          end
        end

      descendant_pid, worker_pid, process_group =
        Timeout.timeout(2) do
          loop do
            break File.read(pid_path).split(":").map { |value| Integer(value) } if File.size?(pid_path)

            sleep 0.01
          end
        end

      assert_equal worker_pid, process_group, "descendant did not inherit the worker process group"

      Process.kill("KILL", supervisor_pid)
      Process.waitpid(supervisor_pid)
      supervisor_pid = nil

      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 1
      sleep 0.01 while process_alive?(descendant_pid) && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline

      refute process_alive?(descendant_pid), "forked descendant survived its supervisor"
    end
  ensure
    kill_process_if_alive(supervisor_pid) if supervisor_pid
    kill_process_if_alive(descendant_pid) if descendant_pid
  end

  def test_fork_applies_the_filesystem_policy
    skip "Landlock unsupported" unless Landlock.supported?

    Dir.mktmpdir do |directory|
      path = File.join(directory, "secret")
      File.write(path, "secret")

      result = Landlock.fork(read: [], write: []) { File.read(path) }

      assert_equal 1, result.status.exitstatus
      assert_match(/Errno::EACCES/, result.stderr)
    end
  end

  def test_fork_applies_process_options
    skip "Landlock unsupported" unless Landlock.supported?

    Dir.mktmpdir do |directory|
      result =
        Landlock.fork(
          chdir: directory,
          env: {
            LANDLOCK_FORK: "child"
          },
          unsetenv_others: true,
          stdin: "input",
          rlimits: {
            open_files: 32
          }
        ) { print [Dir.pwd, ENV.fetch("LANDLOCK_FORK"), STDIN.read, Process.getrlimit(:NOFILE).first].join(":") }

      assert_equal "#{directory}:child:input:32", result.stdout
      assert_predicate result, :success?
    end
  end

  def test_fork_closes_inherited_io
    skip "Landlock unsupported" unless Landlock.supported?

    reader, writer = IO.pipe
    result = Landlock.fork(rlimits: { open_files: 64 }) { print writer.closed? }

    assert_equal "true", result.stdout
  ensure
    reader&.close
    writer&.close
  end

  def test_fork_closes_inherited_raw_file_descriptors
    skip "Landlock unsupported" unless Landlock.supported?

    fd = IO.sysopen(File::NULL)
    result =
      Landlock.fork(rlimits: { open_files: 64 }) do
        IO.for_fd(fd, autoclose: false).stat
        print "open"
      rescue Errno::EBADF
        print "closed"
      end

    assert_equal "closed", result.stdout
  ensure
    Landlock::Native.close_fd(fd) if fd
  end

  def test_fork_enforces_output_limit
    skip "Landlock unsupported" unless Landlock.supported?

    error =
      assert_raises(Landlock::CommandError) do
        Landlock.fork(rlimits: { open_files: 64 }, max_output_bytes: 4) { print "output" }
      end

    assert_equal "outp", error.stdout
    assert_predicate error.result, :output_truncated?
  end

  def test_fork_requires_a_block
    error = assert_raises(ArgumentError) { Landlock.fork(rlimits: { open_files: 64 }) }

    assert_equal "fork requires a block", error.message
  end

  private

  def process_alive?(pid)
    Process.kill(0, pid)
    !File.read("/proc/#{pid}/stat").split.fetch(2).eql?("Z")
  rescue Errno::ESRCH, Errno::ENOENT
    false
  end
end
