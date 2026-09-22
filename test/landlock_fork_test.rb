# frozen_string_literal: true

require_relative "test_helper"

class LandlockForkTest < LandlockTestCase
  def test_fork_raises_when_landlock_is_unsupported_by_default
    Landlock.stub(:abi_version, 0) do
      assert_raises(Landlock::UnsupportedError) { Landlock.fork(rlimits: { open_files: 64 }) { print "unreachable" } }
    end
  end

  def test_fork_runs_without_landlock_when_explicitly_requested
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

  def test_fork_fallback_rejects_landlock_only_policy
    Landlock.stub(:abi_version, 0) do
      error =
        assert_raises(ArgumentError) do
          Landlock.fork(on_unsupported: :run_without_landlock, read: []) { print "unreachable" }
        end

      assert_equal "Landlock fallback requires seccomp_deny_network, seccomp_deny_child_processes, or rlimits",
                   error.message
    end
  end

  def test_fork_fallback_enforces_timeout
    probe = -> { raise Landlock::SyscallError.new("landlock_create_ruleset", Errno::EPERM::Errno) }

    Landlock.stub(:abi_version, probe) do
      result =
        Landlock.fork(on_unsupported: :run_without_landlock, timeout: 0.01, rlimits: { open_files: 64 }) { sleep 30 }

      assert_predicate result, :timed_out?
      refute_predicate result, :success?
    end
  end

  def test_fork_fallback_applies_seccomp
    skip "Landlock fallback is Linux-only" if RUBY_PLATFORM !~ /linux/

    probe = -> { raise Landlock::SyscallError.new("landlock_create_ruleset", Errno::EPERM::Errno) }

    Landlock.stub(:abi_version, probe) do
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

  def test_fork_fallback_enforces_output_limit
    Landlock.stub(:abi_version, 0) do
      error =
        assert_raises(Landlock::CommandError) do
          Landlock.fork(on_unsupported: :run_without_landlock, rlimits: { open_files: 32 }, max_output_bytes: 4) do
            print "output"
          end
        end

      assert_equal "outp", error.stdout
      assert_predicate error.result, :output_truncated?
    end
  end

  def test_fork_rejects_an_invalid_on_unsupported_value
    error =
      assert_raises(ArgumentError) do
        Landlock.fork(on_unsupported: :ignore, rlimits: { open_files: 64 }) { print "unreachable" }
      end

    assert_equal "on_unsupported must be :raise or :run_without_landlock", error.message
  end

  def test_fork_fallback_rejects_seccomp_on_non_linux
    skip "Non-Linux behavior" if RUBY_PLATFORM.include?("linux")

    Landlock.stub(:abi_version, 0) do
      assert_raises(Landlock::UnsupportedError) do
        Landlock.fork(on_unsupported: :run_without_landlock, seccomp_deny_network: true, rlimits: { open_files: 64 }) do
          print "unreachable"
        end
      end
    end
  end

  def test_fork_runs_with_execution_controls_when_the_abi_probe_raises
    probe = -> { raise Landlock::SyscallError.new("landlock_create_ruleset", Errno::EPERM::Errno) }
    reader, writer = IO.pipe

    Landlock.stub(:abi_version, probe) do
      result =
        Landlock.fork(
          on_unsupported: :run_without_landlock,
          read: [],
          paths: [{ path: __FILE__, rights: [:read_file] }],
          env: {
            LANDLOCK_FALLBACK: "child"
          },
          unsetenv_others: true,
          stdin: "input",
          rlimits: {
            open_files: 32
          },
          timeout: 1,
          max_output_bytes: 100
        ) do
          print [ENV.fetch("LANDLOCK_FALLBACK"), STDIN.read, Process.getrlimit(:NOFILE).first, writer.closed?].join(":")
          warn "captured"
        end

      assert_equal "child:input:32:true", result.stdout
      assert_equal "captured\n", result.stderr
      assert_predicate result, :success?
    end
  ensure
    reader&.close
    writer&.close
  end

  def test_fork_raises_by_default_when_the_abi_probe_raises
    probe = -> { raise Landlock::SyscallError.new("landlock_create_ruleset", Errno::EPERM::Errno) }

    Landlock.stub(:abi_version, probe) do
      assert_raises(Landlock::UnsupportedError) { Landlock.fork(rlimits: { open_files: 32 }) { print "unreachable" } }
    end
  end

  def test_fork_does_not_fallback_when_policy_application_fails
    failure = ->(**) { raise Landlock::SyscallError.new("landlock_restrict_self", Errno::EPERM::Errno) }
    result = nil

    Landlock.stub(:abi_version, 1) do
      Landlock.stub(:restrict!, failure) do
        result =
          Landlock.fork(on_unsupported: :run_without_landlock, read: [], rlimits: { open_files: 32 }) do
            print "unreachable"
          end
      end
    end

    assert_equal 127, result.status.exitstatus
    assert_empty result.stdout
    assert_match(/landlock_restrict_self/, result.stderr)
    refute_predicate result, :success?
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

  def test_fork_preserves_system_exit_status
    skip "Landlock unsupported" unless Landlock.supported?

    [0, 7].each do |exit_status|
      result = Landlock.fork(rlimits: { open_files: 64 }) { exit exit_status }

      assert_predicate result.status, :exited?
      assert_equal exit_status, result.status.exitstatus
      assert_equal exit_status.zero?, result.success?
      assert_empty result.stderr
    end
  end

  def test_fork_preserves_signal_status
    skip "Landlock unsupported" unless Landlock.supported?

    result =
      Landlock.fork(rlimits: { open_files: 64 }) do
        Process.kill("TERM", Process.pid)
        sleep 1
      end

    assert_predicate result.status, :signaled?
    assert_equal Signal.list.fetch("TERM"), result.status.termsig
    assert_empty result.stderr
    refute_predicate result, :success?
  end

  def test_fork_captures_block_errors_when_global_stderr_is_reassigned
    skip "Landlock unsupported" unless Landlock.supported?

    original_stderr = $stderr
    replacement_stderr = StringIO.new
    result =
      begin
        $stderr = replacement_stderr
        Landlock.fork(rlimits: { open_files: 64 }) { raise "failed" }
      ensure
        $stderr = original_stderr
      end

    assert_equal 1, result.status.exitstatus
    assert_equal "Landlock forked block failed: RuntimeError: failed\n", result.stderr
    assert_empty replacement_stderr.string
  end

  def test_fork_captures_child_bootstrap_errors
    skip "Landlock unsupported" unless Landlock.supported?

    result = nil
    Landlock::Native.stub(:arm_parent_death_process_group!, ->(*) { raise "bootstrap failed" }) do
      result = Landlock.fork(rlimits: { open_files: 64 }) { print "unreachable" }
    end

    assert_equal 127, result.status.exitstatus
    assert_equal "Landlock child setup failed: RuntimeError: bootstrap failed\n", result.stderr
    refute_predicate result, :success?
  end

  def test_fork_timeout_during_child_bootstrap_preserves_signal_status
    skip "Landlock unsupported" unless Landlock.supported?

    slow_setup = ->(**) { sleep 30 }
    result = nil
    Landlock::Runner::Fork.stub(:prepare_forked_block!, slow_setup) do
      result = Landlock.fork(timeout: 0.01, rlimits: { open_files: 64 }) { raise "unreachable" }
    end

    assert_predicate result, :timed_out?
    assert_predicate result.status, :signaled?
    assert_equal Signal.list.fetch("TERM"), result.status.termsig
    assert_empty result.stderr
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
    assert_predicate result.status, :signaled?
    assert_equal Signal.list.fetch("TERM"), result.status.termsig
    assert_empty result.stderr
    refute_predicate result, :success?
  end

  def test_fork_child_exits_with_its_parent
    skip "Landlock unsupported" unless Landlock.supported?

    supervisor_pid = nil
    child_pid = nil
    Dir.mktmpdir do |directory|
      pid_path = File.join(directory, "child.pid")
      supervisor_pid =
        fork do
          Landlock.fork(write: [directory]) do
            File.write("#{pid_path}.tmp", Process.pid)
            File.rename("#{pid_path}.tmp", pid_path)
            sleep 30
          end
        end

      child_pid =
        Timeout.timeout(2) do
          loop do
            break Integer(File.read(pid_path)) if File.size?(pid_path)

            sleep 0.01
          end
        end
      Process.kill("KILL", supervisor_pid)
      Process.waitpid(supervisor_pid)
      supervisor_pid = nil

      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 1
      sleep 0.01 while process_alive?(child_pid) && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline

      refute process_alive?(child_pid)
      child_pid = nil
    end
  ensure
    kill_process_if_alive(supervisor_pid) if supervisor_pid
    kill_process_if_alive(child_pid) if child_pid
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
      Landlock.fork(read: []) do
        IO.for_fd(fd, autoclose: false).stat
        print "open"
      rescue Errno::EBADF
        print "closed"
      end

    assert_equal "closed", result.stdout
    assert_predicate result, :success?
  ensure
    Landlock::Native.close_fd(fd) if fd
  end

  def test_fork_fallback_closes_inherited_raw_file_descriptors
    fd = IO.sysopen(File::NULL)
    result = nil
    Landlock.stub(:abi_version, 0) do
      result =
        Landlock.fork(on_unsupported: :run_without_landlock, rlimits: { open_files: 64 }) do
          IO.for_fd(fd, autoclose: false).stat
          print "open"
        rescue Errno::EBADF
          print "closed"
        end
    end

    assert_equal "closed", result.stdout
    assert_predicate result, :success?
  ensure
    Landlock::Native.close_fd(fd) if fd
  end

  def test_fork_fails_closed_when_procfs_cannot_be_read
    skip "Landlock unsupported" unless Landlock.supported?

    Dir.mktmpdir do |allowed_directory|
      reader, writer = IO.pipe
      pid =
        fork do
          reader.close
          Landlock.restrict!(read: [allowed_directory])
          result = Landlock.fork(rlimits: { open_files: 64 }) { print "unreachable" }
          writer.write(result.stderr)
          exit! result.status.exitstatus
        end
      writer.close

      stderr = reader.read
      _, status = Process.wait2(pid)

      assert_includes stderr, "opendir(/proc/self/fd) failed:"
      assert_equal 127, status.exitstatus
    ensure
      reader&.close
      writer&.close unless writer&.closed?
    end
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

  def test_fork_denies_fork_when_seccomp_deny_child_processes_is_true
    skip "Landlock unsupported" unless Landlock.supported?
    with_syscall_program(syscall: "fork") do |executable|
      result = Landlock.fork(seccomp_deny_child_processes: true) { exec(executable) }
      skip "fork syscall unavailable on this architecture" if result.status.exitstatus == 77
      assert result.success?, result.inspect
    end
  end

  def test_fork_denies_vfork_when_seccomp_deny_child_processes_is_true
    skip "Landlock unsupported" unless Landlock.supported?
    with_syscall_program(syscall: "vfork") do |executable|
      result = Landlock.fork(seccomp_deny_child_processes: true) { exec(executable) }
      skip "vfork syscall unavailable on this architecture" if result.status.exitstatus == 77
      assert result.success?, result.inspect
    end
  end

  def test_fork_denies_clone_when_seccomp_deny_child_processes_is_true
    skip "Landlock unsupported" unless Landlock.supported?
    with_syscall_program(syscall: "clone", arguments: "SIGCHLD, NULL, NULL, NULL, 0") do |executable|
      result = Landlock.fork(seccomp_deny_child_processes: true) { exec(executable) }
      skip "clone syscall unavailable on this architecture" if result.status.exitstatus == 77
      assert result.success?, result.inspect
    end
  end

  def test_fork_returns_enosys_for_clone3_when_seccomp_deny_child_processes_is_true
    skip "Landlock unsupported" unless Landlock.supported?
    with_syscall_program(syscall: "clone3", arguments: "NULL, 0", expected_errno: "ENOSYS") do |executable|
      result = Landlock.fork(seccomp_deny_child_processes: true) { exec(executable) }
      skip "clone3 syscall unavailable on this architecture" if result.status.exitstatus == 77
      assert result.success?, result.inspect
    end
  end

  def test_fork_allows_threads_when_seccomp_deny_child_processes_is_true
    skip "Landlock unsupported" unless Landlock.supported?
    result = Landlock.fork(seccomp_deny_child_processes: true) { Thread.new { puts "thread" }.join }

    assert result.success?, result.inspect
    assert_equal "thread\n", result.stdout
  end

  def test_fork_denies_fork_from_threads_when_seccomp_deny_child_processes_is_true
    skip "Landlock unsupported" unless Landlock.supported?
    result =
      Landlock.fork(seccomp_deny_child_processes: true) do
        Thread
          .new do
            begin
              child = Process.fork { exit! 0 }
              Process.wait(child)
            rescue Errno::EPERM
              puts "denied"
            end
          end
          .join
      end

    assert result.success?, result.inspect
    assert_equal "denied\n", result.stdout
  end

  def test_fork_does_not_run_when_child_process_filter_installation_fails
    skip "Landlock unsupported" unless Landlock.supported?
    failure = -> { raise Landlock::SyscallError.new("seccomp", Errno::EPERM::Errno) }

    result =
      Landlock::Native.stub(:seccomp_deny_child_processes!, failure) do
        Landlock.fork(seccomp_deny_child_processes: true) { puts "must not run" }
      end

    refute result.success?
    assert_empty result.stdout
    assert_match(/seccomp/, result.stderr)
  end

  def test_fork_rejects_seccomp_deny_child_processes_on_non_linux
    skip "non-Linux required" if RUBY_PLATFORM.include?("linux")
    assert_raises(Landlock::UnsupportedError) do
      Landlock.fork(on_unsupported: :run_without_landlock, seccomp_deny_child_processes: true) { flunk "must not run" }
    end
  end

  def test_fork_allows_child_processes_when_seccomp_deny_child_processes_is_omitted
    result =
      Landlock.fork(on_unsupported: :run_without_landlock, rlimits: { open_files: 64 }) do
        child = Process.fork { puts "child" }
        Process.wait(child)
      end
    assert result.success?, result.inspect
    assert_equal "child\n", result.stdout
  end

  def test_fork_allows_child_processes_when_seccomp_deny_child_processes_is_false
    result =
      Landlock.fork(
        on_unsupported: :run_without_landlock,
        rlimits: {
          open_files: 64
        },
        seccomp_deny_child_processes: false
      ) do
        child = Process.fork { puts "child" }
        Process.wait(child)
      end
    assert result.success?, result.inspect
    assert_equal "child\n", result.stdout
  end

  private

  def process_alive?(pid)
    Process.kill(0, pid)
    !File.read("/proc/#{pid}/stat").split.fetch(2).eql?("Z")
  rescue Errno::ESRCH, Errno::ENOENT
    false
  end
end
