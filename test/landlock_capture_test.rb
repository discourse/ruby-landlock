# frozen_string_literal: true

require_relative "test_helper"

class LandlockCaptureTest < LandlockTestCase
  def test_capture_returns_stdout_stderr_and_status
    skip "Landlock unsupported" unless Landlock.supported?

    result =
      Landlock.capture(
        [RbConfig.ruby, "--disable=gems", "-e", "$stdout.print 'ok'; $stderr.print 'warn'"],
        read: runtime_paths,
        execute: runtime_paths,
        env: {
          "PATH" => ENV.fetch("PATH", "")
        },
        unsetenv_others: true
      )

    assert_equal "ok", result.stdout
    assert_equal "warn", result.stderr
    assert result.status.success?
  end

  def test_capture_bang_raises_and_exposes_output_and_status
    skip "Landlock unsupported" unless Landlock.supported?

    error =
      assert_raises(Landlock::CommandError) do
        Landlock.capture!(
          [RbConfig.ruby, "--disable=gems", "-e", "$stdout.print 'out'; $stderr.print 'err'; exit 7"],
          read: runtime_paths,
          execute: runtime_paths,
          env: {
            "PATH" => ENV.fetch("PATH", "")
          },
          unsetenv_others: true
        )
      end

    assert_equal "out", error.stdout
    assert_equal "err", error.stderr
    assert_equal 7, error.status.exitstatus
    refute error.result.success?
  end

  def test_capture_enforces_output_limit
    skip "Landlock unsupported" unless Landlock.supported?

    error =
      assert_raises(Landlock::CommandError) do
        Landlock.capture(
          [RbConfig.ruby, "--disable=gems", "-e", "print 'x' * 1024"],
          read: runtime_paths,
          execute: runtime_paths,
          env: {
            "PATH" => ENV.fetch("PATH", "")
          },
          unsetenv_others: true,
          max_output_bytes: 10
        )
      end

    assert_match(/exceeded 10 bytes/, error.message)
    assert_equal "x" * 10, error.stdout
    assert error.result.output_truncated?
  end

  def test_capture_rejects_invalid_timeout_before_launch
    skip "Landlock unsupported" unless Landlock.supported?

    Dir.mktmpdir do |dir|
      marker = File.join(dir, "ran")

      assert_raises(ArgumentError) do
        Landlock.capture(
          [RbConfig.ruby, "--disable=gems", "-e", "File.write(ARGV.fetch(0), 'ran')", marker],
          rlimits: {
            open_files: 64
          },
          timeout: "1"
        )
      end

      refute_path_exists marker
    end
  end

  def test_capture_does_not_false_timeout_after_streams_close
    skip "Landlock unsupported" unless Landlock.supported?

    started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    result =
      Landlock.capture(
        [RbConfig.ruby, "--disable=gems", "-e", "STDOUT.close; STDERR.close; sleep 0.1; exit 0"],
        rlimits: {
          open_files: 64
        },
        timeout: 2
      )
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at

    assert_operator elapsed, :<, 1
    assert_equal 0, result.status.exitstatus
    refute result.timed_out?
  end

  def test_capture_waits_for_child_exit_without_polling_after_streams_close
    skip "Landlock unsupported" unless Landlock.supported?

    result = nil
    Landlock::ProcessIO.stub(:sleep, ->(*) { flunk "capture polled for child exit" }) do
      result =
        Landlock.capture(
          [RbConfig.ruby, "--disable=gems", "-e", "STDOUT.close; STDERR.close; sleep 0.25"],
          rlimits: {
            open_files: 64
          }
        )
    end

    assert result.status.success?
    refute result.timed_out?
  end

  def test_capture_timeout_applies_after_streams_close
    skip "Landlock unsupported" unless Landlock.supported?

    error = nil
    Thread.stub(:new, ->(*) { flunk "capture created a timeout thread" }) do
      error =
        assert_raises(Landlock::CommandError) do
          Landlock.capture!(
            ["/bin/sh", "-c", "exec 1>&- 2>&-; exec /bin/sleep 30"],
            rlimits: {
              open_files: 64
            },
            timeout: 0.1
          )
        end
    end

    assert error.result.timed_out?
    refute_nil error.status
    assert error.status.signaled?
  end

  def test_capture_does_not_create_timeout_thread_after_streams_close
    skip "Landlock unsupported" unless Landlock.supported?

    result = nil
    Thread.stub(:new, ->(*) { flunk "capture created a timeout thread" }) do
      result =
        Landlock.capture(
          [RbConfig.ruby, "--disable=gems", "-e", "STDOUT.close; STDERR.close; sleep 0.1"],
          rlimits: {
            open_files: 64
          },
          timeout: 5
        )
    end

    assert result.status.success?
    refute result.timed_out?
  end

  def test_capture_closes_pid_monitor_when_waiting_for_child_raises
    skip "Landlock unsupported" unless Landlock.supported?

    pid_monitors = []
    wait_calls = 0
    original_for_fd = IO.method(:for_fd)
    original_wait_for_pid = Landlock::ProcessIO.method(:wait_for_pid)
    for_fd = ->(*arguments, **options) { original_for_fd.call(*arguments, **options).tap { |io| pid_monitors << io } }
    wait_for_pid =
      lambda do |pid|
        wait_calls += 1
        raise IOError, "wait failed" if wait_calls == 1

        original_wait_for_pid.call(pid)
      end

    IO.stub(:for_fd, for_fd) do
      Landlock::ProcessIO.stub(:wait_for_pid, wait_for_pid) do
        assert_raises(IOError) do
          Landlock.capture(["/bin/sh", "-c", "exec 1>&- 2>&-; sleep 0.1"], rlimits: { open_files: 64 }, timeout: 10)
        end
      end
    end

    assert_equal 1, pid_monitors.size
    assert_predicate pid_monitors.first, :closed?
  end

  def test_capture_closes_raw_pidfd_when_wrapping_it_raises
    skip "Landlock unsupported" unless Landlock.supported?

    pidfd = nil
    closed_pidfds = []
    original_pidfd_open = Landlock::Native.method(:pidfd_open)
    original_close_fd = Landlock::Native.method(:close_fd)
    pidfd_open = ->(pid) { original_pidfd_open.call(pid).tap { |fd| pidfd = fd } }
    close_fd =
      lambda do |fd|
        closed_pidfds << fd if fd == pidfd
        original_close_fd.call(fd)
      end

    Landlock::Native.stub(:pidfd_open, pidfd_open) do
      Landlock::Native.stub(:close_fd, close_fd) do
        IO.stub(:for_fd, ->(*) { raise IOError, "wrap failed" }) do
          assert_raises(IOError) do
            Landlock.capture(["/bin/sh", "-c", "exec 1>&- 2>&-; sleep 30"], rlimits: { open_files: 64 }, timeout: 10)
          end
        end
      end
    end

    refute_nil pidfd
    assert_equal [pidfd], closed_pidfds
  end

  def test_capture_falls_back_without_a_timeout_thread_when_pidfd_is_unavailable
    skip "Landlock unsupported" unless Landlock.supported?

    pidfd_error = Landlock::SyscallError.new("pidfd_open", Errno::EPERM::Errno)
    result = nil
    Landlock::Native.stub(:pidfd_open, ->(*) { raise pidfd_error }) do
      Thread.stub(:new, ->(*) { flunk "capture created a timeout thread" }) do
        result =
          Landlock.capture(
            [RbConfig.ruby, "--disable=gems", "-e", "STDOUT.close; STDERR.close; sleep 0.1"],
            rlimits: {
              open_files: 64
            },
            timeout: 5
          )
      end
    end

    assert result.status.success?
    refute result.timed_out?
  end

  def test_capture_fallback_enforces_timeout_when_pidfd_is_unavailable
    skip "Landlock unsupported" unless Landlock.supported?

    pidfd_error = Landlock::SyscallError.new("pidfd_open", Errno::ENOSYS::Errno)
    result = nil
    Landlock::Native.stub(:pidfd_open, ->(*) { raise pidfd_error }) do
      Thread.stub(:new, ->(*) { flunk "capture created a timeout thread" }) do
        result =
          Landlock.capture(
            ["/bin/sh", "-c", "exec 1>&- 2>&-; exec /bin/sleep 30"],
            rlimits: {
              open_files: 64
            },
            timeout: 0.1
          )
      end
    end

    assert result.timed_out?
    assert_predicate result.status, :signaled?
  end

  def test_capture_does_not_wait_forever_for_blocked_stdin_reader
    skip "Landlock unsupported" unless Landlock.supported?

    reader, writer = IO.pipe
    started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    result =
      Landlock.capture(
        [RbConfig.ruby, "--disable=gems", "-e", "exit 0"],
        stdin: reader,
        rlimits: {
          open_files: 64
        },
        timeout: 2
      )
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at

    assert_operator elapsed, :<, 1
    assert_equal 0, result.status.exitstatus
  ensure
    reader&.close unless reader&.closed?
    writer&.close unless writer&.closed?
  end

  def test_capture_rejects_zero_effective_custom_path_rules
    skip "Landlock unsupported" unless Landlock.supported?

    Dir.mktmpdir do |dir|
      file = File.join(dir, "file.txt")
      File.write(file, "content")

      error =
        assert_raises(ArgumentError) do
          Landlock.capture(
            [RbConfig.ruby, "--disable=gems", "-e", "exit 0"],
            paths: [{ path: file, rights: [:read_dir] }]
          )
        end

      assert_match(/no effective rights/, error.message)
    end
  end

  def test_capture_rejects_empty_policy
    skip "Landlock unsupported" unless Landlock.supported?

    error =
      assert_raises(ArgumentError) { Landlock.capture([RbConfig.ruby, "--disable=gems", "-e", "print 'unsandboxed'"]) }

    assert_match(/empty capture policy/, error.message)
  end

  def test_capture_allows_rlimits_only_policy
    skip "Landlock unsupported" unless Landlock.supported?

    result =
      Landlock.capture(
        [RbConfig.ruby, "--disable=gems", "-e", "print Process.getrlimit(Process::RLIMIT_NOFILE).first"],
        rlimits: {
          open_files: 32
        },
        env: {
          "PATH" => ENV.fetch("PATH", "")
        },
        unsetenv_others: true
      )

    assert result.status.success?, result.stderr
    assert_equal "32", result.stdout
  end

  def test_capture_rejects_invalid_env_before_backend_selection
    skip "Landlock unsupported" unless Landlock.supported?

    assert_raises(ArgumentError) do
      Landlock.capture(
        [RbConfig.ruby, "--disable=gems", "-e", "exit 0"],
        bind_tcp: [free_port],
        env: {
          "BAD=KEY" => "value"
        },
        close_others: false
      )
    end
  end

  def test_capture_normalizes_environment_entries_before_spawning
    skip "Landlock unsupported" unless Landlock.supported?

    result =
      Landlock.capture(
        [RbConfig.ruby, "--disable=gems", "-e", "print ENV.fetch('LANDLOCK_TEST_CHILD')"],
        rlimits: {
          open_files: 64
        },
        env: {
          LANDLOCK_TEST_CHILD: :child
        },
        unsetenv_others: true
      )

    assert result.status.success?, result.stderr
    assert_equal "child", result.stdout
  end

  def test_capture_falls_back_to_fork_when_native_policy_argv_is_too_large
    expected = Object.new
    forked = nil

    Landlock::Native.stub(:abi_version, 1) do
      Landlock::Runner::Native.stub(:available?, true) do
        Landlock::Runner::Native.stub(:call, ->(*, **) { raise Errno::E2BIG }) do
          Landlock::Runner::Fork.stub(
            :call,
            ->(argv, **options) do
              forked = [argv, options]
              expected
            end
          ) { assert_same expected, Landlock.capture(["true"], rlimits: { open_files: 64 }) }
        end
      end
    end

    assert_equal ["true"], forked.fetch(0)
    assert_equal [[:open_files, 64]], forked.fetch(1).fetch(:rlimits)
  end

  def test_capture_seccomp_denies_network
    skip "Landlock unsupported" unless Landlock.supported?

    result =
      Landlock.capture(
        [
          RbConfig.ruby,
          "--disable=gems",
          "-rsocket",
          "-e",
          "begin; Socket.new(:INET, :STREAM); rescue Errno::EPERM; print 'denied'; end"
        ],
        read: runtime_paths,
        execute: runtime_paths,
        env: {
          "PATH" => ENV.fetch("PATH", "")
        },
        unsetenv_others: true,
        seccomp_deny_network: true
      )

    assert result.status.success?, result.stderr
    assert_equal "denied", result.stdout
  end

  def test_capture_custom_path_rule_allows_read
    skip "Landlock unsupported" unless Landlock.supported?

    Dir.mktmpdir do |dir|
      allowed = File.join(dir, "allowed.txt")
      denied = File.join(dir, "denied.txt")
      File.write(allowed, "ok")
      File.write(denied, "no")

      result =
        Landlock.capture(
          [
            RbConfig.ruby,
            "--disable=gems",
            "-e",
            "print File.read(ARGV.fetch(0)); begin; File.read(ARGV.fetch(1)); rescue Errno::EACCES; print ':denied'; end",
            allowed,
            denied
          ],
          read: runtime_paths,
          execute: runtime_paths,
          paths: [{ path: allowed, rights: %i[read_file read_dir] }],
          env: {
            "PATH" => ENV.fetch("PATH", "")
          },
          unsetenv_others: true,
          allow_all_known: true
        )

      assert result.status.success?, result.stderr
      assert_equal "ok:denied", result.stdout
    end
  end

  def test_capture_signal_scope_denies_signalling_parent
    skip "Landlock unsupported" unless Landlock.supported?
    skip "Landlock scopes unsupported" if Landlock.abi_version < 6

    result =
      Landlock.capture(
        [
          RbConfig.ruby,
          "--disable=gems",
          "-e",
          "begin; Process.kill(0, Process.ppid); rescue Errno::EPERM; print 'denied'; end"
        ],
        read: runtime_paths,
        execute: runtime_paths,
        env: {
          "PATH" => ENV.fetch("PATH", "")
        },
        unsetenv_others: true,
        scope: [:signal]
      )

    assert_equal "denied", result.stdout
  end

  def test_capture_timeout_kills_process_group
    skip "Landlock unsupported" unless Landlock.supported?

    Dir.mktmpdir do |dir|
      pidfile = File.join(dir, "grandchild.pid")
      assert_raises(Landlock::CommandError) do
        Landlock.capture!(
          [
            RbConfig.ruby,
            "--disable=gems",
            "-e",
            "pid = Process.fork { sleep 30 }; File.write(ARGV.fetch(0), pid); sleep 30",
            pidfile
          ],
          read: runtime_paths,
          write: [dir],
          execute: runtime_paths,
          env: {
            "PATH" => ENV.fetch("PATH", "")
          },
          unsetenv_others: true,
          timeout: 0.2
        )
      end

      assert_path_exists pidfile
      refute_process_alive Integer(File.read(pidfile))
    end
  end

  def test_capture_bang_raises_when_timeout_handler_exits_successfully
    skip "Landlock unsupported" unless Landlock.supported?

    error =
      assert_raises(Landlock::CommandError) do
        Landlock.capture!(
          [RbConfig.ruby, "--disable=gems", "-e", "trap('TERM') { exit 0 }; sleep 30"],
          read: runtime_paths,
          execute: runtime_paths,
          env: {
            "PATH" => ENV.fetch("PATH", "")
          },
          unsetenv_others: true,
          timeout: 0.1
        )
      end

    assert error.result.timed_out?
    assert_equal 0, error.status.exitstatus
    refute error.result.success?
  end

  def test_capture_timeout_returns_when_escaped_descendant_keeps_stdout_open
    skip "Landlock unsupported" unless Landlock.supported?

    Dir.mktmpdir do |dir|
      pidfile = File.join(dir, "escaped.pid")
      error = nil
      elapsed =
        Timeout.timeout(3) do
          start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          error =
            assert_raises(Landlock::CommandError) do
              Landlock.capture!(
                [
                  RbConfig.ruby,
                  "--disable=gems",
                  "-e",
                  "pid = Process.fork { Process.setsid; $stdout.sync = true; print 'held'; sleep 30 }; File.write(ARGV.fetch(0), pid); sleep 30",
                  pidfile
                ],
                read: runtime_paths,
                write: [dir],
                execute: runtime_paths,
                env: {
                  "PATH" => ENV.fetch("PATH", "")
                },
                unsetenv_others: true,
                timeout: 0.2
              )
            end
          Process.clock_gettime(Process::CLOCK_MONOTONIC) - start
        end

      assert error.result.timed_out?
      assert_operator elapsed, :<, 2
    ensure
      kill_process_from_file(pidfile)
    end
  end

  def test_capture_validates_relative_sandbox_paths_against_chdir
    skip "Landlock unsupported" unless Landlock.supported?

    Dir.mktmpdir do |dir|
      allowed = File.join(dir, "relative-allowed")
      Dir.mkdir(allowed)
      File.write(File.join(allowed, "input.txt"), "ok")

      result =
        Landlock.capture(
          [RbConfig.ruby, "--disable=gems", "-e", "print File.read('relative-allowed/input.txt')"],
          chdir: dir,
          read: ["relative-allowed"],
          execute: runtime_paths,
          env: {
            "PATH" => ENV.fetch("PATH", "")
          },
          unsetenv_others: true
        )

      assert_equal "ok", result.stdout
    end
  end

  def test_capture_rejects_missing_sandbox_paths_before_fork
    skip "Landlock unsupported" unless Landlock.supported?

    missing = "/definitely/missing/landlock-test-#{$$}"

    assert_raises(ArgumentError) do
      Landlock.capture([RbConfig.ruby, "--disable=gems", "-e", "exit 0"], read: [missing])
    end

    assert_raises(ArgumentError) do
      Landlock.capture(
        [RbConfig.ruby, "--disable=gems", "-e", "exit 0"],
        paths: [{ path: missing, rights: [:read_file] }]
      )
    end
  end

  def test_native_and_fork_runners_are_empirically_equivalent
    skip "Landlock unsupported" unless Landlock.supported?
    skip "native runner helper unavailable" unless File.executable?(Landlock::Runner::Native.helper_path)

    Dir.mktmpdir do |dir|
      allowed = File.join(dir, "allowed.txt")
      denied = File.join(dir, "denied.txt")
      File.write(allowed, "allowed")
      File.write(denied, "denied")

      old_env_remove = ENV["LANDLOCK_TEST_REMOVE"]
      connect_server = nil
      accept_thread = nil
      ENV["LANDLOCK_TEST_REMOVE"] = "parent"

      cases = {
        "stdout/stderr/status" => {
          argv: [RbConfig.ruby, "--disable=gems", "-e", "$stdout.print 'out'; $stderr.print 'err'; exit 7"],
          env: {
            "PATH" => ENV.fetch("PATH", "")
          },
          unsetenv_others: true
        },
        "stdin/chdir/env" => {
          argv: [
            RbConfig.ruby,
            "--disable=gems",
            "-e",
            "print [STDIN.read.upcase, ENV['LANDLOCK_TEST_CHILD'], ENV.key?('LANDLOCK_TEST_REMOVE'), File.basename(Dir.pwd)].join(':')"
          ],
          stdin: "hello",
          chdir: dir,
          env: {
            "PATH" => ENV.fetch("PATH", ""),
            "LANDLOCK_TEST_CHILD" => "child",
            "LANDLOCK_TEST_REMOVE" => nil
          },
          unsetenv_others: true
        },
        "env nil without unsetenv_others" => {
          argv: [RbConfig.ruby, "--disable=gems", "-e", "print ENV.key?('LANDLOCK_TEST_REMOVE')"],
          env: {
            "LANDLOCK_TEST_REMOVE" => nil
          }
        },
        "truncated output" => {
          argv: [RbConfig.ruby, "--disable=gems", "-e", "print 'x' * 1024"],
          env: {
            "PATH" => ENV.fetch("PATH", "")
          },
          unsetenv_others: true,
          max_output_bytes: 10,
          truncate_output: true
        },
        "custom path rules" => {
          argv: [
            RbConfig.ruby,
            "--disable=gems",
            "-e",
            "print File.read(ARGV.fetch(0)); begin; File.read(ARGV.fetch(1)); rescue Errno::EACCES; print ':denied'; end",
            allowed,
            denied
          ],
          read: runtime_paths,
          execute: runtime_paths,
          paths: [{ path: allowed, rights: %i[read_file read_dir] }],
          env: {
            "PATH" => ENV.fetch("PATH", "")
          },
          unsetenv_others: true,
          allow_all_known: true
        },
        "seccomp network denial" => {
          argv: [
            RbConfig.ruby,
            "--disable=gems",
            "-rsocket",
            "-e",
            "begin; Socket.new(:INET, :STREAM); rescue Errno::EPERM; print 'denied'; end"
          ],
          env: {
            "PATH" => ENV.fetch("PATH", "")
          },
          unsetenv_others: true,
          seccomp_deny_network: true
        }
      }

      if Landlock.abi_version >= 4
        connect_server = TCPServer.new("127.0.0.1", 0)
        connect_port = connect_server.addr.fetch(1)
        accept_thread =
          Thread.new do
            2.times do
              socket = connect_server.accept
              socket.close
            rescue IOError
              break
            end
          end
        bind_port = free_port
        cases["connect tcp"] = {
          argv: [
            RbConfig.ruby,
            "--disable=gems",
            "-rsocket",
            "-e",
            "TCPSocket.new('127.0.0.1', Integer(ARGV.fetch(0))).close; print 'connected'",
            connect_port.to_s
          ],
          connect_tcp: [connect_port]
        }
        cases["bind tcp"] = {
          argv: [
            RbConfig.ruby,
            "--disable=gems",
            "-rsocket",
            "-e",
            "server = TCPServer.new('127.0.0.1', Integer(ARGV.fetch(0))); print 'bound'; server.close",
            bind_port.to_s
          ],
          bind_tcp: [bind_port]
        }
      end

      cases.each { |name, options| assert_capture_backends_equivalent(name, **options) }
    ensure
      if old_env_remove.nil?
        ENV.delete("LANDLOCK_TEST_REMOVE")
      else
        ENV["LANDLOCK_TEST_REMOVE"] = old_env_remove
      end
      connect_server&.close
      accept_thread&.join(1)
      accept_thread&.kill if accept_thread&.alive?
    end
  end
end
