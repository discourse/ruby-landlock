# frozen_string_literal: true

require "minitest/autorun"
require "tmpdir"
require "rbconfig"
require "socket"
require "English"
require "open3"
require "stringio"
require "landlock"

class LandlockTest < Minitest::Test
  def test_supported_predicate_returns_boolean
    assert_includes [true, false], Landlock.supported?
  end

  def test_syscall_error_exposes_errno_and_syscall
    error = Landlock::SyscallError.new("landlock_test", Errno::EINVAL::Errno)

    assert_equal "landlock_test", error.syscall
    assert_equal Errno::EINVAL::Errno, error.errno
    assert_match(/landlock_test failed/, error.message)
  end

  def test_empty_argv_rejected
    assert_raises(ArgumentError) { Landlock.exec([]) }
    assert_raises(ArgumentError) { Landlock.spawn([]) }
  end

  def test_string_argv_rejected_to_avoid_implicit_shell
    assert_raises(ArgumentError) { Landlock.exec("echo unsafe") }
    assert_raises(ArgumentError) { Landlock.spawn("echo unsafe") }
  end

  def test_child_setup_failure_does_not_run_inherited_at_exit_handlers
    Dir.mktmpdir do |dir|
      marker = File.join(dir, "at_exit_ran")
      script = <<~RUBY
        require "landlock"
        parent_pid = Process.pid
        marker = #{marker.inspect}
        at_exit { File.write(marker, "ran") if Process.pid != parent_pid }
        status = Landlock.exec([#{RbConfig.ruby.inspect}, "-e", "exit 0"])
        exit 10 if File.exist?(marker)
        exit(status.exitstatus == 127 ? 0 : 11)
      RUBY

      out = IO.popen([RbConfig.ruby, "-Ilib", "-Ilib/landlock", "-e", script], chdir: root, err: [:child, :out], &:read)
      assert $CHILD_STATUS.success?, out
      refute_path_exists marker
    end
  end

  def test_rule_validation_helpers
    assert_equal ["/tmp", [:read_file]], Landlock.send(:normalize_path_rule, path: "/tmp", rights: :read_file)
    assert_equal ["/tmp", [:read_file]], Landlock.send(:normalize_path_rule, ["/tmp", :read_file])

    assert_raises(ArgumentError) { Landlock.send(:normalize_path_rule, "/tmp") }
    assert_raises(ArgumentError) { Landlock.send(:mask, [:bogus], Landlock::FS_RIGHTS, Landlock.abi_version) }
  end

  def test_abi_detection
    assert_kind_of Integer, Landlock.abi_version
  end

  def test_filesystem_read_denied_outside_allowlist
    skip "Landlock unsupported" unless Landlock.supported?

    Dir.mktmpdir do |dir|
      allowed = File.join(dir, "allowed")
      denied = File.join(dir, "denied")
      Dir.mkdir(allowed)
      Dir.mkdir(denied)
      File.write(File.join(allowed, "ok.txt"), "ok")
      File.write(File.join(denied, "no.txt"), "no")

      script = <<~RUBY
        require "landlock"
        Landlock.restrict!(read: [#{allowed.inspect}])
        print File.read(#{File.join(allowed, "ok.txt").inspect})
        begin
          File.read(#{File.join(denied, "no.txt").inspect})
          exit 10
        rescue Errno::EACCES
          exit 0
        end
      RUBY

      out = IO.popen([RbConfig.ruby, "-Ilib", "-Ilib/landlock", "-e", script], chdir: root, err: [:child, :out], &:read)
      assert $CHILD_STATUS.success?, out
      assert_equal "ok", out
    end
  end

  def test_filesystem_read_allows_single_file_path
    skip "Landlock unsupported" unless Landlock.supported?

    Dir.mktmpdir do |dir|
      allowed = File.join(dir, "allowed.txt")
      denied = File.join(dir, "denied.txt")
      File.write(allowed, "ok")
      File.write(denied, "no")

      script = <<~RUBY
        require "landlock"
        Landlock.restrict!(read: [#{allowed.inspect}])
        print File.read(#{allowed.inspect})
        begin
          File.read(#{denied.inspect})
          exit 10
        rescue Errno::EACCES
          exit 0
        end
      RUBY

      out = IO.popen([RbConfig.ruby, "-Ilib", "-Ilib/landlock", "-e", script], chdir: root, err: [:child, :out], &:read)
      assert $CHILD_STATUS.success?, out
      assert_equal "ok", out
    end
  end

  def test_filesystem_write_denied_outside_allowlist
    skip "Landlock unsupported" unless Landlock.supported?

    Dir.mktmpdir do |dir|
      allowed = File.join(dir, "allowed")
      denied = File.join(dir, "denied")
      Dir.mkdir(allowed)
      Dir.mkdir(denied)

      script = <<~RUBY
        require "landlock"
        Landlock.restrict!(write: [#{allowed.inspect}])
        File.write(#{File.join(allowed, "ok.txt").inspect}, "ok")
        begin
          File.write(#{File.join(denied, "no.txt").inspect}, "no")
          exit 10
        rescue Errno::EACCES
          exit 0
        end
      RUBY

      out = IO.popen([RbConfig.ruby, "-Ilib", "-Ilib/landlock", "-e", script], chdir: root, err: [:child, :out], &:read)
      assert $CHILD_STATUS.success?, out
      assert_equal "ok", File.read(File.join(allowed, "ok.txt"))
      refute_path_exists File.join(denied, "no.txt")
    end
  end

  def test_filesystem_write_allows_single_existing_file_path
    skip "Landlock unsupported" unless Landlock.supported?

    Dir.mktmpdir do |dir|
      allowed = File.join(dir, "allowed.txt")
      denied = File.join(dir, "denied.txt")
      File.write(allowed, "old")
      File.write(denied, "old")

      script = <<~RUBY
        require "landlock"
        Landlock.restrict!(write: [#{allowed.inspect}])
        File.write(#{allowed.inspect}, "ok")
        begin
          File.write(#{denied.inspect}, "no")
          exit 10
        rescue Errno::EACCES
          exit 0
        end
      RUBY

      out = IO.popen([RbConfig.ruby, "-Ilib", "-Ilib/landlock", "-e", script], chdir: root, err: [:child, :out], &:read)
      assert $CHILD_STATUS.success?, out
      assert_equal "ok", File.read(allowed)
      assert_equal "old", File.read(denied)
    end
  end

  def test_custom_path_rule_allows_read
    skip "Landlock unsupported" unless Landlock.supported?

    Dir.mktmpdir do |dir|
      allowed = File.join(dir, "allowed.txt")
      denied = File.join(dir, "denied.txt")
      File.write(allowed, "ok")
      File.write(denied, "no")

      script = <<~RUBY
        require "landlock"
        Landlock.restrict!(paths: [{ path: #{allowed.inspect}, rights: [:read_file] }])
        print File.read(#{allowed.inspect})
        begin
          File.read(#{denied.inspect})
          exit 10
        rescue Errno::EACCES
          exit 0
        end
      RUBY

      out = IO.popen([RbConfig.ruby, "-Ilib", "-Ilib/landlock", "-e", script], chdir: root, err: [:child, :out], &:read)
      assert $CHILD_STATUS.success?, out
      assert_equal "ok", out
    end
  end

  def test_exec_returns_process_status
    skip "Landlock unsupported" unless Landlock.supported?
    skip "Landlock network unsupported" if Landlock.abi_version < 4

    status = Landlock.exec([RbConfig.ruby, "-e", "exit 7"], bind_tcp: [free_port])

    assert_equal 7, status.exitstatus
  end

  def test_signal_scope_denies_signalling_parent
    skip "Landlock unsupported" unless Landlock.supported?
    skip "Landlock scopes unsupported" if Landlock.abi_version < 6

    script = <<~RUBY
      require "landlock"
      Landlock.restrict!(scope: [:signal])
      begin
        Process.kill(0, Process.ppid)
        exit 10
      rescue Errno::EPERM
        exit 0
      end
    RUBY

    out = IO.popen([RbConfig.ruby, "-Ilib", "-Ilib/landlock", "-e", script], chdir: root, err: [:child, :out], &:read)
    assert $CHILD_STATUS.success?, out
  end

  def test_exec_unsetenv_others_clears_parent_environment
    skip "Landlock unsupported" unless Landlock.supported?
    skip "Landlock network unsupported" if Landlock.abi_version < 4

    ENV["LANDLOCK_TEST_SECRET"] = "secret"
    status = Landlock.exec(
      [RbConfig.ruby, "--disable=gems", "-e", "exit(ENV.key?('LANDLOCK_TEST_SECRET') ? 10 : 0)"],
      bind_tcp: [free_port],
      env: { "PATH" => ENV.fetch("PATH", "") },
      unsetenv_others: true
    )

    assert status.success?
  ensure
    ENV.delete("LANDLOCK_TEST_SECRET")
  end

  def test_exec_env_without_unsetenv_others_adds_to_parent_environment
    skip "Landlock unsupported" unless Landlock.supported?
    skip "Landlock network unsupported" if Landlock.abi_version < 4

    ENV["LANDLOCK_TEST_PARENT"] = "parent"
    status = Landlock.exec(
      [RbConfig.ruby, "--disable=gems", "-e", "exit(ENV['LANDLOCK_TEST_PARENT'] == 'parent' && ENV['LANDLOCK_TEST_CHILD'] == 'child' ? 0 : 10)"],
      bind_tcp: [free_port],
      env: { "LANDLOCK_TEST_CHILD" => "child" }
    )

    assert status.success?
  ensure
    ENV.delete("LANDLOCK_TEST_PARENT")
  end

  def test_exec_chdir
    skip "Landlock unsupported" unless Landlock.supported?
    skip "Landlock network unsupported" if Landlock.abi_version < 4

    Dir.mktmpdir do |dir|
      status = Landlock.exec(
        [RbConfig.ruby, "--disable=gems", "-e", "exit(Dir.pwd == ARGV.fetch(0) ? 0 : 10)", dir],
        bind_tcp: [free_port],
        chdir: dir
      )

      assert status.success?
    end
  end

  def test_exec_unsupported_kernel_raises_before_fork
    Landlock.stub(:abi_version, 0) do
      assert_raises(Landlock::UnsupportedError) do
        Landlock.exec([RbConfig.ruby, "--disable=gems", "-e", "exit 0"], bind_tcp: [1])
      end
    end
  end

  def test_spawn_unsupported_kernel_raises_before_fork
    Landlock.stub(:abi_version, 0) do
      assert_raises(Landlock::UnsupportedError) do
        Landlock.spawn([RbConfig.ruby, "--disable=gems", "-e", "exit 0"], bind_tcp: [1])
      end
    end
  end

  def test_spawn_env_and_unsetenv_others
    skip "Landlock unsupported" unless Landlock.supported?
    skip "Landlock network unsupported" if Landlock.abi_version < 4

    ENV["LANDLOCK_TEST_SECRET"] = "secret"
    pid = Landlock.spawn(
      [RbConfig.ruby, "--disable=gems", "-e", "exit(ENV['LANDLOCK_TEST_CHILD'] == 'child' && !ENV.key?('LANDLOCK_TEST_SECRET') ? 0 : 10)"],
      bind_tcp: [free_port],
      env: { "LANDLOCK_TEST_CHILD" => "child" },
      unsetenv_others: true
    )
    _, status = Process.wait2(pid)

    assert status.success?
  ensure
    ENV.delete("LANDLOCK_TEST_SECRET")
  end

  def test_exec_allow_all_known_denies_unlisted_writes
    skip "Landlock unsupported" unless Landlock.supported?

    Dir.mktmpdir do |dir|
      denied = File.join(dir, "denied.txt")
      script = <<~RUBY
        begin
          File.write(#{denied.inspect}, "no")
          exit 10
        rescue Errno::EACCES
          exit 0
        end
      RUBY

      status = Landlock.exec(
        [RbConfig.ruby, "--disable=gems", "-e", script],
        read: runtime_paths,
        execute: runtime_paths,
        allow_all_known: true,
        env: { "PATH" => ENV.fetch("PATH", "") },
        unsetenv_others: true
      )

      assert status.success?
      refute_path_exists denied
    end
  end

  def test_spawn_returns_pid
    skip "Landlock unsupported" unless Landlock.supported?
    skip "Landlock network unsupported" if Landlock.abi_version < 4

    Dir.mktmpdir do |dir|
      marker = File.join(dir, "spawned.txt")
      pid = Landlock.spawn([RbConfig.ruby, "-e", "File.write(ARGV.fetch(0), 'ok')", marker], bind_tcp: [free_port])
      _, status = Process.wait2(pid)

      assert status.success?
      assert_equal "ok", File.read(marker)
    end
  end

  def test_connect_tcp_denied_except_allowed_port
    skip "Landlock unsupported" unless Landlock.supported?
    skip "Landlock network unsupported" if Landlock.abi_version < 4

    server = TCPServer.new("127.0.0.1", 0)
    allowed_port = server.addr[1]
    other = TCPServer.new("127.0.0.1", 0)
    denied_port = other.addr[1]

    accept_thread = Thread.new do
      socket = server.accept
      socket.close
    rescue IOError, Errno::EBADF
    end

    script = <<~RUBY
      require "socket"
      require "landlock"
      Landlock.restrict!(connect_tcp: [#{allowed_port}])
      TCPSocket.new("127.0.0.1", #{allowed_port}).close
      begin
        TCPSocket.new("127.0.0.1", #{denied_port}).close
        exit 10
      rescue Errno::EACCES
        exit 0
      end
    RUBY

    out = IO.popen([RbConfig.ruby, "-Ilib", "-Ilib/landlock", "-e", script], chdir: root, err: [:child, :out], &:read)
    assert $CHILD_STATUS.success?, out
  ensure
    server&.close
    other&.close
    accept_thread&.join(1)
  end

  def test_bind_tcp_denied_except_allowed_port
    skip "Landlock unsupported" unless Landlock.supported?
    skip "Landlock network unsupported" if Landlock.abi_version < 4

    allowed = free_port
    denied = free_port

    script = <<~RUBY
      require "socket"
      require "landlock"
      Landlock.restrict!(bind_tcp: [#{allowed}])
      TCPServer.new("127.0.0.1", #{allowed}).close
      begin
        TCPServer.new("127.0.0.1", #{denied}).close
        exit 10
      rescue Errno::EACCES
        exit 0
      end
    RUBY

    out = IO.popen([RbConfig.ruby, "-Ilib", "-Ilib/landlock", "-e", script], chdir: root, err: [:child, :out], &:read)
    assert $CHILD_STATUS.success?, out
  end

  def test_safe_exec_capture_returns_stdout_stderr_and_status
    stdout, stderr, status = Landlock::SafeExec.capture(
      RbConfig.ruby,
      "--disable=gems",
      "-e",
      "$stdout.print 'ok'; $stderr.print 'warn'",
      read: runtime_paths,
      execute: runtime_paths,
      env: { "PATH" => ENV.fetch("PATH", "") }
    )

    assert_equal "ok", stdout
    assert_equal "warn", stderr
    assert status.success?
  end

  def test_safe_exec_enforces_output_limit
    error = assert_raises(Landlock::SafeExec::CommandError) do
      Landlock::SafeExec.capture(
        RbConfig.ruby,
        "--disable=gems",
        "-e",
        "print 'x' * 1024",
        read: runtime_paths,
        execute: runtime_paths,
        env: { "PATH" => ENV.fetch("PATH", "") },
        max_output_bytes: 10
      )
    end

    assert_match(/exceeded 10 bytes/, error.message)
  end

  def test_safe_exec_truncates_output
    output = Landlock::SafeExec.capture(
      RbConfig.ruby,
      "--disable=gems",
      "-e",
      "print 'x' * 1024",
      read: runtime_paths,
      execute: runtime_paths,
      env: { "PATH" => ENV.fetch("PATH", "") },
      max_output_bytes: 10,
      truncate_output: true
    )

    assert_equal "x" * 10, output.stdout
    assert output.output_truncated?
    refute output.timed_out?
  end

  def test_safe_exec_stdin_support
    output = Landlock::SafeExec.capture(
      RbConfig.ruby,
      "--disable=gems",
      "-e",
      "print STDIN.read.upcase",
      stdin: "hello",
      read: runtime_paths,
      execute: runtime_paths,
      env: { "PATH" => ENV.fetch("PATH", "") }
    )

    assert_equal "HELLO", output.stdout
  end

  def test_safe_exec_io_stdin_support
    input = StringIO.new("streamed")
    output = Landlock::SafeExec.capture(
      RbConfig.ruby,
      "--disable=gems",
      "-e",
      "print STDIN.read.reverse",
      stdin: input,
      read: runtime_paths,
      execute: runtime_paths,
      env: { "PATH" => ENV.fetch("PATH", "") }
    )

    assert_equal "demaerts", output.stdout
  end

  def test_safe_exec_output_limit_counts_stdout_and_stderr_together
    stdout, stderr, _status, truncated = Landlock::SafeExec.send(
      :capture_process,
      [RbConfig.ruby, "--disable=gems", "-e", "$stdout.print('o' * 8); $stderr.print('e' * 8)"],
      read: runtime_paths,
      write: [],
      execute: runtime_paths,
      timeout: nil,
      env: { "PATH" => ENV.fetch("PATH", "") },
      inherit_env: false,
      stdin: nil,
      chdir: nil,
      connect_tcp: nil,
      bind_tcp: [],
      rlimits: {},
      seccomp_deny_network: false,
      max_output_bytes: 10,
      truncate_output: true,
      allow_all_known: true
    )

    assert truncated
    assert_equal 10, stdout.bytesize + stderr.bytesize
    assert_operator stdout.bytesize, :<=, 8
    assert_operator stderr.bytesize, :<=, 8
  end

  def test_safe_exec_seccomp_denies_network
    skip "SafeExec helper unavailable" unless File.executable?(Landlock::SafeExec.helper_path)

    output = Landlock::SafeExec.capture(
      RbConfig.ruby,
      "--disable=gems",
      "-rsocket",
      "-e",
      "begin; Socket.new(:INET, :STREAM); rescue Errno::EPERM; print 'denied'; end",
      read: runtime_paths,
      execute: runtime_paths,
      env: { "PATH" => ENV.fetch("PATH", "") },
      seccomp_deny_network: true
    )

    assert_equal "denied", output.stdout
  end

  def test_safe_exec_seccomp_denies_socketpair
    skip "SafeExec helper unavailable" unless File.executable?(Landlock::SafeExec.helper_path)

    output = Landlock::SafeExec.capture(
      RbConfig.ruby,
      "--disable=gems",
      "-rsocket",
      "-e",
      "begin; Socket.pair(:UNIX, :STREAM, 0); rescue Errno::EPERM; print 'denied'; end",
      read: runtime_paths,
      execute: runtime_paths,
      env: { "PATH" => ENV.fetch("PATH", "") },
      seccomp_deny_network: true
    )

    assert_equal "denied", output.stdout
  end

  def test_safe_exec_seccomp_denies_tcp_server_creation
    skip "SafeExec helper unavailable" unless File.executable?(Landlock::SafeExec.helper_path)

    output = Landlock::SafeExec.capture(
      RbConfig.ruby,
      "--disable=gems",
      "-rsocket",
      "-e",
      "begin; TCPServer.new('127.0.0.1', 0); rescue Errno::EPERM; print 'denied'; end",
      read: runtime_paths,
      execute: runtime_paths,
      env: { "PATH" => ENV.fetch("PATH", "") },
      seccomp_deny_network: true
    )

    assert_equal "denied", output.stdout
  end

  def test_safe_exec_env_is_exact_by_default
    ENV["LANDLOCK_TEST_SECRET"] = "secret"

    output = Landlock::SafeExec.capture(
      RbConfig.ruby,
      "--disable=gems",
      "-e",
      "print ENV['LANDLOCK_TEST_CHILD']; exit(ENV.key?('LANDLOCK_TEST_SECRET') ? 10 : 0)",
      read: runtime_paths,
      execute: runtime_paths,
      env: { "PATH" => ENV.fetch("PATH", ""), "LANDLOCK_TEST_CHILD" => "child" },
    )

    assert_equal "child", output.stdout
  ensure
    ENV.delete("LANDLOCK_TEST_SECRET")
  end

  def test_safe_exec_inherit_env_keeps_parent_environment
    ENV["LANDLOCK_TEST_PARENT"] = "parent"

    output = Landlock::SafeExec.capture(
      RbConfig.ruby,
      "--disable=gems",
      "-e",
      "print ENV['LANDLOCK_TEST_PARENT']",
      connect_tcp: [],
      env: { "PATH" => ENV.fetch("PATH", "") },
      inherit_env: true
    )

    assert_equal "parent", output.stdout
  ensure
    ENV.delete("LANDLOCK_TEST_PARENT")
  end

  def test_safe_exec_chdir
    Dir.mktmpdir do |dir|
      output = Landlock::SafeExec.capture(
        RbConfig.ruby,
        "--disable=gems",
        "-e",
        "print Dir.pwd",
        read: runtime_paths,
        execute: runtime_paths,
        env: { "PATH" => ENV.fetch("PATH", "") },
        chdir: dir
      )

      assert_equal dir, output.stdout
    end
  end

  def test_safe_exec_capture_bang_raises_and_exposes_output_and_status
    error = assert_raises(Landlock::SafeExec::CommandError) do
      Landlock::SafeExec.capture!(
        RbConfig.ruby,
        "--disable=gems",
        "-e",
        "$stdout.print 'out'; $stderr.print 'err'; exit 7",
        read: runtime_paths,
        execute: runtime_paths,
        env: { "PATH" => ENV.fetch("PATH", "") }
      )
    end

    assert_equal "out", error.stdout
    assert_equal "err", error.stderr
    assert_equal 7, error.status.exitstatus
    assert_equal error.status, error.result.status
    refute error.result.success?
  end

  def test_safe_exec_capture_returns_non_success_status_without_raising
    stdout, stderr, status = Landlock::SafeExec.capture(
      RbConfig.ruby,
      "--disable=gems",
      "-e",
      "$stdout.print 'out'; $stderr.print 'err'; exit 7",
      read: runtime_paths,
      execute: runtime_paths,
      env: { "PATH" => ENV.fetch("PATH", "") },
    )

    assert_equal "out", stdout
    assert_equal "err", stderr
    assert_equal 7, status.exitstatus
  end

  def test_safe_exec_timeout
    error = assert_raises(Landlock::SafeExec::CommandError) do
      Landlock::SafeExec.capture!(
        RbConfig.ruby,
        "--disable=gems",
        "-e",
        "sleep 10",
        read: runtime_paths,
        execute: runtime_paths,
        env: { "PATH" => ENV.fetch("PATH", "") },
        timeout: 0.1
      )
    end

    refute error.status.success?
    assert error.result.timed_out?
  end

  def test_safe_exec_applies_open_files_rlimit
    output = Landlock::SafeExec.capture(
      RbConfig.ruby,
      "--disable=gems",
      "-e",
      "print Process.getrlimit(Process::RLIMIT_NOFILE).first",
      read: runtime_paths,
      execute: runtime_paths,
      env: { "PATH" => ENV.fetch("PATH", "") },
      rlimits: { open_files: 32 }
    )

    assert_equal "32", output.stdout
  end

  def test_safe_exec_applies_memory_rlimit
    memory_limit = 8 * 1024 * 1024 * 1024
    output = Landlock::SafeExec.capture(
      RbConfig.ruby,
      "--disable=gems",
      "-e",
      "print Process.getrlimit(Process::RLIMIT_AS).first",
      read: runtime_paths,
      execute: runtime_paths,
      env: { "PATH" => ENV.fetch("PATH", "") },
      rlimits: { memory_bytes: memory_limit }
    )

    assert_equal memory_limit.to_s, output.stdout
  end

  def test_safe_exec_accepts_processes_rlimit
    argv = Landlock::SafeExec.send(
      :helper_argv,
      [RbConfig.ruby, "--disable=gems", "-e", "exit 0"],
      read: [],
      write: [],
      execute: [],
      env: {},
      inherit_env: false,
      chdir: nil,
      connect_tcp: [],
      bind_tcp: [],
      rlimits: { processes: 64 },
      seccomp_deny_network: false,
      allow_all_known: true
    )

    assert_includes argv, "--rlimit"
    assert_includes argv, "processes=64"
  end

  def test_safe_exec_applies_file_size_rlimit
    Dir.mktmpdir do |dir|
      path = File.join(dir, "too-large.txt")
      error = assert_raises(Landlock::SafeExec::CommandError) do
        Landlock::SafeExec.capture!(
          RbConfig.ruby,
          "--disable=gems",
          "-e",
          "File.binwrite(ARGV.fetch(0), 'x' * 4096)",
          path,
          read: runtime_paths,
          write: [dir],
          execute: runtime_paths,
          env: { "PATH" => ENV.fetch("PATH", "") },
          rlimits: { file_size_bytes: 1024 }
        )
      end

      refute error.status.success?
      assert_operator File.size(path), :<=, 1024 if File.exist?(path)
    end
  end

  def test_safe_exec_applies_cpu_rlimit
    skip "SafeExec helper unavailable" unless File.executable?(Landlock::SafeExec.helper_path)

    error = assert_raises(Landlock::SafeExec::CommandError) do
      Landlock::SafeExec.capture!(
        RbConfig.ruby,
        "--disable=gems",
        "-e",
        "loop { 1 + 1 }",
        read: runtime_paths,
        execute: runtime_paths,
        env: { "PATH" => ENV.fetch("PATH", "") },
        rlimits: { cpu_seconds: 1 },
        timeout: 5
      )
    end

    refute error.status.success?
  end

  def test_safe_exec_rejects_unknown_rlimit
    assert_raises(ArgumentError) do
      Landlock::SafeExec.capture(
        RbConfig.ruby,
        "--disable=gems",
        "-e",
        "exit 0",
        rlimits: { bogus: 1 }
      )
    end
  end

  def test_safe_exec_rejects_negative_rlimit
    assert_raises(ArgumentError) do
      Landlock::SafeExec.capture(
        RbConfig.ruby,
        "--disable=gems",
        "-e",
        "exit 0",
        rlimits: { open_files: -1 }
      )
    end
  end

  def test_safe_exec_rejects_negative_output_limit
    assert_raises(ArgumentError) do
      Landlock::SafeExec.capture(
        RbConfig.ruby,
        "--disable=gems",
        "-e",
        "exit 0",
        max_output_bytes: -1
      )
    end
  end

  def test_safe_exec_rejects_missing_sandbox_paths
    skip "SafeExec helper unavailable" unless File.executable?(Landlock::SafeExec.helper_path)

    assert_raises(ArgumentError) do
      Landlock::SafeExec.capture(
        RbConfig.ruby,
        "--disable=gems",
        "-e",
        "exit 0",
        read: ["/definitely/missing/landlock-test"]
      )
    end
  end

  def test_safe_exec_rejects_invalid_tcp_ports
    assert_raises(ArgumentError) do
      Landlock::SafeExec.capture(
        RbConfig.ruby,
        "--disable=gems",
        "-e",
        "exit 0",
        connect_tcp: ["123x"]
      )
    end

    assert_raises(ArgumentError) do
      Landlock::SafeExec.capture(
        RbConfig.ruby,
        "--disable=gems",
        "-e",
        "exit 0",
        bind_tcp: [-1]
      )
    end
  end

  def test_safe_exec_landlock_denies_unlisted_write
    skip "SafeExec helper unavailable" unless File.executable?(Landlock::SafeExec.helper_path)
    skip "Landlock unsupported" unless Landlock.supported?

    Dir.mktmpdir do |dir|
      denied = File.join(dir, "denied.txt")
      output = Landlock::SafeExec.capture(
        RbConfig.ruby,
        "--disable=gems",
        "-e",
        "begin; File.write(ARGV.fetch(0), 'no'); rescue Errno::EACCES; print 'denied'; end",
        denied,
        read: runtime_paths,
        execute: runtime_paths,
        env: { "PATH" => ENV.fetch("PATH", "") },
        )

      assert_equal "denied", output.stdout
      refute_path_exists denied
    end
  end

  def test_safe_exec_landlock_allows_listed_write
    skip "SafeExec helper unavailable" unless File.executable?(Landlock::SafeExec.helper_path)
    skip "Landlock unsupported" unless Landlock.supported?

    Dir.mktmpdir do |dir|
      allowed = File.join(dir, "allowed.txt")
      output = Landlock::SafeExec.capture(
        RbConfig.ruby,
        "--disable=gems",
        "-e",
        "File.write(ARGV.fetch(0), 'ok'); print File.read(ARGV.fetch(0))",
        allowed,
        read: runtime_paths,
        write: [dir],
        execute: runtime_paths,
        env: { "PATH" => ENV.fetch("PATH", "") }
      )

      assert_equal "ok", output.stdout
      assert_equal "ok", File.read(allowed)
    end
  end

  def test_safe_exec_landlock_allows_listed_read_and_denies_unlisted_read
    skip "SafeExec helper unavailable" unless File.executable?(Landlock::SafeExec.helper_path)
    skip "Landlock unsupported" unless Landlock.supported?

    Dir.mktmpdir do |dir|
      allowed = File.join(dir, "allowed.txt")
      denied = File.join(dir, "denied.txt")
      File.write(allowed, "allowed")
      File.write(denied, "denied")

      output = Landlock::SafeExec.capture(
        RbConfig.ruby,
        "--disable=gems",
        "-e",
        "print File.read(ARGV.fetch(0)); begin; File.read(ARGV.fetch(1)); rescue Errno::EACCES; print ':denied'; end",
        allowed,
        denied,
        read: [*runtime_paths, allowed],
        execute: runtime_paths,
        env: { "PATH" => ENV.fetch("PATH", "") }
      )

      assert_equal "allowed:denied", output.stdout
    end
  end

  def test_safe_exec_landlock_denies_unlisted_execute
    skip "SafeExec helper unavailable" unless File.executable?(Landlock::SafeExec.helper_path)
    skip "Landlock unsupported" unless Landlock.supported?

    Dir.mktmpdir do |dir|
      executable = File.join(dir, "program")
      File.write(executable, "#!/bin/sh\necho nope\n")
      File.chmod(0o755, executable)

      error = assert_raises(Landlock::SafeExec::CommandError) do
        Landlock::SafeExec.capture!(
          executable,
          read: [*runtime_paths, executable],
          execute: runtime_paths,
          env: { "PATH" => ENV.fetch("PATH", "") }
        )
      end

      assert_equal 126, error.status.exitstatus
      assert_match(/Permission denied/, error.stderr)
    end
  end

  def test_safe_exec_allow_all_known_false_does_not_install_strict_filesystem_policy
    argv = Landlock::SafeExec.send(
      :helper_argv,
      [RbConfig.ruby, "--disable=gems", "-e", "exit 0"],
      read: runtime_paths,
      write: [],
      execute: runtime_paths,
      env: { "PATH" => ENV.fetch("PATH", "") },
      inherit_env: false,
      chdir: nil,
      connect_tcp: [],
      bind_tcp: [],
      rlimits: {},
      seccomp_deny_network: false,
      allow_all_known: false
    )

    refute_includes argv, "--allow-all-known"
  end

  def test_safe_exec_timeout_kills_process_group
    skip "SafeExec helper unavailable" unless File.executable?(Landlock::SafeExec.helper_path)

    Dir.mktmpdir do |dir|
      marker = File.join(dir, "child-survived")
      assert_raises(Landlock::SafeExec::CommandError) do
        Landlock::SafeExec.capture!(
          RbConfig.ruby,
          "--disable=gems",
          "-e",
          "Process.fork { sleep 1; File.write(ARGV.fetch(0), 'alive') }; sleep 10",
          marker,
          read: runtime_paths,
          write: [dir],
          execute: runtime_paths,
          env: { "PATH" => ENV.fetch("PATH", "") },
          timeout: 0.1
        )
      end

      sleep 1.2
      refute_path_exists marker
    end
  end

  def test_safe_exec_connect_tcp_allows_only_listed_port
    skip "SafeExec helper unavailable" unless File.executable?(Landlock::SafeExec.helper_path)
    skip "Landlock unsupported" unless Landlock.supported?
    skip "Landlock network unsupported" if Landlock.abi_version < 4

    server = TCPServer.new("127.0.0.1", 0)
    allowed_port = server.addr[1]
    other = TCPServer.new("127.0.0.1", 0)
    denied_port = other.addr[1]

    accept_thread = Thread.new do
      socket = server.accept
      socket.close
    rescue IOError, Errno::EBADF
    end

    output = Landlock::SafeExec.capture(
      RbConfig.ruby,
      "--disable=gems",
      "-rsocket",
      "-e",
      "TCPSocket.new('127.0.0.1', ARGV.fetch(0).to_i).close; begin; TCPSocket.new('127.0.0.1', ARGV.fetch(1).to_i).close; rescue Errno::EACCES; print 'denied'; end",
      allowed_port.to_s,
      denied_port.to_s,
      read: runtime_paths,
      execute: runtime_paths,
      connect_tcp: [allowed_port],
      env: { "PATH" => ENV.fetch("PATH", "") }
    )

    assert_equal "denied", output.stdout
  ensure
    server&.close
    other&.close
    accept_thread&.join(1)
  end

  def test_safe_exec_omitted_connect_tcp_denies_connects
    skip "SafeExec helper unavailable" unless File.executable?(Landlock::SafeExec.helper_path)
    skip "Landlock unsupported" unless Landlock.supported?
    skip "Landlock network unsupported" if Landlock.abi_version < 4

    server = TCPServer.new("127.0.0.1", 0)
    output = Landlock::SafeExec.capture(
      RbConfig.ruby,
      "--disable=gems",
      "-rsocket",
      "-e",
      "begin; TCPSocket.new('127.0.0.1', ARGV.fetch(0).to_i).close; rescue Errno::EACCES; print 'denied'; end",
      server.addr[1].to_s,
      read: runtime_paths,
      execute: runtime_paths,
      env: { "PATH" => ENV.fetch("PATH", "") }
    )

    assert_equal "denied", output.stdout
  ensure
    server&.close
  end

  def test_safe_exec_empty_connect_tcp_leaves_connects_unrestricted
    skip "SafeExec helper unavailable" unless File.executable?(Landlock::SafeExec.helper_path)

    server = TCPServer.new("127.0.0.1", 0)
    accept_thread = Thread.new do
      socket = server.accept
      socket.close
    rescue IOError, Errno::EBADF
    end

    output = Landlock::SafeExec.capture(
      RbConfig.ruby,
      "--disable=gems",
      "-rsocket",
      "-e",
      "TCPSocket.new('127.0.0.1', ARGV.fetch(0).to_i).close; print 'connected'",
      server.addr[1].to_s,
      connect_tcp: [],
      env: { "PATH" => ENV.fetch("PATH", "") }
    )

    assert_equal "connected", output.stdout
  ensure
    server&.close
    accept_thread&.join(1)
  end

  def test_safe_exec_bind_tcp_allows_only_listed_port
    skip "SafeExec helper unavailable" unless File.executable?(Landlock::SafeExec.helper_path)
    skip "Landlock unsupported" unless Landlock.supported?
    skip "Landlock network unsupported" if Landlock.abi_version < 4

    allowed = free_port
    denied = free_port
    output = Landlock::SafeExec.capture(
      RbConfig.ruby,
      "--disable=gems",
      "-rsocket",
      "-e",
      "TCPServer.new('127.0.0.1', ARGV.fetch(0).to_i).close; begin; TCPServer.new('127.0.0.1', ARGV.fetch(1).to_i).close; rescue Errno::EACCES; print 'denied'; end",
      allowed.to_s,
      denied.to_s,
      read: runtime_paths,
      execute: runtime_paths,
      bind_tcp: [allowed],
      env: { "PATH" => ENV.fetch("PATH", "") }
    )

    assert_equal "denied", output.stdout
  end

  def test_safe_exec_helper_reports_cli_parse_errors
    skip "SafeExec helper unavailable" unless File.executable?(Landlock::SafeExec.helper_path)

    cases = [
      [["--bogus", "--", "true"], /unknown option/],
      [["--read"], /missing option argument/],
      [["--"], /missing command/],
      [["--bind-tcp", "70000", "--", "true"], /TCP port must be between 0 and 65535/],
      [["--rlimit", "nope", "--", "true"], /rlimit must be name=value/],
      [["--rlimit", "bogus=1", "--", "true"], /unknown rlimit/],
      [["--rlimit", "open_files=12x", "--", "true"], /rlimit value/],
      [["--connect-tcp", "abc", "--", "true"], /TCP port must be an integer/],
      [["--connect-tcp", "-1", "--", "true"], /TCP port must be an integer/]
    ]

    cases.each do |argv, error_pattern|
      _stdout, stderr, status = Open3.capture3(Landlock::SafeExec.helper_path, *argv)

      assert_equal 126, status.exitstatus, argv.inspect
      assert_match error_pattern, stderr
    end
  end

  def test_safe_exec_without_helper_is_pass_through_and_warns_for_sandbox_options
    Landlock::SafeExec.instance_variable_set(:@warned_unsupported_sandbox, false)
    output = nil
    _stdout, stderr = capture_io do
      Landlock::SafeExec.stub(:helper_available?, false) do
        output = Landlock::SafeExec.capture(
          RbConfig.ruby,
          "--disable=gems",
          "-e",
          "print 'ok'",
          read: ["/definitely/sandbox/only"],
          seccomp_deny_network: true,
          env: { "PATH" => ENV.fetch("PATH", "") }
        )
      end
    end

    assert_equal "ok", output.stdout
    assert_match(/running command as a pass-through/, stderr)
  ensure
    Landlock::SafeExec.instance_variable_set(:@warned_unsupported_sandbox, false)
  end

  def test_safe_exec_without_helper_preserves_process_management_features
    ENV["LANDLOCK_TEST_SECRET"] = "secret"
    output = nil

    Landlock::SafeExec.stub(:helper_available?, false) do
      Dir.mktmpdir do |dir|
        output = Landlock::SafeExec.capture(
          RbConfig.ruby,
          "--disable=gems",
          "-e",
          "print [Dir.pwd, ENV['LANDLOCK_TEST_CHILD'], ENV.key?('LANDLOCK_TEST_SECRET'), Process.getrlimit(Process::RLIMIT_NOFILE).first].join(':')",
          chdir: dir,
          env: { "PATH" => ENV.fetch("PATH", ""), "LANDLOCK_TEST_CHILD" => "child" },
          rlimits: { open_files: 32 },
          max_output_bytes: 1_024
        )

        assert_equal "#{dir}:child:false:32", output.stdout
      end
    end
  ensure
    ENV.delete("LANDLOCK_TEST_SECRET")
  end

  private

  def root
    File.expand_path("..", __dir__)
  end

  def free_port
    s = TCPServer.new("127.0.0.1", 0)
    s.addr[1]
  ensure
    s&.close
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
end
