# frozen_string_literal: true

require "minitest/autorun"
require "tmpdir"
require "rbconfig"
require "socket"
require "English"
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
