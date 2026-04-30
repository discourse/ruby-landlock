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
end
