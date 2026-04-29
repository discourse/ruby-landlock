# frozen_string_literal: true

require "minitest/autorun"
require "tmpdir"
require "rbconfig"
require "socket"
require "English"
require "landlock"

class LandlockTest < Minitest::Test
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
