# frozen_string_literal: true

require_relative "landlock/version"
require_relative "landlock/landlock"

module Landlock
  class Error < StandardError; end
  class UnsupportedError < Error; end

  class SyscallError < Error
    attr_reader :errno, :syscall

    def initialize(syscall, errno, message = nil)
      @syscall = syscall
      @errno = errno
      super(message || "#{syscall} failed: #{errno}")
    end
  end

  FS_RIGHTS = {
    execute: ACCESS_FS_EXECUTE,
    write_file: ACCESS_FS_WRITE_FILE,
    read_file: ACCESS_FS_READ_FILE,
    read_dir: ACCESS_FS_READ_DIR,
    remove_dir: ACCESS_FS_REMOVE_DIR,
    remove_file: ACCESS_FS_REMOVE_FILE,
    make_char: ACCESS_FS_MAKE_CHAR,
    make_dir: ACCESS_FS_MAKE_DIR,
    make_reg: ACCESS_FS_MAKE_REG,
    make_sock: ACCESS_FS_MAKE_SOCK,
    make_fifo: ACCESS_FS_MAKE_FIFO,
    make_block: ACCESS_FS_MAKE_BLOCK,
    make_sym: ACCESS_FS_MAKE_SYM,
    refer: ACCESS_FS_REFER,
    truncate: ACCESS_FS_TRUNCATE,
    ioctl_dev: ACCESS_FS_IOCTL_DEV
  }.freeze

  NET_RIGHTS = {
    bind_tcp: ACCESS_NET_BIND_TCP,
    connect_tcp: ACCESS_NET_CONNECT_TCP
  }.freeze

  READ_RIGHTS = %i[read_file read_dir].freeze
  EXEC_RIGHTS = %i[execute read_file read_dir].freeze
  WRITE_RIGHTS = %i[
    read_file read_dir write_file truncate remove_dir remove_file make_char
    make_dir make_reg make_sock make_fifo make_block make_sym refer
  ].freeze

  module_function

  def supported?
    abi_version.positive?
  rescue Error
    false
  end

  def restrict!(read: [], write: [], execute: [], connect_tcp: [], bind_tcp: [], paths: [], allow_all_known: false)
    abi = abi_version
    raise UnsupportedError, "Linux Landlock is unavailable" unless abi.positive?

    fs_handled = allow_all_known ? _fs_rights_for_abi(abi) : _handled_fs_for(read:, write:, execute:, paths:, abi:)
    net_handled = _handled_net_for(connect_tcp:, bind_tcp:, abi:)

    if fs_handled.zero? && net_handled.zero?
      raise ArgumentError, "empty Landlock policy: provide filesystem paths or TCP ports"
    end

    fd = _create_ruleset(fs_handled, net_handled)
    begin
      add_path_rules(fd, read, READ_RIGHTS, abi)
      add_path_rules(fd, execute, EXEC_RIGHTS, abi)
      add_path_rules(fd, write, WRITE_RIGHTS, abi)

      paths.each do |rule|
        path, rights = normalize_path_rule(rule)
        _add_path_rule(fd, File.expand_path(path), mask(rights, FS_RIGHTS, abi))
      end

      add_net_rules(fd, connect_tcp, [:connect_tcp], abi)
      add_net_rules(fd, bind_tcp, [:bind_tcp], abi)

      _restrict_self(fd)
    ensure
      _close_fd(fd) if fd && fd >= 0
    end

    true
  end

  def exec(argv, read: [], write: [], execute: [], connect_tcp: [], bind_tcp: [], paths: [], chdir: nil, env: nil, unsetenv_others: false, close_others: true)
    argv = Array(argv)
    raise ArgumentError, "argv must not be empty" if argv.empty?

    pid = fork do
      # Safe after fork: this runs only in the child process before exec.
      Dir.chdir(chdir) if chdir # rubocop:disable Discourse/NoChdir
      restrict!(read:, write:, execute:, connect_tcp:, bind_tcp:, paths:)

      if env
        exec_env = unsetenv_others ? env : ENV.to_h.merge(env)
        Kernel.exec(exec_env, *argv, close_others: close_others)
      else
        Kernel.exec(*argv, close_others: close_others)
      end
    end

    _, status = Process.wait2(pid)
    status
  end

  def spawn(argv, **opts)
    argv = Array(argv)
    raise ArgumentError, "argv must not be empty" if argv.empty?

    fork do
      # Safe after fork: this runs only in the child process before exec.
      Dir.chdir(opts[:chdir]) if opts[:chdir] # rubocop:disable Discourse/NoChdir
      restrict!(
        read: opts.fetch(:read, []),
        write: opts.fetch(:write, []),
        execute: opts.fetch(:execute, []),
        connect_tcp: opts.fetch(:connect_tcp, []),
        bind_tcp: opts.fetch(:bind_tcp, []),
        paths: opts.fetch(:paths, [])
      )
      Kernel.exec(*argv, close_others: opts.fetch(:close_others, true))
    end
  end

  def add_path_rules(fd, paths, rights, abi)
    Array(paths).each { |path| _add_path_rule(fd, File.expand_path(path), mask(rights, FS_RIGHTS, abi)) }
  end
  private_class_method :add_path_rules

  def add_net_rules(fd, ports, rights, abi)
    return if Array(ports).empty?
    raise UnsupportedError, "Landlock network rules require ABI v4+; running ABI v#{abi}" if abi < 4

    Array(ports).each { |port| _add_net_rule(fd, Integer(port), mask(rights, NET_RIGHTS, abi)) }
  end
  private_class_method :add_net_rules

  def normalize_path_rule(rule)
    case rule
    when Hash
      [rule.fetch(:path), Array(rule.fetch(:rights))]
    when Array
      [rule.fetch(0), Array(rule.fetch(1))]
    else
      raise ArgumentError, "path rule must be {path:, rights:} or [path, rights]"
    end
  end
  private_class_method :normalize_path_rule

  def mask(names, table, abi)
    Array(names).reduce(0) do |bits, name|
      bit = table.fetch(name.to_sym) { raise ArgumentError, "unknown Landlock right: #{name.inspect}" }
      next bits if bit == ACCESS_FS_REFER && abi < 2
      next bits if bit == ACCESS_FS_TRUNCATE && abi < 3
      next bits if bit == ACCESS_FS_IOCTL_DEV && abi < 5
      bits | bit
    end
  end
  private_class_method :mask

  def _fs_rights_for_abi(abi)
    rights = FS_RIGHTS.values.reduce(0, :|)
    rights &= ~ACCESS_FS_REFER if abi < 2
    rights &= ~ACCESS_FS_TRUNCATE if abi < 3
    rights &= ~ACCESS_FS_IOCTL_DEV if abi < 5
    rights
  end

  def _handled_fs_for(read:, write:, execute:, paths:, abi:)
    bits = 0
    bits |= mask(READ_RIGHTS, FS_RIGHTS, abi) unless Array(read).empty?
    bits |= mask(EXEC_RIGHTS, FS_RIGHTS, abi) unless Array(execute).empty?
    bits |= mask(WRITE_RIGHTS, FS_RIGHTS, abi) unless Array(write).empty?
    Array(paths).each { |rule| bits |= mask(normalize_path_rule(rule).last, FS_RIGHTS, abi) }
    bits
  end
  private_class_method :_handled_fs_for

  def _handled_net_for(connect_tcp:, bind_tcp:, abi:)
    bits = 0
    bits |= ACCESS_NET_CONNECT_TCP unless Array(connect_tcp).empty?
    bits |= ACCESS_NET_BIND_TCP unless Array(bind_tcp).empty?
    return 0 if bits.zero?
    raise UnsupportedError, "Landlock network rules require ABI v4+; running ABI v#{abi}" if abi < 4
    bits
  end
  private_class_method :_handled_net_for
end
