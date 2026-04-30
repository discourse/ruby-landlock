# frozen_string_literal: true

require_relative "landlock/version"
require_relative "landlock/landlock"
require_relative "landlock/safe_exec"

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

  SCOPE_FLAGS = {
    abstract_unix_socket: SCOPE_ABSTRACT_UNIX_SOCKET,
    signal: SCOPE_SIGNAL
  }.freeze

  READ_RIGHTS = %i[read_file read_dir].freeze
  EXEC_RIGHTS = %i[execute read_file read_dir].freeze
  WRITE_RIGHTS = %i[
    read_file read_dir write_file truncate remove_dir remove_file make_char
    make_dir make_reg make_sock make_fifo make_block make_sym refer
  ].freeze
  FILE_PATH_RIGHTS = %i[execute write_file read_file truncate ioctl_dev].freeze

  module_function

  def supported?
    abi_version.positive?
  rescue Error
    false
  end

  def restrict!(read: [], write: [], execute: [], connect_tcp: [], bind_tcp: [], paths: [], scope: [], allow_all_known: false)
    abi = abi_version
    raise UnsupportedError, "Linux Landlock is unavailable" unless abi.positive?

    fs_handled = allow_all_known ? _fs_rights_for_abi(abi) : _handled_fs_for(read:, write:, execute:, paths:, abi:)
    net_handled = _handled_net_for(connect_tcp:, bind_tcp:, abi:)
    scoped = _scope_for(scope:, abi:)

    if fs_handled.zero? && net_handled.zero? && scoped.zero?
      raise ArgumentError, "empty Landlock policy: provide filesystem paths, TCP ports, or scopes"
    end

    fd = _create_ruleset(fs_handled, net_handled, scoped)
    begin
      add_path_rules(fd, read, READ_RIGHTS, abi)
      add_path_rules(fd, execute, EXEC_RIGHTS, abi)
      add_path_rules(fd, write, WRITE_RIGHTS, abi)

      paths.each do |rule|
        path, rights = normalize_path_rule(rule)
        access_mask = mask(rights, FS_RIGHTS, abi)
        next if access_mask.zero?

        _add_path_rule(fd, File.expand_path(path), access_mask)
      end

      add_net_rules(fd, connect_tcp, [:connect_tcp], abi)
      add_net_rules(fd, bind_tcp, [:bind_tcp], abi)

      _restrict_self(fd)
    ensure
      _close_fd(fd) if fd && fd >= 0
    end

    true
  end

  def exec(argv, read: [], write: [], execute: [], connect_tcp: [], bind_tcp: [], paths: [], scope: [], chdir: nil, env: nil, unsetenv_others: false, close_others: true, allow_all_known: false)
    argv = normalize_argv(argv)
    ensure_landlock_supported!

    pid = fork do
      begin
        # Safe after fork: this runs only in the child process before exec.
        Dir.chdir(chdir) if chdir # rubocop:disable Discourse/NoChdir
        restrict!(read:, write:, execute:, connect_tcp:, bind_tcp:, paths:, scope:, allow_all_known:)

        Kernel.exec(*kernel_exec_args(argv, env, unsetenv_others:, close_others:))
      rescue Exception => error
        exit_child!(error)
      end
    end

    _, status = Process.wait2(pid)
    status
  end

  def spawn(argv, read: [], write: [], execute: [], connect_tcp: [], bind_tcp: [], paths: [], scope: [], chdir: nil, env: nil, unsetenv_others: false, close_others: true, allow_all_known: false)
    argv = normalize_argv(argv)
    ensure_landlock_supported!

    fork do
      begin
        # Safe after fork: this runs only in the child process before exec.
        Dir.chdir(chdir) if chdir # rubocop:disable Discourse/NoChdir
        restrict!(read:, write:, execute:, connect_tcp:, bind_tcp:, paths:, scope:, allow_all_known:)
        Kernel.exec(*kernel_exec_args(argv, env, unsetenv_others:, close_others:))
      rescue Exception => error
        exit_child!(error)
      end
    end
  end

  def normalize_argv(argv)
    raise ArgumentError, "argv must be an Array of command arguments" unless argv.is_a?(Array)
    raise ArgumentError, "argv must not be empty" if argv.empty?

    argv
  end
  private_class_method :normalize_argv

  def argv_for_exec(argv)
    command = argv.fetch(0)
    [[command, command], *argv.drop(1)]
  end
  private_class_method :argv_for_exec

  def kernel_exec_args(argv, env, unsetenv_others:, close_others:)
    exec_options = { close_others: close_others }
    exec_options[:unsetenv_others] = true if unsetenv_others

    if env
      [env, *argv_for_exec(argv), exec_options]
    else
      [*argv_for_exec(argv), exec_options]
    end
  end
  private_class_method :kernel_exec_args

  def ensure_landlock_supported!
    raise UnsupportedError, "Linux Landlock is unavailable" unless abi_version.positive?
  end
  private_class_method :ensure_landlock_supported!

  def exit_child!(error)
    warn "Landlock child failed before exec: #{error.class}: #{error.message}"
  ensure
    exit! 127
  end
  private_class_method :exit_child!

  def path_rights(path, rights)
    File.directory?(path) ? rights : Array(rights) & FILE_PATH_RIGHTS
  end
  private_class_method :path_rights

  def add_path_rules(fd, paths, rights, abi)
    Array(paths).each do |path|
      expanded_path = File.expand_path(path)
      access_mask = mask(path_rights(expanded_path, rights), FS_RIGHTS, abi)
      next if access_mask.zero?

      _add_path_rule(fd, expanded_path, access_mask)
    end
  end
  private_class_method :add_path_rules

  def add_net_rules(fd, ports, rights, abi)
    ports = Array(ports)
    return if ports.empty?
    raise UnsupportedError, "Landlock network rules require ABI v4+; running ABI v#{abi}" if abi < 4

    access_mask = mask(rights, NET_RIGHTS, abi)
    return if access_mask.zero?

    ports.each { |port| _add_net_rule(fd, Integer(port), access_mask) }
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

  def _scope_for(scope:, abi:)
    bits = mask(scope, SCOPE_FLAGS, abi)
    return 0 if bits.zero?
    raise UnsupportedError, "Landlock scopes require ABI v6+; running ABI v#{abi}" if abi < 6

    bits
  end
  private_class_method :_scope_for
end
