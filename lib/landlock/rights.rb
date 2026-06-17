# frozen_string_literal: true

require_relative "native"

module Landlock
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

  NET_RIGHTS = { bind_tcp: ACCESS_NET_BIND_TCP, connect_tcp: ACCESS_NET_CONNECT_TCP }.freeze

  SCOPE_FLAGS = { abstract_unix_socket: SCOPE_ABSTRACT_UNIX_SOCKET, signal: SCOPE_SIGNAL }.freeze

  READ_RIGHTS = %i[read_file read_dir].freeze
  EXEC_RIGHTS = %i[execute read_file read_dir].freeze
  WRITE_RIGHTS = %i[
    read_file
    read_dir
    write_file
    truncate
    remove_dir
    remove_file
    make_char
    make_dir
    make_reg
    make_sock
    make_fifo
    make_block
    make_sym
    refer
  ].freeze
  FILE_PATH_RIGHTS = %i[execute write_file read_file truncate ioctl_dev].freeze
end
