# frozen_string_literal: true

require_relative "native"
require_relative "rights"

module Landlock
  module Policy
    module_function

    def restrict!(
      read: nil,
      write: nil,
      execute: nil,
      connect_tcp: nil,
      bind_tcp: nil,
      paths: nil,
      scope: nil,
      allow_all_known: false
    )
      abi = Native.abi_version
      raise UnsupportedError, "Linux Landlock is unavailable" unless abi.positive?

      fs_handled =
        (
          if allow_all_known
            fs_rights_for_abi(abi)
          else
            handled_fs_for(read:, write:, execute:, paths:, abi:)
          end
        )
      net_handled = handled_net_for(connect_tcp:, bind_tcp:, abi:)
      scoped = scope_for(scope:, abi:)

      if fs_handled.zero? && net_handled.zero? && scoped.zero?
        raise ArgumentError, "empty Landlock policy: provide filesystem paths, TCP ports, or scopes"
      end

      fd = Native.create_ruleset(fs_handled, net_handled, scoped)
      begin
        add_path_rules(fd, read, READ_RIGHTS, abi)
        add_path_rules(fd, execute, EXEC_RIGHTS, abi)
        add_path_rules(fd, write, WRITE_RIGHTS, abi)

        Array(paths).each do |rule|
          path, rights = normalize_path_rule(rule)
          expanded_path = File.expand_path(path)
          access_mask = path_rule_access_mask(expanded_path, rights, abi)

          Native.add_path_rule(fd, expanded_path, access_mask)
        end

        add_net_rules(fd, connect_tcp, [:connect_tcp], abi)
        add_net_rules(fd, bind_tcp, [:bind_tcp], abi)

        Native.restrict_self(fd)
      ensure
        Native.close_fd(fd) if fd && fd >= 0
      end

      true
    end

    def requested?(read:, write:, execute:, connect_tcp:, bind_tcp:, paths:, scope:, allow_all_known:)
      allow_all_known || !read.nil? || !write.nil? || !execute.nil? || !connect_tcp.nil? || !bind_tcp.nil? ||
        !Array(paths).empty? || !Array(scope).empty?
    end

    def path_rights(path, rights)
      File.directory?(path) ? rights : Array(rights) & FILE_PATH_RIGHTS
    end

    def path_rule_access_mask(path, rights, abi)
      mask(path_rights(path, rights), FS_RIGHTS, abi).tap do |access_mask|
        raise ArgumentError, "path rule has no effective rights: #{path}" if access_mask.zero?
      end
    end

    def add_path_rules(fd, paths, rights, abi)
      Array(paths).each do |path|
        expanded_path = File.expand_path(path)
        access_mask = mask(path_rights(expanded_path, rights), FS_RIGHTS, abi)
        next if access_mask.zero?

        Native.add_path_rule(fd, expanded_path, access_mask)
      end
    end

    def add_net_rules(fd, ports, rights, abi)
      ports = Array(ports)
      return if ports.empty?
      raise UnsupportedError, "Landlock network rules require ABI v4+; running ABI v#{abi}" if abi < 4

      access_mask = mask(rights, NET_RIGHTS, abi)
      return if access_mask.zero?

      ports.each { |port| Native.add_net_rule(fd, Integer(port), access_mask) }
    end

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

    def mask(names, table, abi)
      Array(names).reduce(0) do |bits, name|
        bit = table.fetch(name.to_sym) { raise ArgumentError, "unknown Landlock right: #{name.inspect}" }
        next bits if bit == ACCESS_FS_REFER && abi < 2
        next bits if bit == ACCESS_FS_TRUNCATE && abi < 3
        next bits if bit == ACCESS_FS_IOCTL_DEV && abi < 5

        bits | bit
      end
    end

    def fs_rights_for_abi(abi)
      rights = FS_RIGHTS.values.reduce(0, :|)
      rights &= ~ACCESS_FS_REFER if abi < 2
      rights &= ~ACCESS_FS_TRUNCATE if abi < 3
      rights &= ~ACCESS_FS_IOCTL_DEV if abi < 5
      rights
    end

    # Landlock leaves any right absent from handled_access_fs unrestricted
    # kernel-wide, so nil (do not police this class) and [] (police it, grant
    # nothing) must produce different masks.
    def handled_fs_for(read:, write:, execute:, paths:, abi:)
      bits = 0
      bits |= mask(READ_RIGHTS, FS_RIGHTS, abi) unless read.nil?
      bits |= mask(EXEC_RIGHTS, FS_RIGHTS, abi) unless execute.nil?
      bits |= mask(WRITE_RIGHTS, FS_RIGHTS, abi) unless write.nil?
      Array(paths).each do |rule|
        path, rights = normalize_path_rule(rule)
        bits |= path_rule_access_mask(File.expand_path(path), rights, abi)
      end
      bits
    end

    def handled_net_for(connect_tcp:, bind_tcp:, abi:)
      bits = 0
      bits |= ACCESS_NET_CONNECT_TCP unless connect_tcp.nil?
      bits |= ACCESS_NET_BIND_TCP unless bind_tcp.nil?
      return 0 if bits.zero?

      raise UnsupportedError, "Landlock network rules require ABI v4+; running ABI v#{abi}" if abi < 4

      bits
    end

    def scope_for(scope:, abi:)
      bits = mask(scope, SCOPE_FLAGS, abi)
      return 0 if bits.zero?

      raise UnsupportedError, "Landlock scopes require ABI v6+; running ABI v#{abi}" if abi < 6

      bits
    end
  end
end
