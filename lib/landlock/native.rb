# frozen_string_literal: true

require_relative "errors"
require_relative "landlock"
require_relative "result"

module Landlock
  module Native
    module_function

    def abi_version
      Landlock.abi_version
    end

    def create_ruleset(fs_handled, net_handled, scoped)
      Landlock.__send__(:_create_ruleset, fs_handled, net_handled, scoped)
    end

    def add_path_rule(fd, path, access_mask)
      Landlock.__send__(:_add_path_rule, fd, path, access_mask)
    end

    def add_net_rule(fd, port, access_mask)
      Landlock.__send__(:_add_net_rule, fd, port, access_mask)
    end

    def restrict_self(fd)
      Landlock.__send__(:_restrict_self, fd)
    end

    def close_fd(fd)
      Landlock.__send__(:_close_fd, fd)
    end

    def wait4(pid, flags)
      result = Landlock.__send__(:_wait4, pid, flags)
      return unless result

      status, user_seconds, system_seconds, max_rss_bytes = result
      [status, ResourceUsage.new(user_seconds:, system_seconds:, max_rss_bytes:)]
    end

    def seccomp_deny_network!
      Landlock.seccomp_deny_network!
    end
  end
end
