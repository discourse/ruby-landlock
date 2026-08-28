# frozen_string_literal: true

require_relative "errors"
require_relative "landlock"

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

    def close_inherited_fds!
      Landlock.__send__(:_close_inherited_fds)
    end

    def pidfd_open(pid)
      Landlock.__send__(:_pidfd_open, pid)
    end

    def set_parent_death_signal!
      Landlock.__send__(:_set_parent_death_signal)
    end

    def seccomp_deny_network!
      Landlock.seccomp_deny_network!
    end
  end
end
