# frozen_string_literal: true

require_relative "env"
require_relative "native"
require_relative "policy"
require_relative "result"
require_relative "rlimits"
require_relative "runner"
require_relative "validation"

module Landlock
  module Execution
    module_function

    def exec(
      argv,
      read: [],
      write: [],
      execute: [],
      connect_tcp: [],
      bind_tcp: [],
      paths: [],
      scope: [],
      chdir: nil,
      env: nil,
      unsetenv_others: false,
      close_others: true,
      allow_all_known: false
    )
      pid =
        spawn(
          argv,
          read:,
          write:,
          execute:,
          connect_tcp:,
          bind_tcp:,
          paths:,
          scope:,
          chdir:,
          env:,
          unsetenv_others:,
          close_others:,
          allow_all_known:
        )
      _, status = ::Process.wait2(pid)
      status
    end

    def spawn(
      argv,
      read: [],
      write: [],
      execute: [],
      connect_tcp: [],
      bind_tcp: [],
      paths: [],
      scope: [],
      chdir: nil,
      env: nil,
      unsetenv_others: false,
      close_others: true,
      allow_all_known: false
    )
      argv = Validation.normalize_argv(argv).map(&:to_s)
      ensure_landlock_supported!
      env = Env.normalize(env)
      policy =
        prepare_policy(read:, write:, execute:, connect_tcp:, bind_tcp:, paths:, scope:, chdir:, allow_all_known:)
      validate_landlock_restriction!(**policy)

      spawn_with_runner(argv, **policy, chdir:, env:, unsetenv_others:, close_others:)
    end

    def capture(argv, **options)
      capture_with(argv, raise_on_failure: false, **options)
    end

    def capture!(argv, **options)
      capture_with(argv, raise_on_failure: true, **options)
    end

    def capture_with(
      argv,
      read: [],
      write: [],
      execute: [],
      connect_tcp: [],
      bind_tcp: [],
      paths: [],
      scope: [],
      chdir: nil,
      env: nil,
      unsetenv_others: false,
      close_others: true,
      allow_all_known: false,
      timeout: nil,
      stdin: nil,
      rlimits: {},
      seccomp_deny_network: false,
      max_output_bytes: nil,
      truncate_output: false,
      success_status_codes: [0],
      failure_message: "",
      raise_on_failure:
    )
      argv = Validation.normalize_argv(argv).map(&:to_s)
      ensure_landlock_supported!
      max_output_bytes = Validation.validate_output_limit!(max_output_bytes)
      timeout = Validation.validate_timeout!(timeout)
      normalized_rlimits = Rlimits.normalize(rlimits)
      env = Env.normalize(env)
      policy =
        prepare_policy(read:, write:, execute:, connect_tcp:, bind_tcp:, paths:, scope:, chdir:, allow_all_known:)
      validate_capture_restriction!(**policy, seccomp_deny_network:, rlimits: normalized_rlimits)

      result =
        call_with_runner(
          argv,
          **policy,
          chdir:,
          env:,
          unsetenv_others:,
          close_others:,
          timeout:,
          stdin:,
          rlimits: normalized_rlimits,
          seccomp_deny_network:,
          max_output_bytes:,
          truncate_output:
        )

      if raise_on_failure &&
           (result.timed_out? || !result.status.exited? || !success_status_codes.include?(result.status.exitstatus))
        message = [argv.join(" "), failure_message, result.stderr].filter { |part| part.to_s != "" }.join("\n")
        raise CommandError.new(message, stdout: result.stdout, stderr: result.stderr, status: result.status, result:)
      end

      result
    rescue OutputTooLargeError => e
      message = [argv&.join(" "), failure_message, e.message].filter { |part| part.to_s != "" }.join("\n")
      result = e.result
      raise CommandError.new(
              message,
              stdout: result&.stdout.to_s,
              stderr: result&.stderr.to_s,
              status: result&.status,
              result:
            )
    end

    def spawn_with_runner(argv, **options)
      if Runner::Native.available?
        begin
          return Runner::Native.spawn(argv, **options)
        rescue Errno::E2BIG
          return Runner::Fork.spawn(argv, **options)
        end
      end

      Runner::Fork.spawn(argv, **options)
    end

    def call_with_runner(argv, **options)
      if Runner::Native.available?
        begin
          return Runner::Native.call(argv, **options)
        rescue Errno::E2BIG
          return Runner::Fork.call(argv, **options)
        end
      end

      Runner::Fork.call(argv, **options)
    end

    def ensure_landlock_supported!
      raise UnsupportedError, "Linux Landlock is unavailable" unless Native.abi_version.positive?
    end

    def prepare_policy(read:, write:, execute:, connect_tcp:, bind_tcp:, paths:, scope:, chdir:, allow_all_known:)
      connect_tcp = Validation.normalize_ports(connect_tcp, :connect_tcp)
      bind_tcp = Validation.normalize_ports(bind_tcp, :bind_tcp)
      read, write, execute, paths = validate_policy_paths!(read:, write:, execute:, paths:, chdir:)
      { read:, write:, execute:, connect_tcp:, bind_tcp:, paths:, scope:, allow_all_known: }
    end

    def validate_landlock_restriction!(
      read:,
      write:,
      execute:,
      connect_tcp:,
      bind_tcp:,
      paths:,
      scope:,
      allow_all_known:
    )
      return if Policy.requested?(read:, write:, execute:, connect_tcp:, bind_tcp:, paths:, scope:, allow_all_known:)

      raise ArgumentError, "empty Landlock policy: provide filesystem paths, TCP ports, or scopes"
    end

    def validate_capture_restriction!(
      read:,
      write:,
      execute:,
      connect_tcp:,
      bind_tcp:,
      paths:,
      scope:,
      allow_all_known:,
      seccomp_deny_network:,
      rlimits:
    )
      return if Policy.requested?(read:, write:, execute:, connect_tcp:, bind_tcp:, paths:, scope:, allow_all_known:)
      return if seccomp_deny_network
      return if Array(rlimits).any?

      raise ArgumentError, "empty capture policy: provide Landlock rules, seccomp_deny_network, or rlimits"
    end

    def validate_policy_paths!(read:, write:, execute:, paths:, chdir:)
      base = chdir ? File.expand_path(chdir) : Dir.pwd
      abi = Native.abi_version
      read = Validation.validate_existing_paths(read, :read, chdir:)
      write = Validation.validate_existing_paths(write, :write, chdir:)
      execute = Validation.validate_existing_paths(execute, :execute, chdir:)
      paths =
        Array(paths).map do |rule|
          path, rights = Policy.normalize_path_rule(rule)
          Validation.validate_existing_path!(path, :path, base)
          Policy.path_rule_access_mask(File.expand_path(path, base), rights, abi)
          { path: path.to_s, rights: }
        end

      [read, write, execute, paths]
    end
  end
end
