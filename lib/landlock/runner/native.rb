# frozen_string_literal: true

require "rbconfig"
require_relative "../errors"
require_relative "../policy"
require_relative "../process_io"

module Landlock
  module Runner
    module Native
      # Starts the native helper with the sandbox policy encoded as argv flags.
      # The helper applies the policy, then execs the target command so the
      # long-lived child is not a forked Ruby process.
      module_function

      def available?
        File.executable?(helper_path)
      end

      def helper_path
        candidates = [
          File.expand_path("../landlock-safe-exec", __dir__),
          File.expand_path(
            "../../../tmp/#{RbConfig::CONFIG.fetch("arch")}/landlock/#{RUBY_VERSION}/landlock-safe-exec",
            __dir__
          ),
          File.expand_path("../../../ext/landlock/landlock-safe-exec", __dir__)
        ]
        candidates.find { |path| File.executable?(path) } || candidates.first
      end

      def spawn(
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
        spawn_helper(
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
          allow_all_known:,
          rlimits: [],
          seccomp_deny_network: false
        )
      end

      def call(
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
        allow_all_known:,
        timeout:,
        stdin:,
        rlimits:,
        seccomp_deny_network:,
        max_output_bytes:,
        truncate_output:
      )
        stdout_reader, stdout_writer = IO.pipe
        stderr_reader, stderr_writer = IO.pipe
        stdin_reader, stdin_writer = IO.pipe

        pid =
          spawn_helper(
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
            allow_all_known:,
            rlimits:,
            seccomp_deny_network:,
            stdin_reader:,
            stdout_writer:,
            stderr_writer:,
            pgroup: true
          )

        stdin_reader.close
        stdout_writer.close
        stderr_writer.close

        ProcessIO.complete_pipe_capture(
          pid,
          stdout_reader,
          stderr_reader,
          stdin_writer,
          stdin,
          timeout,
          max_output_bytes,
          truncate_output
        )
      rescue OutputTooLargeError
        raise
      rescue Exception
        ProcessIO.terminate_and_wait(pid) if pid
        raise
      ensure
        [stdin_reader, stdin_writer, stdout_reader, stdout_writer, stderr_reader, stderr_writer].each do |io|
          io&.close unless io.closed?
        rescue IOError
        end
      end

      def spawn_helper(
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
        allow_all_known:,
        rlimits:,
        seccomp_deny_network:,
        stdin_reader: nil,
        stdout_writer: nil,
        stderr_writer: nil,
        pgroup: false
      )
        spawn_options = { close_others: }
        spawn_options[:unsetenv_others] = true if unsetenv_others
        spawn_options[:chdir] = chdir if chdir
        spawn_options[:in] = stdin_reader if stdin_reader
        spawn_options[:out] = stdout_writer if stdout_writer
        spawn_options[:err] = stderr_writer if stderr_writer
        spawn_options[:pgroup] = true if pgroup

        spawn_args =
          helper_argv(
            argv,
            read:,
            write:,
            execute:,
            connect_tcp:,
            bind_tcp:,
            paths:,
            scope:,
            allow_all_known:,
            rlimits:,
            seccomp_deny_network:,
            close_others:
          )
        env ? ::Process.spawn(env, *spawn_args, spawn_options) : ::Process.spawn(*spawn_args, spawn_options)
      end

      def helper_argv(
        argv,
        read:,
        write:,
        execute:,
        connect_tcp:,
        bind_tcp:,
        paths:,
        scope:,
        allow_all_known:,
        rlimits:,
        seccomp_deny_network:,
        close_others:
      )
        args = [helper_path]
        emit_rules(args, "--read", read)
        emit_rules(args, "--write", write)
        emit_rules(args, "--execute", execute)
        Array(paths).each do |rule|
          path, rights = Policy.normalize_path_rule(rule)
          args << "--path" << path.to_s << Array(rights).map(&:to_s).join(",")
        end
        emit_rules(args, "--connect-tcp", connect_tcp)
        emit_rules(args, "--bind-tcp", bind_tcp)
        Array(scope).each { |name| args << "--scope" << name.to_s }
        Array(rlimits).each { |key, value| args << "--rlimit" << "#{key}=#{value}" }
        args << "--allow-all-known" if allow_all_known
        args << "--seccomp-deny-network" if seccomp_deny_network
        args << "--keep-fds" unless close_others
        args << "--"
        args.concat(argv.map(&:to_s))
        args
      end

      # An empty value keeps the rights in the handled mask while granting
      # nothing; the empty string is never a valid path or port, so it cannot
      # collide with a real entry.
      def emit_rules(args, flag, values)
        return if values.nil?
        return args.push(flag, "") if Array(values).empty?

        Array(values).each { |value| args.push(flag, value.to_s) }
      end
    end
  end
end
