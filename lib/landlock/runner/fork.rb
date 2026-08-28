# frozen_string_literal: true

require_relative "../errors"
require_relative "../native"
require_relative "../policy"
require_relative "../process_io"
require_relative "../rlimits"

module Landlock
  module Runner
    module Fork
      module_function

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
        fork do
          begin
            setup_child!(
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
          rescue Exception => error
            Runner.exit_child!(error)
          end
        end
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
        capture_pipes(timeout:, stdin:, max_output_bytes:, truncate_output:) do
          setup_child!(
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
            seccomp_deny_network:
          )
        rescue Exception => error
          Runner.exit_child!(error)
        end
      end

      def call_block(timeout:, stdin:, max_output_bytes:, truncate_output:, enforce_landlock:, **options, &block)
        capture_pipes(
          timeout:,
          stdin:,
          max_output_bytes:,
          truncate_output:,
          kill_process_group_on_parent_death: true
        ) do
          begin
            prepare_forked_block!(**options, enforce_landlock:)
          rescue Exception => error
            Runner.exit_child!(error)
          end

          block.call(STDOUT, STDERR)
          exit! 0
        rescue Exception => error
          Runner.exit_forked_block!(error)
        end
      end

      def capture_pipes(
        timeout:,
        stdin:,
        max_output_bytes:,
        truncate_output:,
        kill_process_group_on_parent_death: false
      )
        stdout_reader, stdout_writer = IO.pipe
        stderr_reader, stderr_writer = IO.pipe
        stdin_reader, stdin_writer = IO.pipe
        parent_pid = ::Process.pid

        pid =
          fork do
            begin
              # Arm group cleanup only after leaving the supervisor's process group.
              ::Process.setpgrp
              if kill_process_group_on_parent_death
                Landlock::Native.arm_parent_death_process_group!(parent_pid)
              else
                Landlock::Native.set_parent_death_signal!
                exit! 1 if ::Process.ppid != parent_pid
              end
              stdout_reader.close
              stderr_reader.close
              stdin_writer.close
              STDIN.reopen(stdin_reader)
              STDOUT.reopen(stdout_writer)
              STDERR.reopen(stderr_writer)
              STDOUT.sync = true
              STDERR.sync = true
              stdin_reader.close
              stdout_writer.close
              stderr_writer.close

              yield
            rescue Exception => error
              Runner.exit_child!(error, stderr: capture_error_stream(stderr_writer))
            end
          end

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
        if pid
          ProcessIO.terminate_process(pid)
          ProcessIO.wait_for_pid(pid)
        end
        raise
      ensure
        [stdin_reader, stdin_writer, stdout_reader, stdout_writer, stderr_reader, stderr_writer].each do |io|
          io&.close unless io.closed?
        rescue IOError
        end
      end

      def capture_error_stream(stderr_writer)
        stderr_writer && !stderr_writer.closed? ? stderr_writer : STDERR
      rescue IOError
        STDERR
      end

      def setup_child!(
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
        seccomp_deny_network:
      )
        Dir.chdir(chdir) if chdir # rubocop:disable Discourse/NoChdir
        if Policy.requested?(read:, write:, execute:, connect_tcp:, bind_tcp:, paths:, scope:, allow_all_known:)
          Landlock.restrict!(read:, write:, execute:, connect_tcp:, bind_tcp:, paths:, scope:, allow_all_known:)
        end
        Landlock::Native.seccomp_deny_network! if seccomp_deny_network
        Rlimits.apply!(rlimits)
        Kernel.exec(*Runner.kernel_exec_args(argv, env, unsetenv_others:, close_others:))
      end

      def prepare_forked_block!(
        chdir:,
        env:,
        unsetenv_others:,
        close_others:,
        rlimits:,
        seccomp_deny_network:,
        enforce_landlock:,
        **policy
      )
        close_inherited_ios if close_others
        Dir.public_send(:chdir, chdir) if chdir
        ENV.clear if unsetenv_others
        env&.each { |key, value| value.nil? ? ENV.delete(key) : ENV[key] = value }
        Landlock.restrict!(**policy) if enforce_landlock && Policy.requested?(**policy)
        Landlock::Native.seccomp_deny_network! if seccomp_deny_network
        Rlimits.apply!(rlimits)
      end

      def close_inherited_ios
        ObjectSpace
          .each_object(IO)
          .to_a
          .each do |io|
            next if io.closed? || io.fileno <= 2

            io.close
          rescue IOError
          end

        Landlock::Native.close_inherited_fds!
      end
    end
  end
end
