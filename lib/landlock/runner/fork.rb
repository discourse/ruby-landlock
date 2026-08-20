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
        stdout_reader, stdout_writer = IO.pipe
        stderr_reader, stderr_writer = IO.pipe
        stdin_reader, stdin_writer = IO.pipe

        pid =
          fork do
            begin
              stdout_reader.close
              stderr_reader.close
              stdin_writer.close
              ::Process.setpgrp
              STDIN.reopen(stdin_reader)
              STDOUT.reopen(stdout_writer)
              STDERR.reopen(stderr_writer)
              stdin_reader.close
              stdout_writer.close
              stderr_writer.close

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
    end
  end
end
