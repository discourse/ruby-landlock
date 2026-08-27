# frozen_string_literal: true

module Landlock
  module Runner
    module_function

    def argv_for_exec(argv)
      command = argv.fetch(0)
      [[command, command], *argv.drop(1)]
    end

    def kernel_exec_args(argv, env, unsetenv_others:, close_others:)
      exec_options = { close_others: }
      exec_options[:unsetenv_others] = true if unsetenv_others

      env ? [env, *argv_for_exec(argv), exec_options] : [*argv_for_exec(argv), exec_options]
    end

    def exit_child!(error)
      warn "Landlock child failed before exec: #{error.class}: #{error.message}"
    ensure
      exit! 127
    end

    def exit_forked_block!(error)
      warn "Landlock forked block failed: #{error.class}: #{error.message}"
    ensure
      exit! 1
    end
  end
end

require_relative "runner/fork"
require_relative "runner/native"
