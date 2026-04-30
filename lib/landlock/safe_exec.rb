# frozen_string_literal: true

require "open3"
require "rbconfig"
require "timeout"
require_relative "landlock"

module Landlock
  class SafeExec
    Error = Class.new(StandardError)
    OutputTooLargeError = Class.new(Error)

    class CommandError < Error
      attr_reader :stdout, :stderr, :status, :result

      def initialize(message, stdout: "", stderr: "", status: nil, result: nil)
        @stdout = stdout
        @stderr = stderr
        @status = status
        @result = result
        super(message)
      end
    end

    class Result
      attr_reader :stdout, :stderr, :status

      def initialize(stdout:, stderr:, status:, output_truncated: false, timed_out: false)
        @stdout = stdout
        @stderr = stderr
        @status = status
        @output_truncated = output_truncated
        @timed_out = timed_out
      end

      def success?
        !timed_out? && status&.success?
      end

      def output_truncated?
        @output_truncated
      end

      def timed_out?
        @timed_out
      end

      def to_ary
        [stdout, stderr, status]
      end

      def to_s
        stdout.to_s
      end

      def inspect
        "#<#{self.class} status=#{status.inspect} timed_out=#{timed_out?} output_truncated=#{output_truncated?} stdout=#{stdout.inspect} stderr=#{stderr.inspect}>"
      end
    end

    DEFAULT_READ_PATHS = %w[/bin /etc /lib /lib64 /usr].freeze
    DEFAULT_EXECUTE_PATHS = %w[/bin /lib /lib64 /usr].freeze
    READ_CHUNK_BYTES = 16 * 1024

    class << self
      def capture(*command, **options)
        perform_capture(*command, raise_on_failure: false, **options)
      end

      def capture!(*command, **options)
        perform_capture(*command, raise_on_failure: true, **options)
      end

      def perform_capture(
        *command,
        read: [],
        write: [],
        execute: [],
        timeout: nil,
        failure_message: "",
        success_status_codes: [0],
        env: {},
        inherit_env: false,
        chdir: nil,
        stdin: nil,
        connect_tcp: nil,
        bind_tcp: [],
        rlimits: {},
        seccomp_deny_network: false,
        max_output_bytes: nil,
        truncate_output: false,
        allow_all_known: true,
        raise_on_failure:
      )
        validate_sandbox_option_values!(connect_tcp: connect_tcp, bind_tcp: bind_tcp)

        unsupported_options = unsupported_sandbox_options(
          read: read,
          write: write,
          execute: execute,
          connect_tcp: connect_tcp,
          bind_tcp: bind_tcp,
          seccomp_deny_network: seccomp_deny_network
        )
        use_helper = helper_available?
        warn_unsupported_platform_once(unsupported_options) if !use_helper && unsupported_options.any?

        stdout, stderr, status, output_truncated, timed_out = if use_helper
          max_output_bytes = validate_output_limit!(max_output_bytes)
          capture_process(
            command,
            read: read,
            write: write,
            execute: execute,
            timeout: timeout,
            env: env,
            inherit_env: inherit_env,
            chdir: chdir,
            stdin: stdin,
            connect_tcp: connect_tcp,
            bind_tcp: bind_tcp,
            rlimits: rlimits,
            seccomp_deny_network: seccomp_deny_network,
            max_output_bytes: max_output_bytes,
            truncate_output: truncate_output,
            allow_all_known: allow_all_known
          )
        else
          max_output_bytes = validate_output_limit!(max_output_bytes)
          capture_process_without_helper(
            command,
            timeout: timeout,
            env: env,
            inherit_env: inherit_env,
            chdir: chdir,
            stdin: stdin,
            rlimits: rlimits,
            max_output_bytes: max_output_bytes,
            truncate_output: truncate_output
          )
        end

        result = Result.new(stdout: stdout, stderr: stderr, status: status, output_truncated: output_truncated, timed_out: timed_out)

        if raise_on_failure && (!status.exited? || !success_status_codes.include?(status.exitstatus))
          message = [command.join(" "), failure_message, stderr].filter { |part| part.to_s != "" }.join("\n")
          raise CommandError.new(message, stdout: stdout, stderr: stderr, status: status, result: result)
        end

        result
      rescue OutputTooLargeError => e
        message = [command.join(" "), failure_message, e.message].filter { |part| part.to_s != "" }.join("\n")
        raise CommandError.new(message)
      end
      private :perform_capture

      def supported?
        helper_available? && Landlock.supported?
      end

      def sandboxing?
        supported?
      end

      def helper_path
        candidates = [
          File.expand_path("landlock-safe-exec", __dir__),
          File.expand_path("../../tmp/#{RbConfig::CONFIG.fetch("arch")}/landlock/#{RUBY_VERSION}/landlock-safe-exec", __dir__),
          File.expand_path("../../ext/landlock/landlock-safe-exec", __dir__)
        ]
        candidates.find { |path| File.executable?(path) } || candidates.first
      end

      def default_read_paths
        existing_paths(DEFAULT_READ_PATHS)
      end

      def default_execute_paths
        existing_paths(DEFAULT_EXECUTE_PATHS)
      end

      def existing_paths(paths)
        Array(paths).filter { |path| path.to_s != "" && File.exist?(path) }.uniq
      end

      private

      def helper_available?
        RUBY_PLATFORM.include?("linux") && File.executable?(helper_path)
      end

      def validate_sandbox_option_values!(connect_tcp:, bind_tcp:)
        normalized_ports(connect_tcp, :connect_tcp) if !connect_tcp.nil?
        normalized_ports(bind_tcp, :bind_tcp)
      end

      def unsupported_sandbox_options(read:, write:, execute:, connect_tcp:, bind_tcp:, seccomp_deny_network:)
        options = []
        options << :read if Array(read).any?
        options << :write if Array(write).any?
        options << :execute if Array(execute).any?
        options << :connect_tcp if !connect_tcp.nil?
        options << :bind_tcp if Array(bind_tcp).any?
        options << :seccomp_deny_network if seccomp_deny_network
        options
      end

      def warn_unsupported_platform_once(options)
        return if @warned_unsupported_sandbox

        @warned_unsupported_sandbox = true
        warn(
          "Landlock::SafeExec sandbox options #{options.join(", ")} are unavailable without the Linux " \
            "landlock-safe-exec helper; running command as a pass-through with those restrictions ignored"
        )
      end

      def validate_output_limit!(max_output_bytes)
        return if max_output_bytes.nil?

        Integer(max_output_bytes).tap do |value|
          raise ArgumentError, "max_output_bytes must be non-negative" if value.negative?
        end
      end

      def capture_process_without_helper(
        command,
        timeout:,
        env:,
        inherit_env:,
        chdir:,
        stdin:,
        rlimits:,
        max_output_bytes:,
        truncate_output:
      )
        argv = normalize_command(command)
        spawn_options = fallback_spawn_options(
          inherit_env: inherit_env,
          chdir: chdir,
          rlimits: rlimits
        )
        popen_args = [env || {}, *argv, spawn_options]

        output_state = { bytes: 0, truncated: false }
        output_mutex = Mutex.new
        stdout = stderr = status = nil
        timed_out = false

        Open3.popen3(*popen_args) do |stdin_io, stdout_io, stderr_io, wait_thread|
          stdin_thread = write_process_input(stdin_io, stdin)
          stdout_thread = Thread.new do
            Thread.current.report_on_exception = false
            read_process_output(stdout_io, max_output_bytes, truncate_output, output_state, output_mutex, wait_thread.pid)
          end
          stderr_thread = Thread.new do
            Thread.current.report_on_exception = false
            read_process_output(stderr_io, max_output_bytes, truncate_output, output_state, output_mutex, wait_thread.pid)
          end

          status, timed_out = wait_for_process(wait_thread, timeout)
          stdin_thread&.value
          stdout = stdout_thread.value
          stderr = stderr_thread.value
        end

        [stdout, stderr, status, output_state[:truncated], timed_out]
      end

      def fallback_spawn_options(inherit_env:, chdir:, rlimits:)
        options = { close_others: true, pgroup: true }
        options[:unsetenv_others] = true if !inherit_env
        options[:chdir] = chdir if chdir
        options.merge!(rlimit_spawn_options(rlimits))
        options
      end

      def rlimit_spawn_options(rlimits)
        normalized_rlimits(rlimits).to_h do |key, value|
          [rlimit_spawn_key(key), [value, value]]
        end
      end

      def rlimit_spawn_key(name)
        case name
        when :cpu_seconds
          :rlimit_cpu
        when :memory_bytes
          :rlimit_as
        when :file_size_bytes
          :rlimit_fsize
        when :open_files
          :rlimit_nofile
        when :processes
          :rlimit_nproc
        end
      end

      def normalize_command(command)
        raise ArgumentError, "command must not be empty" if command.empty?

        command.map(&:to_s)
      end

      def capture_process(
        command,
        read:,
        write:,
        execute:,
        timeout:,
        env:,
        inherit_env:,
        chdir:,
        stdin:,
        connect_tcp:,
        bind_tcp:,
        rlimits:,
        seccomp_deny_network:,
        max_output_bytes:,
        truncate_output:,
        allow_all_known:
      )
        argv = helper_argv(
          command,
          read: read,
          write: write,
          execute: execute,
          env: env,
          inherit_env: inherit_env,
          chdir: chdir,
          connect_tcp: connect_tcp,
          bind_tcp: bind_tcp,
          rlimits: rlimits,
          seccomp_deny_network: seccomp_deny_network,
          allow_all_known: allow_all_known
        )

        output_state = { bytes: 0, truncated: false }
        output_mutex = Mutex.new
        stdout = stderr = status = nil
        timed_out = false

        Open3.popen3(*argv, pgroup: true) do |stdin_io, stdout_io, stderr_io, wait_thread|
          stdin_thread = write_process_input(stdin_io, stdin)
          stdout_thread = Thread.new do
            Thread.current.report_on_exception = false
            read_process_output(stdout_io, max_output_bytes, truncate_output, output_state, output_mutex, wait_thread.pid)
          end
          stderr_thread = Thread.new do
            Thread.current.report_on_exception = false
            read_process_output(stderr_io, max_output_bytes, truncate_output, output_state, output_mutex, wait_thread.pid)
          end

          status, timed_out = wait_for_process(wait_thread, timeout)
          stdin_thread&.value
          stdout = stdout_thread.value
          stderr = stderr_thread.value
        end

        [stdout, stderr, status, output_state[:truncated], timed_out]
      end

      def helper_argv(
        command,
        read:,
        write:,
        execute:,
        env:,
        inherit_env:,
        chdir:,
        connect_tcp:,
        bind_tcp:,
        rlimits:,
        seccomp_deny_network:,
        allow_all_known:
      )
        normalize_command(command)
        read_paths = validate_existing_paths(read, :read)
        write_paths = validate_existing_paths(write, :write)
        execute_paths = validate_existing_paths(execute, :execute)
        filesystem_policy_requested = read_paths.any? || write_paths.any? || execute_paths.any?

        argv = [helper_path]
        read_paths.each { |path| argv << "--read" << path }
        write_paths.each { |path| argv << "--write" << path }
        execute_paths.each { |path| argv << "--execute" << path }
        sandbox_connect_tcp_ports(connect_tcp).each { |port| argv << "--connect-tcp" << port.to_s }
        normalized_ports(bind_tcp, :bind_tcp).each { |port| argv << "--bind-tcp" << port.to_s }
        argv << "--chdir" << chdir if chdir
        Array(env).each { |key, value| argv << "--env" << "#{key}=#{value}" }
        argv << "--unsetenv-others" if !inherit_env
        normalized_rlimits(rlimits).each { |key, value| argv << "--rlimit" << "#{key}=#{value}" }
        argv << "--seccomp-deny-network" if seccomp_deny_network
        argv << "--allow-all-known" if allow_all_known && filesystem_policy_requested
        argv << "--"
        argv.concat(command.map(&:to_s))
        argv
      end

      def sandbox_connect_tcp_ports(connect_tcp)
        return normalized_ports(connect_tcp, :connect_tcp) if !connect_tcp.nil?
        return [] if !Landlock.supported? || Landlock.abi_version < 4

        [0]
      end

      def normalized_ports(ports, name)
        Array(ports).map do |port|
          integer = Integer(port)
          raise ArgumentError, "#{name} port must be between 0 and 65535" if integer.negative? || integer > 65_535

          integer
        end
      end

      def validate_existing_paths(paths, name)
        Array(paths).map do |path|
          string = path.to_s
          raise ArgumentError, "#{name} path must not be empty" if string.empty?
          raise ArgumentError, "#{name} path does not exist: #{string}" if !File.exist?(string)

          string
        end.uniq
      end

      def normalized_rlimits(rlimits)
        Array(rlimits).filter_map do |name, value|
          next if value.nil?

          key = name.to_sym
          if !%i[cpu_seconds memory_bytes file_size_bytes open_files processes].include?(key)
            raise ArgumentError, "Unknown rlimit: #{name}"
          end

          value = Integer(value)
          raise ArgumentError, "rlimit #{name} must be non-negative" if value.negative?

          [key, value]
        end
      end

      def wait_for_process(wait_thread, timeout)
        if timeout
          [Timeout.timeout(timeout) { wait_thread.value }, false]
        else
          [wait_thread.value, false]
        end
      rescue Timeout::Error
        terminate_process(wait_thread.pid)
        [wait_thread.value, true]
      end

      def write_process_input(io, input)
        return io.close if input.nil?

        Thread.new do
          Thread.current.report_on_exception = false
          begin
            if input.respond_to?(:read)
              while (chunk = input.read(READ_CHUNK_BYTES))
                io.write(chunk)
              end
            else
              io.write(input.to_s)
            end
          rescue Errno::EPIPE, IOError
          ensure
            io.close unless io.closed?
          end
        end
      end

      def read_process_output(io, max_output_bytes, truncate_output, output_state, output_mutex, pid)
        return io.read if max_output_bytes.nil?

        output = +""
        while (chunk = io.read(READ_CHUNK_BYTES))
          chunk_to_append = chunk
          over_limit = false

          output_mutex.synchronize do
            remaining_bytes = max_output_bytes - output_state[:bytes]
            if remaining_bytes <= 0
              chunk_to_append = ""
              over_limit = true
            elsif chunk.bytesize > remaining_bytes
              chunk_to_append = chunk.byteslice(0, remaining_bytes)
              over_limit = true
            end

            output_state[:bytes] += chunk.bytesize
            output_state[:truncated] = true if over_limit
          end

          output << chunk_to_append
          if over_limit
            terminate_process(pid)
            raise OutputTooLargeError, "Process output exceeded #{max_output_bytes} bytes" if !truncate_output

            break
          end
        end
        output
      end

      def terminate_process(pid)
        signal_process("TERM", pid)
        sleep 0.5
        signal_process("KILL", pid)
      end

      def signal_process(signal, pid)
        Process.kill(signal, -pid)
      rescue Errno::ESRCH, Errno::EPERM
        begin
          Process.kill(signal, pid)
        rescue Errno::ESRCH, Errno::EPERM
        end
      end
    end
  end
end
