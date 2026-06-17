# frozen_string_literal: true

require_relative "errors"
require_relative "result"

module Landlock
  READ_CHUNK_BYTES = 16 * 1024
  PROCESS_POLL_SECONDS = 0.1
  STDIN_THREAD_JOIN_SECONDS = 0.1
  POST_TIMEOUT_DRAIN_SECONDS = 0.05

  module ProcessIO
    module_function

    def complete_pipe_capture(
      pid,
      stdout_reader,
      stderr_reader,
      stdin_writer,
      stdin,
      timeout,
      max_output_bytes,
      truncate_output
    )
      stdin_thread = write_input(stdin_writer, stdin)

      stdout = +"".b
      stderr = +"".b
      state = { bytes: 0, truncated: false }
      begin
        status, timed_out =
          read_and_wait(
            pid,
            { stdout_reader => stdout, stderr_reader => stderr },
            timeout,
            max_output_bytes,
            truncate_output,
            state
          )
      rescue OutputTooLargeError => error
        status ||= wait_for_pid(pid)
        error.result = capture_result(stdout, stderr, status, output_truncated: true, timed_out:)
        raise
      ensure
        finish_input_thread(stdin_thread, stdin_writer)
      end

      capture_result(stdout, stderr, status, output_truncated: state[:truncated], timed_out:)
    end

    def capture_result(stdout, stderr, status, output_truncated:, timed_out:)
      stdout.force_encoding(Encoding.default_external)
      stderr.force_encoding(Encoding.default_external)
      CaptureResult.new(stdout:, stderr:, status:, output_truncated:, timed_out:)
    end

    def write_input(io, input)
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

    def finish_input_thread(thread, io)
      close_stream(io)
      return unless thread

      if thread.join(STDIN_THREAD_JOIN_SECONDS)
        thread.value
      else
        thread.kill
        thread.join(STDIN_THREAD_JOIN_SECONDS)
      end
    end

    def read_and_wait(pid, streams, timeout, max_output_bytes, truncate_output, state)
      deadline = timeout ? ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + timeout : nil
      timed_out = false
      status = nil

      until streams.empty? && status
        if deadline
          remaining = deadline - ::Process.clock_gettime(::Process::CLOCK_MONOTONIC)
          if remaining <= 0
            timed_out = true
            terminate_process(pid)
            status = wait_for_pid(pid)
            drain_streams_until(
              streams,
              ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + POST_TIMEOUT_DRAIN_SECONDS,
              max_output_bytes,
              truncate_output,
              state,
              pid
            )
            close_streams(streams)
            break
          end
        end

        status ||= poll_pid(pid)

        break if streams.empty? && status

        wait =
          (
            if deadline
              [deadline - ::Process.clock_gettime(::Process::CLOCK_MONOTONIC), PROCESS_POLL_SECONDS].min
            else
              PROCESS_POLL_SECONDS
            end
          )
        wait = 0 if wait.negative?
        if streams.empty?
          sleep wait
          next
        end

        readable, = IO.select(streams.keys, nil, nil, wait)
        next unless readable

        readable.each do |io|
          begin
            chunk = io.read_nonblock(READ_CHUNK_BYTES)
            append_output_chunk(streams.fetch(io), chunk, state, max_output_bytes, truncate_output, pid)
          rescue IO::WaitReadable
            next
          rescue EOFError
            streams.delete(io)
            io.close
          end
        end
      end

      status ||= wait_for_pid(pid)
      [status, timed_out]
    end

    def poll_pid(pid)
      result = ::Process.wait2(pid, ::Process::WNOHANG)
      result&.last
    rescue Errno::ECHILD
      nil
    end

    def wait_for_pid(pid)
      ::Process.wait2(pid).last
    rescue Errno::ECHILD
      nil
    end

    def close_stream(io)
      io.close unless io.closed?
    rescue IOError
    end

    def read_available_streams(streams, max_output_bytes, truncate_output, state, pid)
      readable, = IO.select(streams.keys, nil, nil, 0)
      return false unless readable

      readable.each do |io|
        begin
          chunk = io.read_nonblock(READ_CHUNK_BYTES)
          append_output_chunk(streams.fetch(io), chunk, state, max_output_bytes, truncate_output, pid)
        rescue IO::WaitReadable
          next
        rescue EOFError
          streams.delete(io)
          io.close
        end
      end

      true
    end

    def drain_streams_until(streams, drain_deadline, max_output_bytes, truncate_output, state, pid)
      while streams.any? && ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) < drain_deadline
        break unless read_available_streams(streams, max_output_bytes, truncate_output, state, pid)
      end
    end

    def close_streams(streams)
      streams.keys.each do |io|
        streams.delete(io)
        io.close unless io.closed?
      rescue IOError
      end
    end

    def append_output_chunk(
      buffer,
      chunk,
      state,
      max_output_bytes,
      truncate_output,
      pid,
      output_too_large_error: Landlock::OutputTooLargeError
    )
      return buffer << chunk if max_output_bytes.nil?

      chunk_to_append = chunk
      over_limit = false
      remaining_bytes = max_output_bytes - state[:bytes]
      if remaining_bytes <= 0
        chunk_to_append = ""
        over_limit = true
      elsif chunk.bytesize > remaining_bytes
        chunk_to_append = chunk.byteslice(0, remaining_bytes)
        over_limit = true
      end

      state[:bytes] += chunk.bytesize
      state[:truncated] = true if over_limit
      buffer << chunk_to_append
      return unless over_limit

      terminate_process(pid)
      raise output_too_large_error, "Process output exceeded #{max_output_bytes} bytes" unless truncate_output
    end

    def terminate_process(pid)
      signal_process("TERM", pid)
      sleep 0.5
      signal_process("KILL", pid)
    end

    def signal_process(signal, pid)
      ::Process.kill(signal, -pid)
    rescue Errno::ESRCH, Errno::EPERM
      begin
        ::Process.kill(signal, pid)
      rescue Errno::ESRCH, Errno::EPERM
      end
    end
  end
end
