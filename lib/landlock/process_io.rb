# frozen_string_literal: true

require_relative "errors"
require_relative "native"
require_relative "result"

module Landlock
  READ_CHUNK_BYTES = 16 * 1024
  PROCESS_POLL_SECONDS = 0.1
  TERMINATION_POLL_SECONDS = 0.01
  TERMINATION_GRACE_SECONDS = 0.5
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
      started_at = monotonic_time
      stdin_thread = write_input(stdin_writer, stdin)

      stdout = +"".b
      stderr = +"".b
      state = { bytes: 0, truncated: false, wait_result: nil, timed_out: false, elapsed_seconds: nil, started_at: }
      begin
        read_and_wait(
          pid,
          { stdout_reader => stdout, stderr_reader => stderr },
          timeout,
          max_output_bytes,
          truncate_output,
          state
        )
      rescue OutputTooLargeError => error
        record_wait_result(state, wait_for_pid(pid)) unless state[:wait_result]
        state[:elapsed_seconds] ||= monotonic_time - started_at
        error.result = capture_result(stdout:, stderr:, state:, output_truncated: true)
        raise
      ensure
        finish_input_thread(stdin_thread, stdin_writer)
      end

      capture_result(stdout:, stderr:, state:, output_truncated: state[:truncated])
    end

    def capture_result(stdout:, stderr:, state:, output_truncated:)
      stdout.force_encoding(Encoding.default_external)
      stderr.force_encoding(Encoding.default_external)
      status, resource_usage = state[:wait_result]
      CaptureResult.new(
        stdout:,
        stderr:,
        status:,
        elapsed_seconds: state[:elapsed_seconds],
        resource_usage:,
        output_truncated:,
        timed_out: state[:timed_out]
      )
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
      deadline = timeout ? state[:started_at] + timeout : nil

      until streams.empty? && state[:wait_result]
        if deadline
          remaining = deadline - monotonic_time
          if remaining <= 0
            state[:timed_out] = true
            wait_result, reaped_at = terminate_and_wait(pid)
            record_wait_result(state, wait_result, reaped_at:)
            drain_streams_until(
              streams,
              monotonic_time + POST_TIMEOUT_DRAIN_SECONDS,
              max_output_bytes,
              truncate_output,
              state,
              pid
            )
            close_streams(streams)
            break
          end
        end

        record_wait_result(state, poll_pid(pid)) unless state[:wait_result]

        break if streams.empty? && state[:wait_result]

        if streams.empty? && deadline
          sleep [deadline - monotonic_time, TERMINATION_POLL_SECONDS].min.clamp(0, TERMINATION_POLL_SECONDS)
          next
        end

        if streams.empty?
          record_wait_result(state, wait_for_pid(pid))
          break
        end

        wait =
          (
            if deadline
              [deadline - monotonic_time, PROCESS_POLL_SECONDS].min
            else
              PROCESS_POLL_SECONDS
            end
          )
        wait = 0 if wait.negative?
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

      record_wait_result(state, wait_for_pid(pid)) unless state[:wait_result]
    end

    def poll_pid(pid)
      Native.wait4(pid, ::Process::WNOHANG)
    rescue Errno::ECHILD
      nil
    end

    def wait_for_pid(pid)
      Native.wait4(pid, 0)
    rescue Errno::ECHILD
      nil
    end

    def record_wait_result(state, wait_result, reaped_at: monotonic_time)
      return unless wait_result
      return if state[:wait_result]

      state[:wait_result] = wait_result
      state[:elapsed_seconds] = reaped_at - state[:started_at]
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
      while streams.any? && monotonic_time < drain_deadline
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

      wait_result, reaped_at = terminate_and_wait(pid)
      record_wait_result(state, wait_result, reaped_at:)
      raise output_too_large_error, "Process output exceeded #{max_output_bytes} bytes" unless truncate_output
    end

    def terminate_and_wait(pid)
      signal_process("TERM", pid)
      deadline = monotonic_time + TERMINATION_GRACE_SECONDS
      wait_result = nil
      reaped_at = nil

      loop do
        unless wait_result
          wait_result = poll_pid(pid)
          reaped_at = monotonic_time if wait_result
        end
        break unless process_group_alive?(pid)

        remaining_seconds = deadline - monotonic_time
        break if remaining_seconds <= 0

        sleep [remaining_seconds, TERMINATION_POLL_SECONDS].min
      end

      signal_process("KILL", pid) if process_group_alive?(pid)
      unless wait_result
        wait_result = wait_for_pid(pid)
        reaped_at = monotonic_time if wait_result
      end

      [wait_result, reaped_at]
    end

    def signal_process(signal, pid)
      ::Process.kill(signal, -pid)
    rescue Errno::ESRCH, Errno::EPERM
      begin
        ::Process.kill(signal, pid)
      rescue Errno::ESRCH, Errno::EPERM
      end
    end

    def process_group_alive?(pid)
      ::Process.kill(0, -pid)
      true
    rescue Errno::ESRCH
      false
    rescue Errno::EPERM
      true
    end

    def monotonic_time
      ::Process.clock_gettime(::Process::CLOCK_MONOTONIC)
    end
  end
end
