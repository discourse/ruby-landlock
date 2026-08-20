# frozen_string_literal: true

module Landlock
  ResourceUsage =
    Data.define(:user_seconds, :system_seconds, :max_rss_bytes) do
      def cpu_seconds
        user_seconds + system_seconds
      end
    end

  module ResultBehavior
    attr_reader :stdout, :stderr, :status, :elapsed_seconds, :resource_usage

    def success?
      !timed_out? && !output_truncated? && status&.success?
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
      "#<#{self.class} status=#{status.inspect} timed_out=#{timed_out?} output_truncated=#{output_truncated?} elapsed_seconds=#{elapsed_seconds.inspect} resource_usage=#{resource_usage.inspect} stdout=#{stdout.inspect} stderr=#{stderr.inspect}>"
    end
  end

  class CaptureResult
    include ResultBehavior

    def initialize(
      stdout:,
      stderr:,
      status:,
      elapsed_seconds: nil,
      resource_usage: nil,
      output_truncated: false,
      timed_out: false
    )
      @stdout = stdout
      @stderr = stderr
      @status = status
      @elapsed_seconds = elapsed_seconds
      @resource_usage = resource_usage
      @output_truncated = output_truncated
      @timed_out = timed_out
    end
  end
end
