# frozen_string_literal: true

module Landlock
  module ResultBehavior
    attr_reader :stdout, :stderr, :status

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

  class CaptureResult
    include ResultBehavior

    def initialize(stdout:, stderr:, status:, output_truncated: false, timed_out: false)
      @stdout = stdout
      @stderr = stderr
      @status = status
      @output_truncated = output_truncated
      @timed_out = timed_out
    end
  end
end
