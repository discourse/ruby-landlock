# frozen_string_literal: true

module Landlock
  Error = Class.new(StandardError)
  UnsupportedError = Class.new(Error)

  class SyscallError < Error
    attr_reader :errno, :syscall

    def initialize(syscall, errno, message = nil)
      @syscall = syscall
      @errno = errno
      super(message || "#{syscall} failed: #{errno}")
    end
  end

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

  class OutputTooLargeError < Error
    attr_accessor :result
  end
end
