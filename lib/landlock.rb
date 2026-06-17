# frozen_string_literal: true

require_relative "landlock/version"
require_relative "landlock/errors"
require_relative "landlock/native"
require_relative "landlock/result"
require_relative "landlock/rights"
require_relative "landlock/validation"
require_relative "landlock/env"
require_relative "landlock/rlimits"
require_relative "landlock/process_io"
require_relative "landlock/policy"
require_relative "landlock/execution"

module Landlock
  class << self
    def supported?
      abi_version.positive?
    rescue Error
      false
    end

    def restrict!(...)
      Policy.restrict!(...)
    end

    def exec(...)
      Execution.exec(...)
    end

    def spawn(...)
      Execution.spawn(...)
    end

    def capture(...)
      Execution.capture(...)
    end

    def capture!(...)
      Execution.capture!(...)
    end
  end
end
