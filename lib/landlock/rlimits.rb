# frozen_string_literal: true

module Landlock
  module Rlimits
    VALID_NAMES = %i[cpu_seconds memory_bytes file_size_bytes open_files processes].freeze

    module_function

    def normalize(rlimits)
      Array(rlimits).filter_map do |name, value|
        next if value.nil?

        key = name.to_sym
        raise ArgumentError, "Unknown rlimit: #{name}" if !VALID_NAMES.include?(key)

        value = Integer(value)
        raise ArgumentError, "rlimit #{name} must be non-negative" if value.negative?

        [key, value]
      end
    end

    def apply!(rlimits)
      rlimits.each do |key, value|
        case key
        when :cpu_seconds
          ::Process.setrlimit(:CPU, value, value)
        when :memory_bytes
          ::Process.setrlimit(:AS, value, value)
        when :file_size_bytes
          ::Process.setrlimit(:FSIZE, value, value)
        when :open_files
          ::Process.setrlimit(:NOFILE, value, value)
        when :processes
          ::Process.setrlimit(:NPROC, value, value)
        end
      end
    end
  end
end
