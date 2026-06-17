# frozen_string_literal: true

module Landlock
  module Validation
    module_function

    def normalize_argv(argv)
      raise ArgumentError, "argv must be an Array of command arguments" unless argv.is_a?(Array)
      raise ArgumentError, "argv must not be empty" if argv.empty?

      argv
    end

    def normalize_ports(ports, name)
      Array(ports).map do |port|
        integer = Integer(port)
        raise ArgumentError, "#{name} port must be between 0 and 65535" if integer.negative? || integer > 65_535

        integer
      end
    end

    def validate_existing_paths(paths, name, chdir: nil)
      base = chdir ? File.expand_path(chdir) : Dir.pwd
      Array(paths)
        .map do |path|
          validate_existing_path!(path, name, base)
          path.to_s
        end
        .uniq
    end

    def validate_existing_path!(path, name, base)
      string = path.to_s
      raise ArgumentError, "#{name} path must not be empty" if string.empty?

      expanded = File.expand_path(string, base)
      raise ArgumentError, "#{name} path does not exist: #{string}" if !File.exist?(expanded)
    end

    def validate_output_limit!(max_output_bytes)
      return if max_output_bytes.nil?

      Integer(max_output_bytes).tap do |value|
        raise ArgumentError, "max_output_bytes must be non-negative" if value.negative?
      end
    end

    def validate_timeout!(timeout)
      return if timeout.nil?
      raise ArgumentError, "timeout must be numeric" unless timeout.is_a?(Numeric)

      Float(timeout).tap do |value|
        raise ArgumentError, "timeout must be finite" unless value.finite?
        raise ArgumentError, "timeout must be non-negative" if value.negative?
      end
    end
  end
end
