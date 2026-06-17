# frozen_string_literal: true

module Landlock
  module Env
    module_function

    def normalize(env)
      return nil if env.nil?

      raise ArgumentError, "env must be a Hash-compatible object" unless env.respond_to?(:each_pair)

      normalized = {}
      env.each_pair do |key, value|
        key = key.to_s
        raise ArgumentError, "env key must not be empty" if key.empty?
        raise ArgumentError, "env key must not contain '='" if key.include?("=")
        raise ArgumentError, "env key must not contain NUL" if key.include?("\0")

        if value.nil?
          normalized[key] = nil
        else
          value = value.to_s
          raise ArgumentError, "env value must not contain NUL" if value.include?("\0")

          normalized[key] = value
        end
      end
      normalized
    end
  end
end
