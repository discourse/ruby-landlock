# frozen_string_literal: true

require_relative "lib/landlock/version"

Gem::Specification.new do |spec|
  spec.name = "landlock"
  spec.version = Landlock::VERSION
  spec.authors = ["Sam Saffron"]
  spec.email = ["sam@samsaffron.com"]

  spec.summary = "Ruby bindings for Linux Landlock sandboxing"
  spec.description = "Native Ruby wrappers for Linux Landlock with filesystem and TCP port restrictions for safe subprocess execution."
  spec.homepage = "https://github.com/sam-saffron-jarvis/landlock"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir.chdir(__dir__) do
    Dir["lib/**/*.rb", "ext/**/*.{c,h,rb}", "README.md", "LICENSE.txt"]
  end
  spec.require_paths = ["lib"]
  spec.extensions = ["ext/landlock/extconf.rb"]

  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rake-compiler", "~> 1.2"
  spec.add_development_dependency "minitest", "~> 5.0"
end
