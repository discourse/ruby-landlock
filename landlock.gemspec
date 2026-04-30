# frozen_string_literal: true

require_relative "lib/landlock/version"

Gem::Specification.new do |spec|
  spec.name = "landlock"
  spec.version = Landlock::VERSION
  spec.authors = ["Sam Saffron"]
  spec.email = ["sam.saffron@gmail.com"]

  spec.summary = "Ruby bindings for Linux Landlock sandboxing"
  spec.description =
    "Native Ruby wrappers for Linux Landlock with filesystem and TCP port restrictions for safe subprocess execution."
  spec.homepage = "https://github.com/discourse/ruby-landlock"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.3"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files =
    Dir[
      "lib/**/*.rb",
      "ext/**/*.{c,h,rb}",
      "benchmark/**/*.rb",
      "README.md",
      "CHANGELOG.md",
      "LICENSE.txt"
    ]
  spec.require_paths = ["lib"]
  spec.extensions = ["ext/landlock/extconf.rb"]

  spec.add_development_dependency "minitest", "~> 5.0"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rake-compiler", "~> 1.2"
  spec.add_development_dependency "rubocop-discourse", "~> 3.9"
end
