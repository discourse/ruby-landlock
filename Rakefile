# frozen_string_literal: true

require "bundler"
require "rake/testtask"
require "rake/extensiontask"

begin
  Bundler.setup :default, :development
  Bundler::GemHelper.install_tasks
rescue Bundler::BundlerError => error
  warn error.message
  warn "Run `bundle install` to install missing gems"
  exit error.status_code
end

Rake::ExtensionTask.new("landlock") do |ext|
  ext.lib_dir = "lib/landlock"
end

Rake::TestTask.new do |t|
  t.libs << "test"
  t.libs << "lib"
  t.pattern = "test/**/*_test.rb"
end

task test: :compile

task default: [:compile, :test]
