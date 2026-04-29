# frozen_string_literal: true

require "rake/testtask"
require "rake/extensiontask"

Rake::ExtensionTask.new("landlock") do |ext|
  ext.lib_dir = "lib/landlock"
end

Rake::TestTask.new do |t|
  t.libs << "test"
  t.libs << "lib"
  t.pattern = "test/**/*_test.rb"
end

task default: [:compile, :test]
