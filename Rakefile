# frozen_string_literal: true

require "bundler"
require "rake/testtask"
require "rake/extensiontask"
require "shellwords"

begin
  Bundler.setup :default, :development
  Bundler::GemHelper.install_tasks
rescue Bundler::BundlerError => error
  warn error.message
  warn "Run `bundle install` to install missing gems"
  exit error.status_code
end

Rake::ExtensionTask.new("landlock") { |ext| ext.lib_dir = "lib/landlock" }

Rake::TestTask.new do |t|
  t.libs << "test"
  t.libs << "lib"
  t.pattern = "test/**/*_test.rb"
end

formattable_ruby_files = FileList["Gemfile", "Rakefile", "*.gemspec", "{lib,test,benchmark}/**/*.rb"].to_a.freeze
formattable_c_files = FileList["ext/**/*.{c,h}"].to_a.freeze
stree_print_width = 120
clang_format = ENV.fetch("CLANG_FORMAT", "clang-format")

namespace :format do
  desc "Check Ruby/C formatting"
  task :check do
    sh "bundle exec stree check --print-width=#{stree_print_width} #{formattable_ruby_files.map(&:shellescape).join(" ")}"
    sh "#{clang_format.shellescape} --dry-run --Werror #{formattable_c_files.map(&:shellescape).join(" ")}"
  end
end

desc "Format Ruby/C files"
task :format do
  sh "bundle exec stree write --print-width=#{stree_print_width} #{formattable_ruby_files.map(&:shellescape).join(" ")}"
  sh "#{clang_format.shellescape} -i #{formattable_c_files.map(&:shellescape).join(" ")}"
end

task test: :compile

namespace :bench do
  desc "Run the Landlock overhead benchmark suite"
  task overhead: :compile do
    ruby "benchmark/landlock_overhead.rb"
  end
end

desc "Run the Landlock overhead benchmark suite"
task bench: "bench:overhead"

task default: %i[compile test]
