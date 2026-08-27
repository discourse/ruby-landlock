# frozen_string_literal: true

require_relative "test_helper"

class LandlockCaptureForkTest < LandlockTestCase
  def test_capture_fork_captures_an_inherited_ruby_block
    skip "Landlock unsupported" unless Landlock.supported?

    inherited = "ready"
    result =
      Landlock.capture_fork(rlimits: { open_files: 64 }) do
        print inherited
        warn "warning"
      end

    assert_equal "ready", result.stdout
    assert_equal "warning\n", result.stderr
    assert_predicate result, :success?
  end

  def test_capture_fork_returns_block_errors
    skip "Landlock unsupported" unless Landlock.supported?

    result = Landlock.capture_fork(rlimits: { open_files: 64 }) { raise "failed" }

    assert_equal 1, result.status.exitstatus
    assert_match(/RuntimeError: failed/, result.stderr)
    refute_predicate result, :success?
  end

  def test_capture_fork_enforces_timeout
    skip "Landlock unsupported" unless Landlock.supported?

    result = Landlock.capture_fork(timeout: 0.01, rlimits: { open_files: 64 }) { sleep 30 }

    assert_predicate result, :timed_out?
    refute_predicate result, :success?
  end

  def test_capture_fork_applies_the_filesystem_policy
    skip "Landlock unsupported" unless Landlock.supported?

    Dir.mktmpdir do |directory|
      path = File.join(directory, "secret")
      File.write(path, "secret")

      result = Landlock.capture_fork(read: [], write: []) { File.read(path) }

      assert_equal 1, result.status.exitstatus
      assert_match(/Errno::EACCES/, result.stderr)
    end
  end

  def test_capture_fork_applies_process_options
    skip "Landlock unsupported" unless Landlock.supported?

    Dir.mktmpdir do |directory|
      result =
        Landlock.capture_fork(
          chdir: directory,
          env: {
            LANDLOCK_CAPTURE_FORK: "child"
          },
          unsetenv_others: true,
          stdin: "input",
          rlimits: {
            open_files: 32
          }
        ) do
          print [Dir.pwd, ENV.fetch("LANDLOCK_CAPTURE_FORK"), STDIN.read, Process.getrlimit(:NOFILE).first].join(":")
        end

      assert_equal "#{directory}:child:input:32", result.stdout
      assert_predicate result, :success?
    end
  end

  def test_capture_fork_closes_inherited_io
    skip "Landlock unsupported" unless Landlock.supported?

    reader, writer = IO.pipe
    result = Landlock.capture_fork(rlimits: { open_files: 64 }) { print writer.closed? }

    assert_equal "true", result.stdout
  ensure
    reader&.close
    writer&.close
  end

  def test_capture_fork_enforces_output_limit
    skip "Landlock unsupported" unless Landlock.supported?

    error =
      assert_raises(Landlock::CommandError) do
        Landlock.capture_fork(rlimits: { open_files: 64 }, max_output_bytes: 4) { print "output" }
      end

    assert_equal "outp", error.stdout
    assert_predicate error.result, :output_truncated?
  end

  def test_capture_fork_requires_a_block
    error = assert_raises(ArgumentError) { Landlock.capture_fork(rlimits: { open_files: 64 }) }

    assert_equal "capture_fork requires a block", error.message
  end
end
