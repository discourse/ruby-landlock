# frozen_string_literal: true

require_relative "test_helper"

class LandlockRunnerNativeTest < LandlockTestCase
  def test_native_helper_reports_cli_parse_errors
    skip "native runner helper unavailable" unless File.executable?(Landlock::Runner::Native.helper_path)

    cases = [
      [%w[--bogus -- true], /unknown option/],
      [["--read"], /missing option argument/],
      [["--"], /missing command/],
      [%w[--bind-tcp 70000 -- true], /TCP port must be between 0 and 65535/],
      [%w[--rlimit nope -- true], /rlimit must be name=value/],
      [%w[--rlimit bogus=1 -- true], /unknown rlimit/],
      [%w[--rlimit open_files=12x -- true], /rlimit value/],
      [%w[--path /tmp], /missing option argument/],
      [%w[--path /tmp bogus -- true], /unknown filesystem right/],
      [%w[--scope bogus -- true], /unknown Landlock scope/],
      [%w[--env LANDLOCK_TEST=value -- true], /unknown option/],
      [%w[--unsetenv-others -- true], /unknown option/],
      [%w[--connect-tcp abc -- true], /TCP port must be an integer/],
      [%w[--connect-tcp +1 -- true], /TCP port must be an integer/],
      [%w[--connect-tcp -1 -- true], /TCP port must be an integer/]
    ]

    cases.each do |argv, error_pattern|
      _stdout, stderr, status = Open3.capture3(Landlock::Runner::Native.helper_path, *argv)

      assert_equal 126, status.exitstatus, argv.inspect
      assert_match error_pattern, stderr
    end
  end

  def test_spawn_backends_are_equivalent_for_basic_process
    skip "Landlock unsupported" unless Landlock.supported?
    skip "native runner helper unavailable" unless File.executable?(Landlock::Runner::Native.helper_path)

    options = {
      read: runtime_paths,
      write: nil,
      execute: runtime_paths,
      connect_tcp: nil,
      bind_tcp: nil,
      paths: [],
      scope: [],
      chdir: nil,
      env: {
        "PATH" => ENV.fetch("PATH", "")
      },
      unsetenv_others: true,
      close_others: true,
      allow_all_known: false
    }

    Dir.mktmpdir do |dir|
      [["native", Landlock::Runner::Native], ["fork", Landlock::Runner::Fork]].each do |name, runner|
        marker = File.join(dir, "#{name}.txt")
        pid =
          runner.spawn([RbConfig.ruby, "--disable=gems", "-e", "File.write(ARGV.fetch(0), 'ok')", marker], **options)
        _finished_pid, status = Process.wait2(pid)

        assert status.success?, name
        assert_equal "ok", File.read(marker), name
      end
    end
  end

  def test_native_helper_closes_inherited_file_descriptors
    skip "native runner helper unavailable" unless File.executable?(Landlock::Runner::Native.helper_path)

    reader, writer = non_stdio_pipe
    pid =
      Process.spawn(
        { "LANDLOCK_TEST_FD" => writer.fileno.to_s },
        Landlock::Runner::Native.helper_path,
        "--",
        RbConfig.ruby,
        "--disable=gems",
        "-e",
        "begin; IO.for_fd(ENV.fetch('LANDLOCK_TEST_FD').to_i).write('leaked'); rescue Exception; end",
        close_others: false,
        out: File::NULL,
        err: File::NULL
      )
    writer.close
    _finished_pid, status = Process.wait2(pid)

    assert status.success?
    assert IO.select([reader], nil, nil, 1), "expected pipe EOF after helper closed inherited fd"
    assert_equal "", reader.read
  ensure
    reader&.close unless reader&.closed?
    writer&.close unless writer&.closed?
  end

  def test_native_helper_keep_fds_preserves_inherited_file_descriptors
    skip "native runner helper unavailable" unless File.executable?(Landlock::Runner::Native.helper_path)

    reader, writer = non_stdio_pipe
    pid =
      Process.spawn(
        { "LANDLOCK_TEST_FD" => writer.fileno.to_s },
        Landlock::Runner::Native.helper_path,
        "--keep-fds",
        "--",
        RbConfig.ruby,
        "--disable=gems",
        "-e",
        "IO.for_fd(ENV.fetch('LANDLOCK_TEST_FD').to_i).write('kept')",
        close_others: false,
        out: File::NULL,
        err: File::NULL
      )
    writer.close
    _finished_pid, status = Process.wait2(pid)

    assert status.success?
    assert_equal "kept", reader.read
  ensure
    reader&.close unless reader&.closed?
    writer&.close unless writer&.closed?
  end

  def test_native_helper_chdir_changes_target_working_directory
    skip "native runner helper unavailable" unless File.executable?(Landlock::Runner::Native.helper_path)

    Dir.mktmpdir do |dir|
      stdout, stderr, status =
        Open3.capture3(
          Landlock::Runner::Native.helper_path,
          "--chdir",
          dir,
          "--",
          RbConfig.ruby,
          "--disable=gems",
          "-e",
          "print Dir.pwd"
        )

      assert status.success?, stderr
      assert_equal dir, stdout
    end
  end

  def test_internal_files_can_be_required_directly
    stdout, stderr, status =
      Open3.capture3(
        RbConfig.ruby,
        "--disable=gems",
        "-I#{File.join(root, "lib")}",
        "-e",
        "require 'landlock/process_io'; require 'landlock/runner/native'; require 'landlock/runner/fork'; print 'ok'"
      )

    assert status.success?, stderr
    assert_equal "ok", stdout
  end
end
