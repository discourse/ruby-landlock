# frozen_string_literal: true

require_relative "test_helper"

# nil means "do not police this class"; [] means "police it, allow nothing".
class HandledClassesTest < LandlockTestCase
  def setup
    skip "Landlock unsupported" unless Landlock.supported?
  end

  private

  # Bundler in the inherited env would try to read paths outside the policy, so
  # the child runs with a bare environment.
  def child_env
    { "PATH" => ENV.fetch("PATH", "") }
  end

  def probe(script, **options)
    Landlock.capture(
      [RbConfig.ruby, "--disable=gems", "-e", script],
      read: runtime_paths,
      execute: runtime_paths,
      env: child_env,
      unsetenv_others: true,
      timeout: 20,
      **options,
    )
  end

  def write_probe(target)
    "begin; File.write(#{target.dump}, 'x'); print 'ALLOWED'; rescue => e; print e.class; end"
  end

  public

  def test_empty_write_array_denies_writes_everywhere
    Dir.mktmpdir do |dir|
      result = probe(write_probe(File.join(dir, "f.txt")), write: [])

      assert_equal "Errno::EACCES", result.stdout
    end
  end

  def test_nil_write_leaves_writes_unpoliced
    Dir.mktmpdir do |dir|
      result = probe(write_probe(File.join(dir, "f.txt")), write: nil)

      assert_equal "ALLOWED", result.stdout
    end
  end

  def test_write_array_still_grants_listed_paths
    Dir.mktmpdir do |dir|
      result = probe(write_probe(File.join(dir, "f.txt")), write: [dir])

      assert_equal "ALLOWED", result.stdout
    end
  end

  # The target sits outside runtime_paths, since an execute grant also carries
  # read_file/read_dir for the paths it lists.
  def test_empty_read_array_denies_reads
    Dir.mktmpdir do |dir|
      target = File.join(dir, "secret.txt")
      File.write(target, "x")
      script = "begin; File.read(#{target.dump}); print 'ALLOWED'; rescue => e; print e.class; end"

      assert_equal "Errno::EACCES", probe(script, read: []).stdout
      assert_equal "ALLOWED", probe(script, read: [dir]).stdout
    end
  end

  def test_empty_execute_array_denies_exec
    result =
      Landlock.capture(
        [RbConfig.ruby, "--disable=gems", "-e", "print 'ran'"],
        read: runtime_paths,
        execute: [],
        env: child_env,
        unsetenv_others: true,
        timeout: 20,
      )

    refute_equal 0, result.status.exitstatus
    refute_equal "ran", result.stdout
  end

  def test_empty_array_alone_is_a_real_policy
    result =
      Landlock.capture(
        [RbConfig.ruby, "--disable=gems", "-e", "print 'ran'"],
        read: runtime_paths,
        execute: runtime_paths,
        write: [],
        env: child_env,
        unsetenv_others: true,
        timeout: 20,
      )

    assert_equal "ran", result.stdout
  end

  def test_all_classes_nil_still_raises
    assert_raises(ArgumentError) { Landlock.capture([RbConfig.ruby, "-e", "1"], timeout: 5) }
  end

  # Only one of the two runners goes through the C helper, so they must agree.
  def test_runners_agree_on_empty_versus_nil_write
    Dir.mktmpdir do |dir|
      { "empty" => [], "nil" => nil }.each do |label, value|
        assert_capture_backends_equivalent(
          "write #{label}",
          argv: [RbConfig.ruby, "--disable=gems", "-e", write_probe(File.join(dir, "#{label}.txt"))],
          read: runtime_paths,
          execute: runtime_paths,
          write: value,
          env: child_env,
          unsetenv_others: true,
        )
      end
    end
  end

  # Agreement alone would be satisfied by both runners being wrong, so pin the
  # absolute behaviour of each.
  def test_each_runner_enforces_empty_and_ignores_nil
    [Landlock::Runner::Native, Landlock::Runner::Fork].each do |runner|
      Dir.mktmpdir do |dir|
        { "empty" => ["Errno::EACCES", []], "nil" => ["ALLOWED", nil] }.each do |label, (expected, value)|
          result =
            capture_backend_result(
              runner,
              [RbConfig.ruby, "--disable=gems", "-e", write_probe(File.join(dir, "#{label}.txt"))],
              read: runtime_paths,
              execute: runtime_paths,
              write: value,
              env: child_env,
              unsetenv_others: true,
              timeout: 20,
            )

          assert_equal expected, result.stdout, "#{runner}: write #{label}"
        end
      end
    end
  end
end
