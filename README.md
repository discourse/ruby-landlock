# landlock

Ruby bindings for Linux [Landlock](https://docs.kernel.org/userspace-api/landlock.html): unprivileged, kernel-enforced sandboxing for the calling thread and its future descendants.

This gem includes a small native extension around the three Landlock syscalls and a Ruby API for safe subprocess execution.

## Status

Experimental. Filesystem support requires Landlock ABI v1+. TCP network rules require ABI v4+. Signal and abstract Unix-domain socket scopes require ABI v6+.

```ruby
require "landlock"

puts Landlock.abi_version
puts Landlock.supported?
```

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## Safe subprocess execution

Pass commands as an argument array. `Landlock.exec` and `Landlock.spawn` do not invoke a shell implicitly; use an explicit shell in the array if that is really required. Both helpers accept `env:` and `unsetenv_others:` and pass them through to `Kernel.exec` so subprocesses can run with a controlled environment.

Allow Ruby to execute and read its runtime, but only allow outbound TCP connections to port 443:

```ruby
status = Landlock.exec(
  [RbConfig.ruby, "script.rb"],
  read: ["/usr", "/lib", "/lib64", "/etc/ssl"],
  execute: ["/usr", "/lib", "/lib64"],
  connect_tcp: [443],
  allow_all_known: true
)

abort "failed" unless status.success?
```

Deny all outbound TCP except the listed ports:

```ruby
Landlock.exec(
  ["curl", "https://example.com"],
  read: [
    "/usr", "/lib", "/lib64",
    "/etc/ssl", "/etc/resolv.conf", "/etc/hosts",
    "/etc/nsswitch.conf", "/etc/gai.conf", "/etc/host.conf",
    "/run/systemd/resolve", "/var/lib/sss"
  ].select { |path| File.exist?(path) },
  execute: ["/usr", "/lib", "/lib64"],
  connect_tcp: [443],
  allow_all_known: true
)
```

TLS and name-resolution dependencies vary by distribution and NSS configuration; add any local CA, DNS, NSS, or resolver paths your system needs.

Allow binding a local TCP port:

```ruby
Landlock.exec(
  [RbConfig.ruby, "server.rb"],
  read: ["/usr", "/lib", "/lib64", Dir.pwd],
  execute: ["/usr", "/lib", "/lib64"],
  bind_tcp: [9292],
  allow_all_known: true
)
```

## SafeExec helper

`Landlock::SafeExec.capture` runs a command through the compiled `landlock-safe-exec` helper. The helper applies Landlock rules, resource limits, and an optional seccomp network-deny filter in the execing process before replacing itself with the target command. This keeps the privileged setup out of Ruby/FFI and avoids running Ruby code in a post-fork child. Use `capture!` when unsuccessful exit statuses should raise.

For example, inspect an uploaded video with `ffprobe` while only allowing reads from the upload and system runtime paths, denying network access, and bounding CPU/output:

```ruby
result = Landlock::SafeExec.capture(
  "ffprobe",
  "-v", "error",
  "-show_format",
  "-show_streams",
  "-of", "json",
  upload_path,
  read: [upload_path, *Landlock::SafeExec.default_read_paths],
  execute: Landlock::SafeExec.default_execute_paths,
  env: { "PATH" => ENV.fetch("PATH", "") },
  rlimits: {
    cpu_seconds: 5,
    memory_bytes: 512 * 1024 * 1024,
    file_size_bytes: 0,
    open_files: 64,
    processes: 0
  },
  seccomp_deny_network: true,
  max_output_bytes: 256 * 1024,
  truncate_output: false
)

metadata = JSON.parse(result.stdout) if result.success?
```

Pass `stdin:` when a tool should read from standard input instead of a file:

```ruby
stdout, stderr, status = Landlock::SafeExec.capture(
  "tr", "a-z", "A-Z",
  stdin: "hello",
  env: { "PATH" => ENV.fetch("PATH", "") }
)
```

`capture` returns a `Landlock::SafeExec::Result` with `stdout`, `stderr`, `status`, `success?`, `timed_out?`, and `output_truncated?`, including for unsuccessful exit statuses. It also supports array destructuring:

```ruby
stdout, stderr, status = Landlock::SafeExec.capture("tool", "arg")
```

`capture!` has the same return shape for successful commands, but raises `Landlock::SafeExec::CommandError` for unsuccessful statuses. The error also exposes `stdout`, `stderr`, `status`, and `result`.

SafeExec options:

- `read:`, `write:`, `execute:` — filesystem allowlists. Explicit paths must exist; missing paths raise `ArgumentError` instead of being silently ignored.
- `connect_tcp:` — allowed outbound TCP ports. If omitted on Landlock ABI v4+, SafeExec denies outbound TCP by installing a dummy allow rule for port `0`. Pass `connect_tcp: []` to leave outbound TCP unrestricted.
- `bind_tcp:` — allowed TCP bind ports. Binding is unrestricted unless this is provided.
- `seccomp_deny_network:` — additionally deny common Linux network syscalls with seccomp. This is Linux-specific and intended as defense in depth.
- `rlimits:` — resource limits. Supported keys are `:cpu_seconds`, `:memory_bytes`, `:file_size_bytes`, `:open_files`, and `:processes`. Values must be non-negative integers.
- `timeout:` — wall-clock timeout in seconds. On timeout SafeExec terminates the process group and returns/raises with `result.timed_out?` true.
- `max_output_bytes:` — combined stdout+stderr byte limit. With `truncate_output: false`, exceeding the limit raises. With `truncate_output: true`, output is truncated and `result.output_truncated?` is true.
- `stdin:` — string or IO-like object to write to the child process stdin.
- `chdir:` — working directory for the child.
- `env:` — exact child environment by default.
- `inherit_env:` — when true, inherit the parent environment and apply `env:` as overrides.
- `success_status_codes:` — status codes considered successful by `capture!`; defaults to `[0]`.
- `allow_all_known:` — when filesystem rules are present, handle all Landlock filesystem rights known to the running ABI so unlisted filesystem access is denied. Defaults to `true`.

SafeExec uses an exact environment by default: `env:` is the full environment passed to the child, not additions to the parent environment. Use `inherit_env: true` when a command really needs the parent environment plus the supplied `env:` overrides.

Use `Landlock::SafeExec.supported?` (or `sandboxing?`) to check whether the Linux helper and Landlock are available. When this is false, SafeExec still runs commands in pass-through mode but does not enforce Landlock/seccomp sandbox options.

On non-Linux platforms, or when the compiled helper is unavailable, SafeExec runs as a pass-through compatibility wrapper. Process-management features such as capture, timeout, environment handling, `chdir:`, output limits, `stdin:`, and supported `rlimits:` still apply, but Landlock and seccomp options (`read:`, `write:`, `execute:`, `connect_tcp:`, `bind_tcp:`, `seccomp_deny_network:`) are ignored and a warning is emitted. This makes cross-platform integration easier while keeping the security guarantees explicit: sandboxing is Linux-only.

## Restrict current process

This is irreversible for the current thread and its future children. Use `Landlock.exec` or `Landlock.spawn` unless you really mean it.

```ruby
Landlock.restrict!(
  read: ["/usr", "/app"],
  write: ["/tmp/my-output"],
  connect_tcp: [443],
  scope: [:signal, :abstract_unix_socket],
  allow_all_known: true
)
```

`write:` grants the filesystem rights needed for practical writes under the listed paths, including directory traversal and reads (`read_file`/`read_dir`). If you need exact rights, use `paths:` with an explicit `rights:` list.

## Lower-level path rules

```ruby
Landlock.restrict!(
  paths: [
    { path: "/usr", rights: %i[read_file read_dir execute] },
    { path: "/tmp/out", rights: %i[read_file read_dir write_file truncate make_reg remove_file] }
  ],
  connect_tcp: [443]
)
```

## Performance

Landlock enforcement is done by the kernel after a ruleset is installed. In normal use the practical cost should be dominated by the one-time sandbox setup and by the work your process already performs, not by Ruby-side wrappers.

This repository includes a small benchmark suite that compares common workloads before and after applying a read-only Landlock policy:

```sh
bundle exec rake bench
# or
bundle exec ruby benchmark/landlock_overhead.rb
```

The suite reports median timings for CPU-only work, file metadata reads, small file reads, directory scans, and the one-time ruleset setup cost. You can tune the run length with environment variables:

```sh
SAMPLES=15 ITERATIONS=100000 DIR_ITERATIONS=5000 bundle exec rake bench
```

Sample output looks like:

```text
workload           baseline     landlocked        delta    delta %
--------------------------------------------------------------------
cpu_loop           0.650 ms       0.648 ms    -0.002 ms     -0.31%
file_stat         42.100 ms      42.300 ms     0.200 ms      0.48%
file_read        120.500 ms     120.900 ms     0.400 ms      0.33%
dir_scan          88.000 ms      88.200 ms     0.200 ms      0.23%

Setup cost (create ruleset, add read rules, restrict current process):
  median 0.080 ms (25 samples)
```

Treat small positive or negative deltas as noise and benchmark on the kernel, filesystem, and hardware you deploy on. The expected result is no practical steady-state overhead for typical application work, with a small one-time cost when installing the sandbox.

## Caveats

Landlock is not a complete container. It restricts selected kernel-mediated actions for the current thread and its future descendants, but it does not create namespaces, hide process IDs, virtualize the filesystem, or isolate the process from every kernel interface. For serious untrusted execution, combine Landlock with a controlled environment, resource limits, seccomp, and process isolation appropriate to your threat model.

`Landlock.restrict!` only installs a Landlock ruleset. It does not close already-open file descriptors, impose resource limits, clean the environment, or kill subprocess trees. `Landlock::SafeExec` adds practical subprocess hardening around this — exact environment by default, `close_others`, optional `rlimits:`, optional `seccomp_deny_network:`, output limits, timeout handling, and process-group termination — but it is still not a VM/container boundary.

If `Landlock.exec` or `Landlock.spawn` child setup fails before `exec`, the child prints a diagnostic and exits 127. `landlock-safe-exec` setup/argument failures exit 126. These codes can collide with commands that legitimately exit with the same status, so inspect stderr when debugging failures.

Path rules follow the kernel's normal path resolution when the rule is installed. Because paths are opened without `O_NOFOLLOW`, a symlink rule applies to the symlink target's inode, not to the symlink path itself. SafeExec validates explicit `read:`, `write:`, and `execute:` paths before launching so typos fail closed instead of silently weakening a policy.

Landlock only restricts access rights included in a ruleset's handled set: omitted categories remain allowed. Use `allow_all_known: true` when you want unlisted filesystem actions denied. SafeExec defaults `allow_all_known:` to true when filesystem rules are provided. Landlock TCP rules do not cover UDP or pathname Unix-domain sockets; ABI v6+ scopes can restrict signals and abstract Unix-domain sockets. SafeExec's `seccomp_deny_network:` is Linux-specific defense in depth for common network syscalls, not a general-purpose seccomp policy language.

`Landlock.restrict!` applies to the calling thread and its future children; already-running sibling threads are not retroactively sandboxed. Prefer `Landlock::SafeExec`, `Landlock.exec`, or `Landlock.spawn` for subprocess sandboxing from a larger Ruby application.
