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

Pass commands as an argument array. `Landlock.exec` and `Landlock.spawn` do not invoke a shell implicitly; use an explicit shell in the array if that is really required. Both helpers require a non-empty Landlock policy, accept `env:`/`unsetenv_others:` for controlled environments, and use the packaged native helper when available so the long-lived child is not a forked Ruby process.

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

## Capturing subprocess output

`Landlock.capture` is the stdout/stderr-capturing sibling of `Landlock.exec`: it launches a child process, applies Landlock rules, resource limits, and the optional seccomp network-deny filter before the target command starts, then execs that command directly. When the packaged `landlock-safe-exec` helper is available, `exec`, `spawn`, and `capture` all spawn that small native helper with policy arguments so the parent does not need to fork a bloated Ruby process; they fall back to the Ruby fork path when the helper cannot be used or when an unusually large helper argv would exceed the platform `ARG_MAX`. Environment changes are applied by Ruby when spawning the helper rather than encoded in helper argv. Use `capture!` when unsuccessful exit statuses should raise.

```ruby
result = Landlock.capture(
  ["ffprobe", "-v", "error", "-show_format", "-of", "json", upload_path],
  read: [upload_path, "/usr", "/lib", "/lib64", "/etc"].select { |path| File.exist?(path) },
  execute: ["/usr", "/lib", "/lib64"].select { |path| File.exist?(path) },
  env: { "PATH" => ENV.fetch("PATH", "") },
  unsetenv_others: true,
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

`Landlock.capture` takes the command as a single argv array, like `Landlock.exec`. It returns a `Landlock::CaptureResult` with `stdout`, `stderr`, `status`, `success?`, `timed_out?`, and `output_truncated?`, including for unsuccessful exit statuses. It also supports array destructuring:

```ruby
stdout, stderr, status = Landlock.capture(
  ["tool", "arg"],
  read: ["/usr", "/lib", "/lib64", "/etc"].select { |path| File.exist?(path) },
  execute: ["/usr", "/lib", "/lib64"].select { |path| File.exist?(path) }
)
```

`Landlock.capture!` has the same return shape for successful commands, but raises `Landlock::CommandError` for unsuccessful statuses. The error also exposes `stdout`, `stderr`, `status`, and `result`.

`Landlock.capture` requires an actual restriction: provide Landlock rules, `seccomp_deny_network: true`, or `rlimits:`. This avoids accidentally running a command completely unsandboxed when a dynamically built policy is empty. It also requires Linux Landlock support and raises `Landlock::UnsupportedError` when unavailable; it does not fall back to running the command unsandboxed.

Pass `stdin:` when a tool should read from standard input instead of a file:

```ruby
stdout, stderr, status = Landlock.capture(
  ["tr", "a-z", "A-Z"],
  stdin: "hello",
  rlimits: { open_files: 64 }
)
```

Capture options:

- `read:`, `write:`, `execute:` — filesystem allowlists. Explicit paths must exist; missing paths raise `ArgumentError` instead of being silently ignored.

  These distinguish `nil` from `[]`. Omitting one (or passing `nil`) leaves that access class outside the ruleset's handled mask, so Landlock does not restrict it **anywhere** — `write: nil` means the child can still create, delete and rename files across the filesystem. Passing `[]` enforces the class while granting no paths, which is what you want for "must not write at all". Prefer `[]` over `nil` unless you deliberately want the class unpoliced.
- `paths:` — exact path rules with explicit Landlock rights, e.g. `{ path:, rights: %i[read_file] }`.
- `connect_tcp:` and `bind_tcp:` — allowed TCP ports, with the same `nil` versus `[]` distinction. `[]` denies all TCP for that operation and requires ABI v4+; `nil` leaves TCP unrestricted.
- `scope:` — Landlock ABI v6+ scopes such as `:signal` and `:abstract_unix_socket`.
- `seccomp_deny_network:` — additionally deny common Linux network syscalls with seccomp. This is Linux-specific and intended as defense in depth.
- `rlimits:` — resource limits. Supported keys are `:cpu_seconds`, `:memory_bytes`, `:file_size_bytes`, `:open_files`, and `:processes`. Values must be non-negative integers.
- `timeout:` — wall-clock timeout in seconds. On timeout capture terminates the process group and returns/raises with `result.timed_out?` true.
- `max_output_bytes:` — combined stdout+stderr byte limit. With `truncate_output: false`, exceeding the limit raises `Landlock::CommandError` with the partial output captured before termination. With `truncate_output: true`, output is truncated and `result.output_truncated?` is true.
- `stdin:` — string or IO-like object to write to the child process stdin.
- `chdir:` — working directory for the child.
- `env:` — environment entries for the child.
- `unsetenv_others:` — clear the parent environment before applying `env:`.
- `success_status_codes:` and `failure_message:` — `capture!` failure handling options.
- `allow_all_known:` — when filesystem rules are present, handle all Landlock filesystem rights known to the running ABI so unlisted filesystem access is denied.

## Forking a Ruby block

`Landlock.fork` is a supervised, synchronous fork. It forks the current Ruby process, applies the requested restrictions in the child, runs the block there, waits for it, and returns a `Landlock::CaptureResult`. It is intended for applications that need to reuse initialized Ruby state without executing a new command:

```ruby
result = Landlock.fork(
  read: [input_path],
  timeout: 5,
  rlimits: { cpu_seconds: 5, memory_bytes: 512 * 1024 * 1024 },
  seccomp_deny_network: true
) do |stdout, _stderr|
  stdout.write(calculate_dominant_color(input_path))
end

color = result.stdout if result.success?
```

The block receives its child-side stdout and stderr streams. Write response data to stdout and diagnostics to stderr, then inspect them through the capture result in the parent. The block's return value is discarded. An exception makes the child exit with status 1 and writes a diagnostic to stderr. `fork` accepts the capture options listed above except `success_status_codes:` and `failure_message:`, which only apply to `capture!`.

By default, `Landlock.fork` requires Linux Landlock support and raises `Landlock::UnsupportedError` before forking when the Landlock ABI is unavailable. A Linux caller that explicitly accepts running without Landlock filesystem, TCP, and scope enforcement can opt in to the fallback:

```ruby
result = Landlock.fork(
  on_unsupported: :run_without_landlock,
  timeout: 5,
  rlimits: { memory_bytes: 512 * 1024 * 1024 },
  seccomp_deny_network: true
) { |stdout, _stderr| stdout.write(run_plugin) }
```

This fallback is used only when the Linux kernel has no Landlock ABI. It skips only Landlock policy enforcement; fork supervision, timeout handling, environment changes, descriptor closing, rlimits, output capture, and seccomp remain active. It is never selected implicitly, and non-Linux systems still raise `Landlock::UnsupportedError`. When fallback is active, the call must include `seccomp_deny_network: true` or at least one `rlimits:` entry because Landlock rules are not effective restrictions in that mode. Timeout, environment handling, descriptor closing, and output limits do not satisfy this requirement. `Landlock.fork` requires an actual restriction. By default the child closes inherited Ruby `IO` objects other than stdin, stdout, and stderr, but native extensions may hold descriptors Ruby does not expose as `IO` objects. Pass `close_others: false` only when the child intentionally needs an inherited descriptor. Child setup failures exit 127.

The worker is a process-group leader and reserves Linux real-time signal `SIGRTMIN+2` for parent-death handling while the block runs. If the Ruby thread supervising the synchronous `Landlock.fork` call terminates, a native signal handler sends `SIGKILL` to the worker's process group. This terminates the worker and ordinary descendants that remain in that group. It does not cover descendants that create another process group or session, and the group-wide guarantee can be disabled by code that replaces or blocks the reserved signal, clears the parent-death signal, changes credentials in a way that clears it, or replaces the worker with `exec`. After `exec`, the reserved signal still terminates the worker by default, but the reset handler no longer kills its process group. This is process-lifecycle hardening, not a cgroup, PID namespace, or hostile-process containment boundary.

Fork only from a process whose loaded libraries and runtime state are safe to use after `fork`. `Landlock.fork` cannot make an unsafe parent fork-safe, and the block must not depend on threads that exist only in the parent.

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

`Landlock.restrict!` only installs a Landlock ruleset. It does not close already-open file descriptors, impose resource limits, clean the environment, or kill subprocess trees. The subprocess helpers add practical hardening around this: `exec`/`spawn` add controlled environments and `close_others`, while `capture` also adds optional `rlimits:`, optional `seccomp_deny_network:`, output limits, timeout handling, and process-group termination. This is still not a VM/container boundary. By default, subprocess helpers close inherited file descriptors numbered 3 and higher before installing the sandbox; pass `close_others: false` only when the child intentionally needs inherited descriptors. Direct `landlock-safe-exec` use also closes inherited descriptors by default.

When the native helper is used, sandbox policy details such as allowed paths, TCP ports, scopes, rights, and rlimits are passed as helper argv. They may be visible to same-user processes through tools such as `ps` or `/proc/<pid>/cmdline` until the helper execs the target command. Environment values passed with `env:` are not encoded in helper argv, but do not put secrets in policy path names or other policy arguments.

If `Landlock.exec`, `Landlock.spawn`, or `Landlock.capture` child setup fails before `exec`, the child prints a diagnostic and exits 127. `landlock-safe-exec` setup/argument failures exit 126. These codes can collide with commands that legitimately exit with the same status, so inspect stderr when debugging failures.

Path rules follow the kernel's normal path resolution when the rule is installed. Because paths are opened without `O_NOFOLLOW`, a symlink rule applies to the symlink target's inode, not to the symlink path itself. Capture APIs validate explicit `read:`, `write:`, and `execute:` paths before launching so typos fail closed instead of silently weakening a policy.

Landlock only restricts access rights included in a ruleset's handled set: omitted categories remain allowed. Use `allow_all_known: true` when you want unlisted filesystem actions denied. Landlock TCP rules do not cover UDP or pathname Unix-domain sockets; ABI v6+ scopes can restrict signals and abstract Unix-domain sockets. `seccomp_deny_network:` is Linux-specific defense in depth for common network syscalls, not a general-purpose seccomp policy language.

`Landlock.restrict!` applies to the calling thread and its future children; already-running sibling threads are not retroactively sandboxed. Prefer `Landlock.capture`, `Landlock.exec`, or `Landlock.spawn` for subprocess sandboxing from a larger Ruby application.
