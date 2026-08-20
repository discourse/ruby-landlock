# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

## [0.4.1] - 2026-08-20

### Fixed

- Remove the 100 ms child-exit polling interval from subprocess capture. Capture now drains stdout and stderr before waiting directly for the child, while preserving wall-clock timeout enforcement after both streams close.

## [0.4] - 2026-08-10

### Changed

- **Breaking.** `read:`, `write:`, `execute:`, `connect_tcp:` and `bind_tcp:` treat an empty array as "block all" rather than "allow all". These were previously controlled by the length of each allowlist, so `read: []` turned off all read restrictions instead of denying everything. `nil` is now the "restrictions disabled" flag and the new default; `[]` means "restriction on, empty allowlist". Callers relying on `[]` to mean unrestricted must pass `nil`; callers passing populated arrays are unaffected.
- The native helper marks an enabled-but-empty restriction by passing the existing flag with an empty value, e.g. `--write ""`. An omitted flag leaves the restriction disabled.

## [0.3] - 2026-06-17

### Added

- Add top-level `Landlock.capture` and `Landlock.capture!`, direct Landlock/`exec` capture APIs with stdout/stderr capture, stdin, wall-clock timeout with process-group cleanup, output byte limits, `rlimits:`, controlled environments, `chdir:`, TCP/scoped Landlock rules, `allow_all_known:`, and optional `seccomp_deny_network:`.
- Expose `Landlock.seccomp_deny_network!` from the native extension so capture children can install the same deny-network seccomp filter used by the helper binary.

### Changed

- Remove the legacy `Landlock::SafeExec` Ruby facade. Use `Landlock.capture`/`capture!` with argv arrays for captured subprocesses and `Landlock.exec`/`spawn` for non-capturing subprocesses.
- `Landlock.exec`, `Landlock.spawn`, and `Landlock.capture` now use the packaged native `landlock-safe-exec` helper when available, passing sandbox policy as helper arguments to avoid forking a large Ruby process for child setup and falling back to the Ruby fork runner if the helper argv exceeds `ARG_MAX`.
- Split subprocess running internals into `Landlock::Runner::Native` and `Landlock::Runner::Fork` backends, with shared validation, process I/O, rlimit, environment, and policy helpers.
- Normalize subprocess `env:` keys and values in Ruby before spawning and keep environment values out of native-helper argv.
- Require non-empty `Landlock.exec`/`spawn` policies instead of launching an unsandboxed command when no Landlock rules are provided.

### Fixed

- Treat timeouts as failures for `capture!` even when a command handles termination and exits with an otherwise successful status.
- Bound post-timeout pipe draining so escaped descendants that keep stdout/stderr open cannot hang capture past the requested timeout.
- Harden `landlock-safe-exec` by closing inherited file descriptors, applying rlimits after sandbox setup, matching Ruby `write:` rights, tightening CLI parsing, and making the shared seccomp network-deny filter reject x32 syscall-number bypasses.
- Validate `Landlock.capture` filesystem policy paths before forking so missing paths raise `ArgumentError`.
- Reject empty `Landlock.capture` policies unless another restriction such as seccomp or rlimits is provided.
- Filter directory-only custom path-rule rights for file paths in `Landlock.restrict!`, matching helper behavior.

### Documentation

- Document `Landlock.capture`, its result/error types, capture options, and subprocess sandboxing guidance.

### [0.2.1] - 2026-06-16

- Build `landlock-safe-exec` without Ruby extension `$(LIBS)` to avoid unnecessary runtime library dependencies and improve SafeExec helper startup time.

## [0.2] - 2026-04-30

- Add `Landlock::SafeExec.capture`, backed by a compiled `landlock-safe-exec` helper, for subprocess capture with Landlock, optional seccomp network denial, resource limits, exact environment handling, stdin, timeout handling, process-group cleanup, result metadata, and output limits.
- Share native Landlock syscall/constant definitions between the Ruby extension and helper binary.
- Add non-Linux/pass-through SafeExec behavior so integration code can run on platforms without the Linux sandbox backend while warning that sandbox options are ignored.

## [0.1.1] - 2026-04-30

### Security

- Require `Landlock.exec` and `Landlock.spawn` commands to be passed as argument arrays. This avoids Ruby's implicit shell execution path for string commands.
- Execute subprocesses with an explicit `argv[0]` tuple (`[command, command]`) so array commands keep their no-shell behavior.
- Use `exit! 127` for child setup failures before `exec`, preventing inherited `at_exit` handlers from running in the forked child.
- Honor `unsetenv_others: true` by passing Ruby's `unsetenv_others` exec option instead of only constructing a reduced environment hash.
- Add ABI v6 Landlock scoping support via `scope: [:signal, :abstract_unix_socket]` to restrict signalling and abstract Unix-domain socket access outside the sandbox domain.
- Expose `allow_all_known:` on `Landlock.exec` and `Landlock.spawn` so subprocess sandboxes can deny unlisted filesystem actions without needing dummy allow rules.

### Fixed

- Allow high-level `read`, `write`, and `execute` helpers to target individual files by filtering directory-only rights before adding file path rules.
- Fix fallback Landlock syscall numbers on i386, handle x32, and prefer platform `__NR_*` constants when available.
- Convert path rule arguments before opening path file descriptors in the native extension to avoid leaking descriptors on argument conversion errors.

### Documentation

- Document important sandbox caveats: only handled rights are restricted, TCP rules do not cover UDP/pathname Unix sockets, already-open descriptors remain usable, and `restrict!` applies to the calling thread and future children.

### Tests

- Add coverage for no-shell argv validation, child setup failure behavior, `unsetenv_others`, strict filesystem subprocess policies, file-specific path rules, and ABI v6 signal scoping.

## [0.1.0] - 2026-04-30

### Added

- Initial Ruby bindings for Linux Landlock rulesets, filesystem path rules, TCP port rules, and safe subprocess helpers.
