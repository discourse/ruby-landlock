# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### [0.2] - 2026-04-30

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
