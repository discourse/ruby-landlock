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

Pass commands as an argument array. `Landlock.exec` and `Landlock.spawn` do not invoke a shell implicitly; use an explicit shell in the array if that is really required.

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
  read: ["/usr", "/lib", "/lib64", "/etc/ssl", "/etc/resolv.conf", "/etc/hosts"],
  execute: ["/usr", "/lib", "/lib64"],
  connect_tcp: [443],
  allow_all_known: true
)
```

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

## Caveats

Landlock is not a complete container. It does not impose CPU/memory limits, hide already-open file descriptors, or replace seccomp/namespaces/cgroups. For serious untrusted execution, combine it with a controlled environment, `close_others`, resource limits, and preferably process isolation.

Landlock only restricts access rights included in a ruleset's handled set: omitted categories remain allowed. Use `allow_all_known: true` when you want unlisted filesystem actions denied. The high-level helpers handle the categories you pass (`read`, `write`, `execute`, `connect_tcp`, `bind_tcp`, `scope`). Landlock's TCP rules do not cover UDP or pathname Unix-domain sockets; ABI v6+ scopes can restrict signals and abstract Unix-domain sockets.

`Landlock.restrict!` applies to the calling thread and its future children; already-running sibling threads are not retroactively sandboxed. Prefer `Landlock.exec` or `Landlock.spawn` for subprocess sandboxing from a larger Ruby application.
