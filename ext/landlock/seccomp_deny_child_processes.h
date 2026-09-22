#ifndef RB_LANDLOCK_SECCOMP_DENY_CHILD_PROCESSES_H
#define RB_LANDLOCK_SECCOMP_DENY_CHILD_PROCESSES_H

#include "seccomp_deny_network.h"
#ifdef __linux__
#include <sched.h>
#endif

static int rb_landlock_seccomp_deny_child_processes(const char **error_message) {
#if defined(__linux__) && defined(RB_LANDLOCK_EXPECTED_AUDIT_ARCH) && defined(__NR_clone3) &&      \
    !(defined(__x86_64__) && defined(__ILP32__))
  struct sock_filter filter[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, RB_LANDLOCK_EXPECTED_AUDIT_ARCH, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
#ifdef RB_LANDLOCK_DENY_X32_SYSCALLS
      BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, __X32_SYSCALL_BIT, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
#endif
#ifdef __NR_fork
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fork, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
#endif
#ifdef __NR_vfork
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_vfork, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
#endif
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
      BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_THREAD, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog program = {.len = sizeof(filter) / sizeof(filter[0]), .filter = filter};
  *error_message = "prctl(PR_SET_NO_NEW_PRIVS)";
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    return -1;
  }
  *error_message = "seccomp deny child processes";
  return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
#else
  *error_message = "seccomp deny child processes unsupported architecture or syscall headers";
  errno = ENOSYS;
  return -1;
#endif
}

#endif
