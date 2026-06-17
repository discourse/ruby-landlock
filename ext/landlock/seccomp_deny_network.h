#ifndef RB_LANDLOCK_SECCOMP_DENY_NETWORK_H
#define RB_LANDLOCK_SECCOMP_DENY_NETWORK_H

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif

#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW 0x7fff0000U
#endif
#ifndef SECCOMP_RET_ERRNO
#define SECCOMP_RET_ERRNO 0x00050000U
#endif
#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif

#ifdef __linux__
static int rb_landlock_deny_network_syscalls[] = {
#ifdef __NR_socket
    __NR_socket,
#endif
#ifdef __NR_socketpair
    __NR_socketpair,
#endif
#ifdef __NR_connect
    __NR_connect,
#endif
#ifdef __NR_bind
    __NR_bind,
#endif
#ifdef __NR_listen
    __NR_listen,
#endif
#ifdef __NR_accept
    __NR_accept,
#endif
#ifdef __NR_accept4
    __NR_accept4,
#endif
#ifdef __NR_sendto
    __NR_sendto,
#endif
#ifdef __NR_sendmsg
    __NR_sendmsg,
#endif
#ifdef __NR_sendmmsg
    __NR_sendmmsg,
#endif
#ifdef __NR_recvfrom
    __NR_recvfrom,
#endif
#ifdef __NR_recvmsg
    __NR_recvmsg,
#endif
#ifdef __NR_recvmmsg
    __NR_recvmmsg,
#endif
#ifdef __NR_socketcall
    __NR_socketcall,
#endif
};

#if defined(__x86_64__) && defined(AUDIT_ARCH_X86_64)
#define RB_LANDLOCK_EXPECTED_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__) && defined(AUDIT_ARCH_AARCH64)
#define RB_LANDLOCK_EXPECTED_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(__i386__) && defined(AUDIT_ARCH_I386)
#define RB_LANDLOCK_EXPECTED_AUDIT_ARCH AUDIT_ARCH_I386
#endif

#if defined(__x86_64__) && !defined(__ILP32__)
#ifndef __X32_SYSCALL_BIT
#define __X32_SYSCALL_BIT 0x40000000
#endif
#define RB_LANDLOCK_DENY_X32_SYSCALLS 1
#endif
#endif

static int rb_landlock_seccomp_deny_network(const char **error_message) {
#ifdef __linux__
#ifndef RB_LANDLOCK_EXPECTED_AUDIT_ARCH
  errno = ENOSYS;
  if (error_message) {
    *error_message = "seccomp unsupported architecture";
  }
  return -1;
#else
  size_t count =
      sizeof(rb_landlock_deny_network_syscalls) / sizeof(rb_landlock_deny_network_syscalls[0]);
  if (count == 0) {
    return 0;
  }

  size_t len = 1 + (2 * count) + 1;
  len += 3;
#ifdef RB_LANDLOCK_DENY_X32_SYSCALLS
  len += 2;
#endif
  struct sock_filter *filter = calloc(len, sizeof(struct sock_filter));
  if (!filter) {
    if (error_message) {
      *error_message = "calloc";
    }
    return -1;
  }

  size_t pc = 0;
  filter[pc++] =
      (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
  filter[pc++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                              RB_LANDLOCK_EXPECTED_AUDIT_ARCH, 1, 0);
  filter[pc++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
  filter[pc++] =
      (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
#ifdef RB_LANDLOCK_DENY_X32_SYSCALLS
  filter[pc++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, __X32_SYSCALL_BIT, 0, 1);
  filter[pc++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
#endif
  for (size_t i = 0; i < count; i++) {
    filter[pc++] = (struct sock_filter)BPF_JUMP(
        BPF_JMP | BPF_JEQ | BPF_K, (unsigned int)rb_landlock_deny_network_syscalls[i], 0, 1);
    filter[pc++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
  }
  filter[pc++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

  struct sock_fprog prog;
  prog.len = (unsigned short)pc;
  prog.filter = filter;

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    if (error_message) {
      *error_message = "prctl(PR_SET_NO_NEW_PRIVS)";
    }
    free(filter);
    return -1;
  }
#ifdef SYS_seccomp
  if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) == 0) {
    free(filter);
    return 0;
  }
#endif
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
    if (error_message) {
      *error_message = "seccomp(SECCOMP_SET_MODE_FILTER)";
    }
    free(filter);
    return -1;
  }

  free(filter);
  return 0;
#endif
#else
  errno = ENOSYS;
  if (error_message) {
    *error_message = "seccomp(SECCOMP_SET_MODE_FILTER)";
  }
  return -1;
#endif
}

#endif
