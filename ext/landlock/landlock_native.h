#ifndef RB_LANDLOCK_NATIVE_H
#define RB_LANDLOCK_NATIVE_H

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/prctl.h>
#include <sys/syscall.h>
#ifdef HAVE_LINUX_LANDLOCK_H
#include <linux/landlock.h>
#endif
#endif

#ifndef SYS_landlock_create_ruleset
# if defined(__linux__) && defined(__NR_landlock_create_ruleset) && defined(__NR_landlock_add_rule) && defined(__NR_landlock_restrict_self)
#  define SYS_landlock_create_ruleset __NR_landlock_create_ruleset
#  define SYS_landlock_add_rule __NR_landlock_add_rule
#  define SYS_landlock_restrict_self __NR_landlock_restrict_self
# elif defined(__linux__) && defined(__x86_64__) && defined(__ILP32__)
#  ifndef __X32_SYSCALL_BIT
#   define __X32_SYSCALL_BIT 0x40000000
#  endif
#  define SYS_landlock_create_ruleset (__X32_SYSCALL_BIT + 444)
#  define SYS_landlock_add_rule (__X32_SYSCALL_BIT + 445)
#  define SYS_landlock_restrict_self (__X32_SYSCALL_BIT + 446)
# elif defined(__linux__) && (defined(__x86_64__) || defined(__aarch64__) || defined(__i386__))
#  define SYS_landlock_create_ruleset 444
#  define SYS_landlock_add_rule 445
#  define SYS_landlock_restrict_self 446
# endif
#endif

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

#ifndef LANDLOCK_RULE_PATH_BENEATH
#define LANDLOCK_RULE_PATH_BENEATH 1
#endif

#ifndef LANDLOCK_RULE_NET_PORT
#define LANDLOCK_RULE_NET_PORT 2
#endif

#ifndef LANDLOCK_ACCESS_FS_EXECUTE
#define LANDLOCK_ACCESS_FS_EXECUTE    (1ULL << 0)
#endif
#ifndef LANDLOCK_ACCESS_FS_WRITE_FILE
#define LANDLOCK_ACCESS_FS_WRITE_FILE (1ULL << 1)
#endif
#ifndef LANDLOCK_ACCESS_FS_READ_FILE
#define LANDLOCK_ACCESS_FS_READ_FILE  (1ULL << 2)
#endif
#ifndef LANDLOCK_ACCESS_FS_READ_DIR
#define LANDLOCK_ACCESS_FS_READ_DIR   (1ULL << 3)
#endif
#ifndef LANDLOCK_ACCESS_FS_REMOVE_DIR
#define LANDLOCK_ACCESS_FS_REMOVE_DIR (1ULL << 4)
#endif
#ifndef LANDLOCK_ACCESS_FS_REMOVE_FILE
#define LANDLOCK_ACCESS_FS_REMOVE_FILE (1ULL << 5)
#endif
#ifndef LANDLOCK_ACCESS_FS_MAKE_CHAR
#define LANDLOCK_ACCESS_FS_MAKE_CHAR  (1ULL << 6)
#endif
#ifndef LANDLOCK_ACCESS_FS_MAKE_DIR
#define LANDLOCK_ACCESS_FS_MAKE_DIR   (1ULL << 7)
#endif
#ifndef LANDLOCK_ACCESS_FS_MAKE_REG
#define LANDLOCK_ACCESS_FS_MAKE_REG   (1ULL << 8)
#endif
#ifndef LANDLOCK_ACCESS_FS_MAKE_SOCK
#define LANDLOCK_ACCESS_FS_MAKE_SOCK  (1ULL << 9)
#endif
#ifndef LANDLOCK_ACCESS_FS_MAKE_FIFO
#define LANDLOCK_ACCESS_FS_MAKE_FIFO  (1ULL << 10)
#endif
#ifndef LANDLOCK_ACCESS_FS_MAKE_BLOCK
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK (1ULL << 11)
#endif
#ifndef LANDLOCK_ACCESS_FS_MAKE_SYM
#define LANDLOCK_ACCESS_FS_MAKE_SYM   (1ULL << 12)
#endif
#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER      (1ULL << 13)
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE   (1ULL << 14)
#endif
#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV  (1ULL << 15)
#endif

#ifndef LANDLOCK_ACCESS_NET_BIND_TCP
#define LANDLOCK_ACCESS_NET_BIND_TCP    (1ULL << 0)
#endif
#ifndef LANDLOCK_ACCESS_NET_CONNECT_TCP
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
#endif

#ifndef LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET
#define LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET (1ULL << 0)
#endif
#ifndef LANDLOCK_SCOPE_SIGNAL
#define LANDLOCK_SCOPE_SIGNAL (1ULL << 1)
#endif

#ifndef O_PATH
#define O_PATH 010000000
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 02000000
#endif

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

struct rb_landlock_ruleset_attr {
  uint64_t handled_access_fs;
  uint64_t handled_access_net;
  uint64_t scoped;
};

struct rb_landlock_path_beneath_attr {
  uint64_t allowed_access;
  int32_t parent_fd;
} __attribute__((packed));

struct rb_landlock_net_port_attr {
  uint64_t allowed_access;
  uint64_t port;
};

static long ll_create_ruleset(const void *attr, size_t size, uint32_t flags) {
#ifdef SYS_landlock_create_ruleset
  return syscall(SYS_landlock_create_ruleset, attr, size, flags);
#else
  errno = ENOSYS;
  return -1;
#endif
}

static long ll_add_rule(int ruleset_fd, int rule_type, const void *rule_attr, uint32_t flags) {
#ifdef SYS_landlock_add_rule
  return syscall(SYS_landlock_add_rule, ruleset_fd, rule_type, rule_attr, flags);
#else
  errno = ENOSYS;
  return -1;
#endif
}

static long ll_restrict_self(int ruleset_fd, uint32_t flags) {
#ifdef SYS_landlock_restrict_self
  return syscall(SYS_landlock_restrict_self, ruleset_fd, flags);
#else
  errno = ENOSYS;
  return -1;
#endif
}

#endif
