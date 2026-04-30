#include "../landlock_native.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/resource.h>
#include <sys/stat.h>

#ifdef __linux__
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#endif

#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW 0x7fff0000U
#endif
#ifndef SECCOMP_RET_ERRNO
#define SECCOMP_RET_ERRNO 0x00050000U
#endif
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif

typedef struct {
  char **items;
  size_t len;
  size_t cap;
} string_list;

typedef struct {
  unsigned long long *items;
  size_t len;
  size_t cap;
} ull_list;

static void die(const char *message) {
  perror(message);
  _exit(126);
}

static void die_msg(const char *message) {
  fprintf(stderr, "landlock-safe-exec: %s\n", message);
  _exit(126);
}

static void string_list_push(string_list *list, char *value) {
  if (list->len == list->cap) {
    size_t cap = list->cap ? list->cap * 2 : 8;
    char **items = realloc(list->items, cap * sizeof(char *));
    if (!items) die("realloc");
    list->items = items;
    list->cap = cap;
  }
  list->items[list->len++] = value;
}

static void ull_list_push(ull_list *list, unsigned long long value) {
  if (list->len == list->cap) {
    size_t cap = list->cap ? list->cap * 2 : 8;
    unsigned long long *items = realloc(list->items, cap * sizeof(unsigned long long));
    if (!items) die("realloc");
    list->items = items;
    list->cap = cap;
  }
  list->items[list->len++] = value;
}

static unsigned long long parse_ull(const char *value, const char *name) {
  if (!value || value[0] == '\0' || value[0] == '-') die_msg(name);

  errno = 0;
  char *end = NULL;
  unsigned long long parsed = strtoull(value, &end, 10);
  if (errno == ERANGE || !end || *end != '\0') die_msg(name);

  return parsed;
}

static unsigned long long parse_port(const char *value) {
  unsigned long long port = parse_ull(value, "TCP port must be an integer between 0 and 65535");
  if (port > 65535ULL) die_msg("TCP port must be between 0 and 65535");
  return port;
}

static int abi_version(void) {
  long abi = ll_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
  if (abi < 0 && (errno == ENOSYS || errno == EOPNOTSUPP)) return 0;
  if (abi < 0) die("landlock_create_ruleset(version)");
  return (int)abi;
}

static uint64_t known_fs_rights_for_abi(int abi) {
  uint64_t rights = LANDLOCK_ACCESS_FS_EXECUTE |
                    LANDLOCK_ACCESS_FS_WRITE_FILE |
                    LANDLOCK_ACCESS_FS_READ_FILE |
                    LANDLOCK_ACCESS_FS_READ_DIR |
                    LANDLOCK_ACCESS_FS_REMOVE_DIR |
                    LANDLOCK_ACCESS_FS_REMOVE_FILE |
                    LANDLOCK_ACCESS_FS_MAKE_CHAR |
                    LANDLOCK_ACCESS_FS_MAKE_DIR |
                    LANDLOCK_ACCESS_FS_MAKE_REG |
                    LANDLOCK_ACCESS_FS_MAKE_SOCK |
                    LANDLOCK_ACCESS_FS_MAKE_FIFO |
                    LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                    LANDLOCK_ACCESS_FS_MAKE_SYM;
  if (abi >= 2) rights |= LANDLOCK_ACCESS_FS_REFER;
  if (abi >= 3) rights |= LANDLOCK_ACCESS_FS_TRUNCATE;
  if (abi >= 5) rights |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
  return rights;
}

static uint64_t read_rights(void) {
  return LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
}

static uint64_t execute_rights(void) {
  return LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
}

static uint64_t write_rights(int abi) {
  return known_fs_rights_for_abi(abi) & ~LANDLOCK_ACCESS_FS_EXECUTE;
}

static uint64_t file_path_rights(void) {
  return LANDLOCK_ACCESS_FS_EXECUTE |
         LANDLOCK_ACCESS_FS_WRITE_FILE |
         LANDLOCK_ACCESS_FS_READ_FILE |
         LANDLOCK_ACCESS_FS_TRUNCATE |
         LANDLOCK_ACCESS_FS_IOCTL_DEV;
}

static void add_path_rule(int fd, const char *path, uint64_t rights) {
  int parent_fd = open(path, O_PATH | O_CLOEXEC);
  if (parent_fd < 0) die("open(path rule)");

  struct stat st;
  if (fstat(parent_fd, &st) != 0) die("fstat(path rule)");
  if (!S_ISDIR(st.st_mode)) rights &= file_path_rights();

  struct rb_landlock_path_beneath_attr rule;
  memset(&rule, 0, sizeof(rule));
  rule.allowed_access = rights;
  rule.parent_fd = parent_fd;

  long ret = ll_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &rule, 0);
  int saved_errno = errno;
  close(parent_fd);
  if (ret < 0) {
    errno = saved_errno;
    die("landlock_add_rule(path_beneath)");
  }
}

static void add_net_rule(int fd, unsigned long long port, uint64_t rights) {
  if (port > 65535ULL) die_msg("TCP port must be between 0 and 65535");
  struct rb_landlock_net_port_attr rule;
  memset(&rule, 0, sizeof(rule));
  rule.allowed_access = rights;
  rule.port = port;
  if (ll_add_rule(fd, LANDLOCK_RULE_NET_PORT, &rule, 0) < 0) die("landlock_add_rule(net_port)");
}

static void apply_landlock(string_list *read_paths, string_list *write_paths, string_list *execute_paths,
                           ull_list *connect_ports, ull_list *bind_ports, int allow_all_known) {
  int need_fs = read_paths->len || write_paths->len || execute_paths->len || allow_all_known;
  int need_net = connect_ports->len || bind_ports->len;
  if (!need_fs && !need_net) return;

  int abi = abi_version();
  if (abi <= 0) die_msg("Linux Landlock is unavailable");
  if (need_net && abi < 4) die_msg("Landlock network rules require ABI v4+");

  uint64_t fs_handled = allow_all_known ? known_fs_rights_for_abi(abi) : 0;
  if (!allow_all_known) {
    if (read_paths->len) fs_handled |= read_rights();
    if (execute_paths->len) fs_handled |= execute_rights();
    if (write_paths->len) fs_handled |= write_rights(abi);
  }
  uint64_t net_handled = 0;
  if (bind_ports->len) net_handled |= LANDLOCK_ACCESS_NET_BIND_TCP;
  if (connect_ports->len) net_handled |= LANDLOCK_ACCESS_NET_CONNECT_TCP;

  struct rb_landlock_ruleset_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.handled_access_fs = fs_handled;
  attr.handled_access_net = net_handled;

  size_t attr_size = net_handled ? offsetof(struct rb_landlock_ruleset_attr, scoped) : offsetof(struct rb_landlock_ruleset_attr, handled_access_net);
  int fd = (int)ll_create_ruleset(&attr, attr_size, 0);
  if (fd < 0) die("landlock_create_ruleset");

  for (size_t i = 0; i < read_paths->len; i++) add_path_rule(fd, read_paths->items[i], read_rights());
  for (size_t i = 0; i < execute_paths->len; i++) add_path_rule(fd, execute_paths->items[i], execute_rights());
  for (size_t i = 0; i < write_paths->len; i++) add_path_rule(fd, write_paths->items[i], write_rights(abi));
  for (size_t i = 0; i < connect_ports->len; i++) add_net_rule(fd, connect_ports->items[i], LANDLOCK_ACCESS_NET_CONNECT_TCP);
  for (size_t i = 0; i < bind_ports->len; i++) add_net_rule(fd, bind_ports->items[i], LANDLOCK_ACCESS_NET_BIND_TCP);

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) die("prctl(PR_SET_NO_NEW_PRIVS)");
  if (ll_restrict_self(fd, 0) < 0) die("landlock_restrict_self");
  close(fd);
}

static void apply_rlimit(const char *spec) {
  char *copy = strdup(spec);
  if (!copy) die("strdup");
  char *eq = strchr(copy, '=');
  if (!eq) die_msg("rlimit must be name=value");
  *eq = '\0';
  unsigned long long value = parse_ull(eq + 1, "rlimit value must be a non-negative integer");
  int resource = -1;

  if (strcmp(copy, "cpu_seconds") == 0) resource = RLIMIT_CPU;
#ifdef RLIMIT_AS
  else if (strcmp(copy, "memory_bytes") == 0) resource = RLIMIT_AS;
#endif
  else if (strcmp(copy, "file_size_bytes") == 0) resource = RLIMIT_FSIZE;
  else if (strcmp(copy, "open_files") == 0) resource = RLIMIT_NOFILE;
#ifdef RLIMIT_NPROC
  else if (strcmp(copy, "processes") == 0) resource = RLIMIT_NPROC;
#endif
  else die_msg("unknown rlimit");

  struct rlimit limit;
  limit.rlim_cur = (rlim_t)value;
  limit.rlim_max = (rlim_t)value;
  if (setrlimit(resource, &limit) != 0) die("setrlimit");
  free(copy);
}

static int deny_syscalls[] = {
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

#ifdef AUDIT_ARCH_X86_64
#define EXPECTED_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(AUDIT_ARCH_AARCH64)
#define EXPECTED_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(AUDIT_ARCH_I386)
#define EXPECTED_AUDIT_ARCH AUDIT_ARCH_I386
#endif

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif

static void apply_seccomp_deny_network(void) {
  size_t count = sizeof(deny_syscalls) / sizeof(deny_syscalls[0]);
  if (count == 0) return;

  size_t len = 1 + (2 * count) + 1;
#ifdef EXPECTED_AUDIT_ARCH
  len += 3;
#endif
  struct sock_filter *filter = calloc(len, sizeof(struct sock_filter));
  if (!filter) die("calloc");

  size_t pc = 0;
#ifdef EXPECTED_AUDIT_ARCH
  filter[pc++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
  filter[pc++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, EXPECTED_AUDIT_ARCH, 1, 0);
  filter[pc++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
#endif
  filter[pc++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
  for (size_t i = 0; i < count; i++) {
    filter[pc++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned int)deny_syscalls[i], 0, 1);
    filter[pc++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
  }
  filter[pc++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

  struct sock_fprog prog;
  prog.len = (unsigned short)pc;
  prog.filter = filter;

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) die("prctl(PR_SET_NO_NEW_PRIVS)");
#ifdef SYS_seccomp
  if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) != 0)
#endif
  {
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) die("seccomp(SECCOMP_SET_MODE_FILTER)");
  }
  free(filter);
}

static char *require_arg(int argc, char **argv, int *i) {
  if (*i + 1 >= argc) die_msg("missing option argument");
  (*i)++;
  return argv[*i];
}

int main(int argc, char **argv) {
  string_list read_paths = {0}, write_paths = {0}, execute_paths = {0}, env_vars = {0};
  ull_list connect_ports = {0}, bind_ports = {0};
  int unsetenv_others = 0, seccomp_deny_network = 0, allow_all_known = 0;
  char *chdir_path = NULL;
  int command_index = -1;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--") == 0) { command_index = i + 1; break; }
    if (strcmp(argv[i], "--read") == 0) string_list_push(&read_paths, require_arg(argc, argv, &i));
    else if (strcmp(argv[i], "--write") == 0) string_list_push(&write_paths, require_arg(argc, argv, &i));
    else if (strcmp(argv[i], "--execute") == 0) string_list_push(&execute_paths, require_arg(argc, argv, &i));
    else if (strcmp(argv[i], "--connect-tcp") == 0) ull_list_push(&connect_ports, parse_port(require_arg(argc, argv, &i)));
    else if (strcmp(argv[i], "--bind-tcp") == 0) ull_list_push(&bind_ports, parse_port(require_arg(argc, argv, &i)));
    else if (strcmp(argv[i], "--chdir") == 0) chdir_path = require_arg(argc, argv, &i);
    else if (strcmp(argv[i], "--env") == 0) string_list_push(&env_vars, require_arg(argc, argv, &i));
    else if (strcmp(argv[i], "--unsetenv-others") == 0) unsetenv_others = 1;
    else if (strcmp(argv[i], "--rlimit") == 0) apply_rlimit(require_arg(argc, argv, &i));
    else if (strcmp(argv[i], "--seccomp-deny-network") == 0) seccomp_deny_network = 1;
    else if (strcmp(argv[i], "--allow-all-known") == 0) allow_all_known = 1;
    else die_msg("unknown option");
  }

  if (command_index < 0 || command_index >= argc) die_msg("missing command after --");

  if (chdir_path && chdir(chdir_path) != 0) die("chdir");
  if (unsetenv_others && clearenv() != 0) die("clearenv");
  for (size_t i = 0; i < env_vars.len; i++) {
    if (putenv(env_vars.items[i]) != 0) die("putenv");
  }

  apply_landlock(&read_paths, &write_paths, &execute_paths, &connect_ports, &bind_ports, allow_all_known);
  if (seccomp_deny_network) apply_seccomp_deny_network();

  execvp(argv[command_index], &argv[command_index]);
  die("execvp");
}
