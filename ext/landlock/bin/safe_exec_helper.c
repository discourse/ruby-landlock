#include "../landlock_native.h"
#include "../seccomp_deny_network.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/resource.h>
#include <sys/stat.h>

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

typedef struct {
  char *path;
  uint64_t rights;
} path_rule;

typedef struct {
  path_rule *items;
  size_t len;
  size_t cap;
} path_rule_list;

#define MAX_CSV_RIGHTS 64U

static void die(const char *message) {
  perror(message);
  _exit(126);
}

static void die_path(const char *message, const char *path) {
  int saved_errno = errno;
  fprintf(stderr, "landlock-safe-exec: %s %s: %s\n", message, path, strerror(saved_errno));
  _exit(126);
}

static void die_msg(const char *message) {
  fprintf(stderr, "landlock-safe-exec: %s\n", message);
  _exit(126);
}

static void die_no_effective_path_rights(const char *path) {
  fprintf(stderr, "landlock-safe-exec: path rule has no effective rights: %s\n", path);
  _exit(126);
}

static void string_list_push(string_list *list, char *value) {
  if (list->len == list->cap) {
    size_t cap = list->cap ? list->cap * 2 : 8;
    char **items = realloc(list->items, cap * sizeof(char *));
    if (!items) {
      die("realloc");
    }
    list->items = items;
    list->cap = cap;
  }
  list->items[list->len++] = value;
}

static void ull_list_push(ull_list *list, unsigned long long value) {
  if (list->len == list->cap) {
    size_t cap = list->cap ? list->cap * 2 : 8;
    unsigned long long *items = realloc(list->items, cap * sizeof(unsigned long long));
    if (!items) {
      die("realloc");
    }
    list->items = items;
    list->cap = cap;
  }
  list->items[list->len++] = value;
}

static void path_rule_list_push(path_rule_list *list, char *path, uint64_t rights) {
  if (list->len == list->cap) {
    size_t cap = list->cap ? list->cap * 2 : 8;
    path_rule *items = realloc(list->items, cap * sizeof(path_rule));
    if (!items) {
      die("realloc");
    }
    list->items = items;
    list->cap = cap;
  }
  list->items[list->len].path = path;
  list->items[list->len].rights = rights;
  list->len++;
}

static unsigned long long parse_ull(const char *value, const char *name) {
  if (!value || value[0] == '\0' || value[0] == '-' || value[0] == '+' ||
      isspace((unsigned char)value[0])) {
    die_msg(name);
  }

  errno = 0;
  char *end = NULL;
  unsigned long long parsed = strtoull(value, &end, 10);
  if (errno == ERANGE || !end || *end != '\0') {
    die_msg(name);
  }

  return parsed;
}

static unsigned long long parse_port(const char *value) {
  unsigned long long port = parse_ull(value, "TCP port must be an integer between 0 and 65535");
  if (port > 65535ULL) {
    die_msg("TCP port must be between 0 and 65535");
  }
  return port;
}

static int abi_version(void) {
  long abi = ll_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
  if (abi < 0 && (errno == ENOSYS || errno == EOPNOTSUPP)) {
    return 0;
  }
  if (abi < 0) {
    die("landlock_create_ruleset(version)");
  }
  return (int)abi;
}

static uint64_t known_fs_rights_for_abi(int abi) {
  uint64_t rights =
      LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE |
      LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
      LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
      LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
      LANDLOCK_ACCESS_FS_MAKE_SYM;
  if (abi >= 2) {
    rights |= LANDLOCK_ACCESS_FS_REFER;
  }
  if (abi >= 3) {
    rights |= LANDLOCK_ACCESS_FS_TRUNCATE;
  }
  if (abi >= 5) {
    rights |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
  }
  return rights;
}

static uint64_t read_rights(void) {
  return LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
}

static uint64_t execute_rights(void) {
  return LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
}

static uint64_t write_rights(int abi) {
  uint64_t rights = LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE |
                    LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR |
                    LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |
                    LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
                    LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |
                    LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM;
  if (abi >= 2) {
    rights |= LANDLOCK_ACCESS_FS_REFER;
  }
  if (abi >= 3) {
    rights |= LANDLOCK_ACCESS_FS_TRUNCATE;
  }
  return rights;
}

static uint64_t file_path_rights(void) {
  return LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE |
         LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_IOCTL_DEV;
}

static uint64_t effective_path_rights(const char *path, uint64_t rights) {
  struct stat st;
  if (stat(path, &st) != 0) {
    die_path("stat(path rule)", path);
  }
  if (!S_ISDIR(st.st_mode)) {
    rights &= file_path_rights();
  }
  return rights;
}

static void add_path_rule(int fd, const char *path, uint64_t rights) {
  int parent_fd = open(path, O_PATH | O_CLOEXEC);
  if (parent_fd < 0) {
    die_path("open(path rule)", path);
  }

  struct stat st;
  if (fstat(parent_fd, &st) != 0) {
    die_path("fstat(path rule)", path);
  }
  if (!S_ISDIR(st.st_mode)) {
    rights &= file_path_rights();
  }
  if (!rights) {
    close(parent_fd);
    return;
  }

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
  if (port > 65535ULL) {
    die_msg("TCP port must be between 0 and 65535");
  }
  struct rb_landlock_net_port_attr rule;
  memset(&rule, 0, sizeof(rule));
  rule.allowed_access = rights;
  rule.port = port;
  if (ll_add_rule(fd, LANDLOCK_RULE_NET_PORT, &rule, 0) < 0) {
    die("landlock_add_rule(net_port)");
  }
}

static void apply_landlock(string_list *read_paths, string_list *write_paths,
                           string_list *execute_paths, path_rule_list *path_rules,
                           ull_list *connect_ports, ull_list *bind_ports, uint64_t scoped,
                           int allow_all_known) {
  int need_fs = read_paths->len || write_paths->len || execute_paths->len || path_rules->len ||
                allow_all_known;
  int need_net = connect_ports->len || bind_ports->len;
  int need_scope = scoped != 0;
  if (!need_fs && !need_net && !need_scope) {
    return;
  }

  int abi = abi_version();
  if (abi <= 0) {
    die_msg("Linux Landlock is unavailable");
  }
  if (need_net && abi < 4) {
    die_msg("Landlock network rules require ABI v4+");
  }
  if (need_scope && abi < 6) {
    die_msg("Landlock scopes require ABI v6+");
  }

  uint64_t known_fs_rights = known_fs_rights_for_abi(abi);
  uint64_t fs_handled = allow_all_known ? known_fs_rights : 0;
  if (!allow_all_known) {
    if (read_paths->len) {
      fs_handled |= read_rights();
    }
    if (execute_paths->len) {
      fs_handled |= execute_rights();
    }
    if (write_paths->len) {
      fs_handled |= write_rights(abi);
    }
    for (size_t i = 0; i < path_rules->len; i++) {
      uint64_t rights = effective_path_rights(path_rules->items[i].path,
                                              path_rules->items[i].rights & known_fs_rights);
      if (!rights) {
        die_no_effective_path_rights(path_rules->items[i].path);
      }
      fs_handled |= rights;
    }
  }
  uint64_t net_handled = 0;
  if (bind_ports->len) {
    net_handled |= LANDLOCK_ACCESS_NET_BIND_TCP;
  }
  if (connect_ports->len) {
    net_handled |= LANDLOCK_ACCESS_NET_CONNECT_TCP;
  }

  if (!fs_handled && !net_handled && !scoped) {
    die_msg("empty Landlock policy: provide filesystem paths, TCP ports, or scopes");
  }

  struct rb_landlock_ruleset_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.handled_access_fs = fs_handled;
  attr.handled_access_net = net_handled;
  attr.scoped = scoped;

  size_t attr_size =
      scoped ? sizeof(struct rb_landlock_ruleset_attr)
             : (net_handled ? offsetof(struct rb_landlock_ruleset_attr, scoped)
                            : offsetof(struct rb_landlock_ruleset_attr, handled_access_net));
  int fd = (int)ll_create_ruleset(&attr, attr_size, 0);
  if (fd < 0) {
    die("landlock_create_ruleset");
  }

  for (size_t i = 0; i < read_paths->len; i++) {
    add_path_rule(fd, read_paths->items[i], read_rights());
  }
  for (size_t i = 0; i < execute_paths->len; i++) {
    add_path_rule(fd, execute_paths->items[i], execute_rights());
  }
  for (size_t i = 0; i < write_paths->len; i++) {
    add_path_rule(fd, write_paths->items[i], write_rights(abi));
  }
  for (size_t i = 0; i < path_rules->len; i++) {
    uint64_t rights = effective_path_rights(path_rules->items[i].path,
                                            path_rules->items[i].rights & known_fs_rights);
    if (!rights) {
      die_no_effective_path_rights(path_rules->items[i].path);
    }
    add_path_rule(fd, path_rules->items[i].path, rights);
  }
  for (size_t i = 0; i < connect_ports->len; i++) {
    add_net_rule(fd, connect_ports->items[i], LANDLOCK_ACCESS_NET_CONNECT_TCP);
  }
  for (size_t i = 0; i < bind_ports->len; i++) {
    add_net_rule(fd, bind_ports->items[i], LANDLOCK_ACCESS_NET_BIND_TCP);
  }

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    die("prctl(PR_SET_NO_NEW_PRIVS)");
  }
  if (ll_restrict_self(fd, 0) < 0) {
    die("landlock_restrict_self");
  }
  close(fd);
}

static void apply_rlimit(const char *spec) {
  char *copy = strdup(spec);
  if (!copy) {
    die("strdup");
  }
  char *eq = strchr(copy, '=');
  if (!eq) {
    die_msg("rlimit must be name=value");
  }
  *eq = '\0';
  unsigned long long value = parse_ull(eq + 1, "rlimit value must be a non-negative integer");
  int resource = -1;

  if (strcmp(copy, "cpu_seconds") == 0) {
    resource = RLIMIT_CPU;
  }
#ifdef RLIMIT_AS
  else if (strcmp(copy, "memory_bytes") == 0) {
    resource = RLIMIT_AS;
  }
#endif
  else if (strcmp(copy, "file_size_bytes") == 0) {
    resource = RLIMIT_FSIZE;
  } else if (strcmp(copy, "open_files") == 0) {
    resource = RLIMIT_NOFILE;
  }
#ifdef RLIMIT_NPROC
  else if (strcmp(copy, "processes") == 0) {
    resource = RLIMIT_NPROC;
  }
#endif
  else {
    die_msg("unknown rlimit");
  }

  struct rlimit limit;
  rlim_t rlim_value = (rlim_t)value;
  if ((unsigned long long)rlim_value != value) {
    die_msg("rlimit value is too large for this platform");
  }
  limit.rlim_cur = rlim_value;
  limit.rlim_max = rlim_value;
  if (setrlimit(resource, &limit) != 0) {
    die("setrlimit");
  }
  free(copy);
}

static void apply_seccomp_deny_network(void) {
  const char *error_message = "seccomp(SECCOMP_SET_MODE_FILTER)";
  if (rb_landlock_seccomp_deny_network(&error_message) != 0) {
    die(error_message);
  }
}

static uint64_t fs_right_name(const char *name) {
  if (strcmp(name, "execute") == 0) {
    return LANDLOCK_ACCESS_FS_EXECUTE;
  }
  if (strcmp(name, "write_file") == 0) {
    return LANDLOCK_ACCESS_FS_WRITE_FILE;
  }
  if (strcmp(name, "read_file") == 0) {
    return LANDLOCK_ACCESS_FS_READ_FILE;
  }
  if (strcmp(name, "read_dir") == 0) {
    return LANDLOCK_ACCESS_FS_READ_DIR;
  }
  if (strcmp(name, "remove_dir") == 0) {
    return LANDLOCK_ACCESS_FS_REMOVE_DIR;
  }
  if (strcmp(name, "remove_file") == 0) {
    return LANDLOCK_ACCESS_FS_REMOVE_FILE;
  }
  if (strcmp(name, "make_char") == 0) {
    return LANDLOCK_ACCESS_FS_MAKE_CHAR;
  }
  if (strcmp(name, "make_dir") == 0) {
    return LANDLOCK_ACCESS_FS_MAKE_DIR;
  }
  if (strcmp(name, "make_reg") == 0) {
    return LANDLOCK_ACCESS_FS_MAKE_REG;
  }
  if (strcmp(name, "make_sock") == 0) {
    return LANDLOCK_ACCESS_FS_MAKE_SOCK;
  }
  if (strcmp(name, "make_fifo") == 0) {
    return LANDLOCK_ACCESS_FS_MAKE_FIFO;
  }
  if (strcmp(name, "make_block") == 0) {
    return LANDLOCK_ACCESS_FS_MAKE_BLOCK;
  }
  if (strcmp(name, "make_sym") == 0) {
    return LANDLOCK_ACCESS_FS_MAKE_SYM;
  }
  if (strcmp(name, "refer") == 0) {
    return LANDLOCK_ACCESS_FS_REFER;
  }
  if (strcmp(name, "truncate") == 0) {
    return LANDLOCK_ACCESS_FS_TRUNCATE;
  }
  if (strcmp(name, "ioctl_dev") == 0) {
    return LANDLOCK_ACCESS_FS_IOCTL_DEV;
  }
  die_msg("unknown filesystem right");
  return 0;
}

static uint64_t parse_fs_rights(const char *spec) {
  char *copy = strdup(spec);
  if (!copy) {
    die("strdup");
  }

  uint64_t rights = 0;
  size_t count = 0;
  char *saveptr = NULL;
  for (char *name = strtok_r(copy, ",", &saveptr); name; name = strtok_r(NULL, ",", &saveptr)) {
    if (name[0] == '\0') {
      free(copy);
      die_msg("empty filesystem right");
    }
    rights |= fs_right_name(name);
    count++;
    if (count > MAX_CSV_RIGHTS) {
      free(copy);
      die_msg("too many filesystem rights");
    }
  }

  free(copy);
  if (!count) {
    die_msg("path rights must not be empty");
  }
  return rights;
}

static uint64_t scope_name(const char *name) {
  if (strcmp(name, "abstract_unix_socket") == 0) {
    return LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET;
  }
  if (strcmp(name, "signal") == 0) {
    return LANDLOCK_SCOPE_SIGNAL;
  }
  die_msg("unknown Landlock scope");
  return 0;
}

static char *require_arg(int argc, char **argv, int *i) {
  if (*i + 1 >= argc) {
    die_msg("missing option argument");
  }
  (*i)++;
  return argv[*i];
}

static void close_inherited_fds(void) {
#ifdef SYS_close_range
  if (syscall(SYS_close_range, 3U, ~0U, 0U) == 0) {
    return;
  }
#endif

  DIR *dir = opendir("/proc/self/fd");
  if (dir) {
    int dir_fd = dirfd(dir);
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
      char *end = NULL;
      errno = 0;
      long fd = strtol(entry->d_name, &end, 10);
      if (errno == 0 && end && *end == '\0' && fd >= 3 && fd != dir_fd) {
        close((int)fd);
      }
    }
    closedir(dir);
    return;
  }

  long max_fd = sysconf(_SC_OPEN_MAX);
  if (max_fd < 0) {
    max_fd = 1024;
  }
  for (long fd = 3; fd < max_fd; fd++) {
    close((int)fd);
  }
}

int main(int argc, char **argv) {
  string_list read_paths = {0}, write_paths = {0}, execute_paths = {0}, rlimit_specs = {0};
  path_rule_list path_rules = {0};
  ull_list connect_ports = {0}, bind_ports = {0};
  int seccomp_deny_network = 0, allow_all_known = 0, close_others = 1;
  uint64_t scoped = 0;
  char *chdir_path = NULL;
  char **command_argv = NULL;
  int command_index = -1;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--") == 0) {
      command_index = i + 1;
      break;
    }
    if (strcmp(argv[i], "--read") == 0) {
      string_list_push(&read_paths, require_arg(argc, argv, &i));
    } else if (strcmp(argv[i], "--write") == 0) {
      string_list_push(&write_paths, require_arg(argc, argv, &i));
    } else if (strcmp(argv[i], "--execute") == 0) {
      string_list_push(&execute_paths, require_arg(argc, argv, &i));
    } else if (strcmp(argv[i], "--path") == 0) {
      char *path = require_arg(argc, argv, &i);
      char *rights = require_arg(argc, argv, &i);
      path_rule_list_push(&path_rules, path, parse_fs_rights(rights));
    } else if (strcmp(argv[i], "--connect-tcp") == 0) {
      ull_list_push(&connect_ports, parse_port(require_arg(argc, argv, &i)));
    } else if (strcmp(argv[i], "--bind-tcp") == 0) {
      ull_list_push(&bind_ports, parse_port(require_arg(argc, argv, &i)));
    } else if (strcmp(argv[i], "--scope") == 0) {
      scoped |= scope_name(require_arg(argc, argv, &i));
    } else if (strcmp(argv[i], "--chdir") == 0) {
      chdir_path = require_arg(argc, argv, &i);
    } else if (strcmp(argv[i], "--rlimit") == 0) {
      string_list_push(&rlimit_specs, require_arg(argc, argv, &i));
    } else if (strcmp(argv[i], "--seccomp-deny-network") == 0) {
      seccomp_deny_network = 1;
    } else if (strcmp(argv[i], "--allow-all-known") == 0) {
      allow_all_known = 1;
    } else if (strcmp(argv[i], "--keep-fds") == 0) {
      close_others = 0;
    } else {
      die_msg("unknown option");
    }
  }

  if (command_index < 0 || command_index >= argc) {
    die_msg("missing command after --");
  }
  command_argv = &argv[command_index];

  if (close_others) {
    close_inherited_fds();
  }

  if (chdir_path && chdir(chdir_path) != 0) {
    die("chdir");
  }

  apply_landlock(&read_paths, &write_paths, &execute_paths, &path_rules, &connect_ports,
                 &bind_ports, scoped, allow_all_known);
  if (seccomp_deny_network) {
    apply_seccomp_deny_network();
  }
  for (size_t i = 0; i < rlimit_specs.len; i++) {
    apply_rlimit(rlimit_specs.items[i]);
  }

  execvp(command_argv[0], command_argv);
  perror("execvp");
  _exit(127);
}
