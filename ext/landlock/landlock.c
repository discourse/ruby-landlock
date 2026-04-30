#include "ruby.h"
#include "landlock_native.h"

#include <string.h>

static VALUE mLandlock;
static VALUE eLandlockError;
static VALUE eSyscallError;

static void raise_syscall_error(const char *syscall_name) {
  int saved_errno = errno;
  VALUE err = rb_funcall(eSyscallError, rb_intern("new"), 3,
                         rb_str_new_cstr(syscall_name),
                         INT2NUM(saved_errno),
                         rb_sprintf("%s failed: %s", syscall_name, strerror(saved_errno)));
  rb_exc_raise(err);
}

static VALUE rb_ll_abi_version(VALUE self) {
  long abi = ll_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
  if (abi < 0) {
    if (errno == ENOSYS || errno == EOPNOTSUPP) return INT2FIX(0);
    raise_syscall_error("landlock_create_ruleset");
  }
  return LONG2NUM(abi);
}

static VALUE rb_ll_create_ruleset(int argc, VALUE *argv, VALUE self) {
  VALUE fs_bits, net_bits, scoped_bits;
  rb_scan_args(argc, argv, "21", &fs_bits, &net_bits, &scoped_bits);

  struct rb_landlock_ruleset_attr attr;
  uint64_t handled_access_net = NUM2ULL(net_bits);
  uint64_t scoped = NIL_P(scoped_bits) ? 0 : NUM2ULL(scoped_bits);
  size_t attr_size = offsetof(struct rb_landlock_ruleset_attr, handled_access_net);
  if (scoped != 0) {
    attr_size = sizeof(struct rb_landlock_ruleset_attr);
  } else if (handled_access_net != 0) {
    attr_size = offsetof(struct rb_landlock_ruleset_attr, scoped);
  }

  memset(&attr, 0, sizeof(attr));
  attr.handled_access_fs = NUM2ULL(fs_bits);
  attr.handled_access_net = handled_access_net;
  attr.scoped = scoped;

  long fd = ll_create_ruleset(&attr, attr_size, 0);
  if (fd < 0) raise_syscall_error("landlock_create_ruleset");
  return INT2NUM(fd);
}

static VALUE rb_ll_add_path_rule(VALUE self, VALUE ruleset_fd, VALUE path, VALUE access_bits) {
  int ruleset = NUM2INT(ruleset_fd);
  uint64_t allowed_access = NUM2ULL(access_bits);
  Check_Type(path, T_STRING);
  const char *cpath = StringValueCStr(path);
  int parent_fd = open(cpath, O_PATH | O_CLOEXEC);
  if (parent_fd < 0) raise_syscall_error("open");

  struct rb_landlock_path_beneath_attr rule;
  memset(&rule, 0, sizeof(rule));
  rule.allowed_access = allowed_access;
  rule.parent_fd = parent_fd;

  long ret = ll_add_rule(ruleset, LANDLOCK_RULE_PATH_BENEATH, &rule, 0);
  int saved_errno = errno;
  close(parent_fd);
  if (ret < 0) {
    errno = saved_errno;
    raise_syscall_error("landlock_add_rule(path_beneath)");
  }
  return Qtrue;
}

static VALUE rb_ll_add_net_rule(VALUE self, VALUE ruleset_fd, VALUE port, VALUE access_bits) {
  unsigned long long p = NUM2ULL(port);
  if (p > 65535ULL) rb_raise(rb_eArgError, "TCP port must be between 0 and 65535");

  struct rb_landlock_net_port_attr rule;
  memset(&rule, 0, sizeof(rule));
  rule.allowed_access = NUM2ULL(access_bits);
  rule.port = p;

  long ret = ll_add_rule(NUM2INT(ruleset_fd), LANDLOCK_RULE_NET_PORT, &rule, 0);
  if (ret < 0) raise_syscall_error("landlock_add_rule(net_port)");
  return Qtrue;
}

static VALUE rb_ll_restrict_self(VALUE self, VALUE ruleset_fd) {
#ifdef __linux__
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    raise_syscall_error("prctl(PR_SET_NO_NEW_PRIVS)");
  }

  long ret = ll_restrict_self(NUM2INT(ruleset_fd), 0);
  if (ret < 0) raise_syscall_error("landlock_restrict_self");
  return Qtrue;
#else
  errno = ENOSYS;
  raise_syscall_error("landlock_restrict_self");
#endif
}

static VALUE rb_ll_close_fd(VALUE self, VALUE fd_value) {
  int fd = NUM2INT(fd_value);
  if (fd >= 0) close(fd);
  return Qnil;
}

void Init_landlock(void) {
  mLandlock = rb_define_module("Landlock");

  if (rb_const_defined(mLandlock, rb_intern("Error"))) {
    eLandlockError = rb_const_get(mLandlock, rb_intern("Error"));
  } else {
    eLandlockError = rb_define_class_under(mLandlock, "Error", rb_eStandardError);
  }

  if (rb_const_defined(mLandlock, rb_intern("SyscallError"))) {
    eSyscallError = rb_const_get(mLandlock, rb_intern("SyscallError"));
  } else {
    eSyscallError = rb_define_class_under(mLandlock, "SyscallError", eLandlockError);
  }

  rb_define_singleton_method(mLandlock, "abi_version", rb_ll_abi_version, 0);
  rb_define_singleton_method(mLandlock, "_create_ruleset", rb_ll_create_ruleset, -1);
  rb_define_singleton_method(mLandlock, "_add_path_rule", rb_ll_add_path_rule, 3);
  rb_define_singleton_method(mLandlock, "_add_net_rule", rb_ll_add_net_rule, 3);
  rb_define_singleton_method(mLandlock, "_restrict_self", rb_ll_restrict_self, 1);
  rb_define_singleton_method(mLandlock, "_close_fd", rb_ll_close_fd, 1);

  rb_define_const(mLandlock, "ACCESS_FS_EXECUTE", ULL2NUM(LANDLOCK_ACCESS_FS_EXECUTE));
  rb_define_const(mLandlock, "ACCESS_FS_WRITE_FILE", ULL2NUM(LANDLOCK_ACCESS_FS_WRITE_FILE));
  rb_define_const(mLandlock, "ACCESS_FS_READ_FILE", ULL2NUM(LANDLOCK_ACCESS_FS_READ_FILE));
  rb_define_const(mLandlock, "ACCESS_FS_READ_DIR", ULL2NUM(LANDLOCK_ACCESS_FS_READ_DIR));
  rb_define_const(mLandlock, "ACCESS_FS_REMOVE_DIR", ULL2NUM(LANDLOCK_ACCESS_FS_REMOVE_DIR));
  rb_define_const(mLandlock, "ACCESS_FS_REMOVE_FILE", ULL2NUM(LANDLOCK_ACCESS_FS_REMOVE_FILE));
  rb_define_const(mLandlock, "ACCESS_FS_MAKE_CHAR", ULL2NUM(LANDLOCK_ACCESS_FS_MAKE_CHAR));
  rb_define_const(mLandlock, "ACCESS_FS_MAKE_DIR", ULL2NUM(LANDLOCK_ACCESS_FS_MAKE_DIR));
  rb_define_const(mLandlock, "ACCESS_FS_MAKE_REG", ULL2NUM(LANDLOCK_ACCESS_FS_MAKE_REG));
  rb_define_const(mLandlock, "ACCESS_FS_MAKE_SOCK", ULL2NUM(LANDLOCK_ACCESS_FS_MAKE_SOCK));
  rb_define_const(mLandlock, "ACCESS_FS_MAKE_FIFO", ULL2NUM(LANDLOCK_ACCESS_FS_MAKE_FIFO));
  rb_define_const(mLandlock, "ACCESS_FS_MAKE_BLOCK", ULL2NUM(LANDLOCK_ACCESS_FS_MAKE_BLOCK));
  rb_define_const(mLandlock, "ACCESS_FS_MAKE_SYM", ULL2NUM(LANDLOCK_ACCESS_FS_MAKE_SYM));
  rb_define_const(mLandlock, "ACCESS_FS_REFER", ULL2NUM(LANDLOCK_ACCESS_FS_REFER));
  rb_define_const(mLandlock, "ACCESS_FS_TRUNCATE", ULL2NUM(LANDLOCK_ACCESS_FS_TRUNCATE));
  rb_define_const(mLandlock, "ACCESS_FS_IOCTL_DEV", ULL2NUM(LANDLOCK_ACCESS_FS_IOCTL_DEV));
  rb_define_const(mLandlock, "ACCESS_NET_BIND_TCP", ULL2NUM(LANDLOCK_ACCESS_NET_BIND_TCP));
  rb_define_const(mLandlock, "ACCESS_NET_CONNECT_TCP", ULL2NUM(LANDLOCK_ACCESS_NET_CONNECT_TCP));
  rb_define_const(mLandlock, "SCOPE_ABSTRACT_UNIX_SOCKET", ULL2NUM(LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET));
  rb_define_const(mLandlock, "SCOPE_SIGNAL", ULL2NUM(LANDLOCK_SCOPE_SIGNAL));
}
