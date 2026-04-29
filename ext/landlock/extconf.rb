require "mkmf"

abort "missing ruby headers" unless have_header("ruby.h")

have_header("linux/landlock.h")
have_header("sys/prctl.h")
have_header("sys/syscall.h")
have_header("fcntl.h")

create_makefile("landlock/landlock")
