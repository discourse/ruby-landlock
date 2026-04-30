# frozen_string_literal: true

require "mkmf"

abort "missing ruby headers" unless have_header("ruby.h")

have_header("linux/landlock.h")
have_header("linux/seccomp.h")
have_header("linux/filter.h")
have_header("sys/prctl.h")
have_header("sys/syscall.h")
have_header("sys/resource.h")
have_header("fcntl.h")

create_makefile("landlock/landlock")

if RUBY_PLATFORM.include?("linux")
  helper = "landlock-safe-exec"
  helper_src = "$(srcdir)/bin/safe_exec_helper.c"
  helper_dest = "$(RUBYARCHDIR)/#{helper}"

  File.open("Makefile", "a") do |makefile|
    makefile.puts <<~MAKE

      all: #{helper}

      #{helper}: #{helper_src}
      \t$(CC) $(INCFLAGS) $(CPPFLAGS) $(CFLAGS) #{helper_src} -o #{helper} $(LIBS)

      install: install-#{helper}

      install-#{helper}: #{helper}
      \t$(MAKEDIRS) $(RUBYARCHDIR)
      \t$(INSTALL_PROG) #{helper} #{helper_dest}

      clean-local::
      \t$(Q)$(RM) #{helper}

      clean: clean-local
    MAKE
  end
end
