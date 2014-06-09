#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([gryphon], [0.4.0], [wangbin579@gmail.com], [gryphon])
AC_CONFIG_HEADER([src/core/config.h])
AM_INIT_AUTOMAKE


# Checks for programs.
AC_PROG_LN_S
AC_PROG_MAKE_SET

# Checks for libraries.

AC_PROG_LIBTOOL
AM_PROG_LIBTOOL

case "$host" in
*-*-linux*) ;;
*) AC_MSG_ERROR([Linux only!]);;
esac

AC_CHECK_HEADERS([pcap.h], [], 
                 [AC_MSG_ERROR([pcap.h not found.])], [])

AC_ARG_ENABLE(debug, AS_HELP_STRING([--enable-debug],[compile gryphon with debug support(saved in a log file)]),,debug=no)
if test "x$enable_debug" = "xyes";then
	AC_DEFINE(GRYPHON_DEBUG, 1, [Define if --enable-debug])
fi

AC_ARG_ENABLE(single, AS_HELP_STRING([--enable-single],[run gryphon at non-distributed mode]),,single=no)
if test "x$enable_single" = "xyes";then
    AC_DEFINE(GRYPHON_SINGLE, 1, [Define if --enable-single])
fi

AC_ARG_ENABLE(comet, AS_HELP_STRING([--enable-comet],[run gryphon at comet mode]),,comet=no)
if test "x$enable_comet" = "xyes";then
    AC_DEFINE(GRYPHON_COMET, 1, [Define if --enable-comet])
fi

AC_ARG_ENABLE(advanced, AS_HELP_STRING([--enable-advanced],[run gryphon at advanced mode]),,advanced=no)
if test "x$enable_advanced" = "xyes";then
    AC_DEFINE(GRYPHON_ADVANCED, 1, [Define if --enable-advanced])
fi

AC_ARG_ENABLE(dlinject, AS_HELP_STRING([--enable-dlinject],[run gryphon at pcap sending mode]),,dlinject=no)
if test "x$enable_dlinject" = "xyes";then
    AC_DEFINE(GRYPHON_PCAP_SEND, 1, [Define if --enable-dlinject])
fi


# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netinet/in.h stdint.h stdlib.h string.h sys/file.h sys/param.h sys/socket.h sys/time.h unistd.h getopt.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_C_VOLATILE
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([atexit gettimeofday inet_ntoa memset select socket localtime_r])

LIBS="-lpcap"


CFLAGS="-g -D_FILE_OFFSET_BITS=64 -Wall -Wunused-function -pedantic -I../communication -I../core -I../event -I../gryphon -I../util"


#AC_CONFIG_FILES([Makefile])
AC_OUTPUT([
Makefile
src/Makefile
src/core/Makefile
src/util/Makefile
src/communication/Makefile
src/gryphon/Makefile
src/event/Makefile
])

