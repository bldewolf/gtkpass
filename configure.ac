AC_PREREQ([2.65])
AC_INIT([gtkpass], [1], [gtkpass@bldewolf.com])
AC_CONFIG_SRCDIR([src/gtkpass.c])
AC_CONFIG_HEADERS([config.h])

AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([-Wall -Werror])

# Checks for programs.
AC_PROG_CC()
AM_PROG_CC_C_O()
AC_PROG_INSTALL()
AC_PROG_LIBTOOL()

# Checks for libraries.
AM_PATH_GTK_2_0([2.10.0],,AC_MSG_ERROR([Gtk+ 2.10.0 or higher required.]))
AC_CHECK_LIB([kpass], [kpass_init_db], [], [AC_MSG_ERROR([Libkpass required.]); exit 1])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h termios.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([memset munmap])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
