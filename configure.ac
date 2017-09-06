# Initialization
AC_PREREQ([2.69])
AC_INIT([phosphor-user-manager], [1.0], [https://github.com/openbmc/phosphor-user-manager/issues])
AC_LANG([C++])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([subdir-objects -Wall -Werror foreign dist-xz])
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for libraries.
PKG_CHECK_MODULES([SDBUSPLUS], [sdbusplus],, [AC_MSG_ERROR([Could not find sdbusplus...openbmc/sdbusplus package required])])
PKG_CHECK_MODULES([PHOSPHOR_DBUS_INTERFACES], [phosphor-dbus-interfaces],, [AC_MSG_ERROR([Could not find phosphor-dbus-interfaces...openbmc/phosphor-dbus-interfaces package required])])

AC_ARG_VAR(USER_MANAGER_BUSNAME, [The Dbus busname to own])
AS_IF([test "x$USER_MANAGER_BUSNAME" == "x"], [USER_MANAGER_BUSNAME="xyz.openbmc_project.User.Manager"])
AC_DEFINE_UNQUOTED([USER_MANAGER_BUSNAME], ["$USER_MANAGER_BUSNAME"], [The DBus busname to own])

AC_ARG_VAR(SHADOW_FILE, [Shadow password file])
AS_IF([test "x$SHADOW_FILE" == "x"], [SHADOW_FILE="/etc/shadow"])
AC_DEFINE_UNQUOTED([SHADOW_FILE], ["$SHADOW_FILE"], [Shadow password file])

# Checks for typedefs, structures, and compiler characteristics.
AX_CXX_COMPILE_STDCXX_14([noext])
AX_APPEND_COMPILE_FLAGS([-Wall -Werror], [CXXFLAGS])

# For libtools
LT_INIT

# Create configured output
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
