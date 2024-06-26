AC_INIT([0.0], [chxhttp])
: ${CXXFLAGS=""}
AM_INIT_AUTOMAKE([-Werror -Wall foreign subdir-objects])

AC_SUBST(CHXHTTP_CXXFLAGS, ["-O3 -g -std=c++20"])
AC_SUBST(CHXHTTP_LDADD, ["-lnghttp2"])
AC_SUBST(CHXHTTP_LDFLAGS)
AC_SUBST(__CHXHTTP_START_STATIC)
AC_SUBST(__CHXHTTP_END_STATIC)

AC_MSG_CHECKING([whether to link against libraries staticlly])
AC_ARG_ENABLE([static], [
    AS_HELP_STRING([--enable-static],
        [link against libraries statically (default is no)])], [
    AS_IF([test "x$enableval" = xyes], [
        AC_MSG_RESULT([yes])
        __CHXHTTP_START_STATIC="-Wl,-Bstatic"
        __CHXHTTP_END_STATIC="-Wl,-Bdynamic"
    ], [
        AC_MSG_RESULT([no])
    ])
], [
    AC_MSG_RESULT([no])
])

PKG_CHECK_MODULES([liburing], [liburing], [
    CHXHTTP_CXXFLAGS="$CHXHTTP_CXXFLAGS $liburing_CFLAGS"
    CHXHTTP_LDADD="$CHXHTTP_LDADD \
        $__CHXHTTP_START_STATIC $liburing_LIBS $__CHXHTTP_END_STATIC"
], [
    AC_MSG_ERROR(["liburing not found"])
])
PKG_CHECK_MODULES([llhttp], [libllhttp], [
    CHXHTTP_CXXFLAGS="$CHXHTTP_CXXFLAGS $llhttp_CFLAGS"
    CHXHTTP_LDADD="$CHXHTTP_LDADD \
        $__CHXHTTP_START_STATIC $llhttp_LIBS $__CHXHTTP_END_STATIC"
], [
    AC_MSG_ERROR(["llhttp not found"])
])
PKG_CHECK_MODULES([nghttp2], [libnghttp2], [
    CHXHTTP_CXXFLAGS="$CHXHTTP_CXXFLAGS $nghttp2_CFLAGS"
    CHXHTTP_LDADD="$CHXHTTP_LDADD \
        $__CHXHTTP_START_STATIC $nghttp2_LIBS $__CHXHTTP_END_STATIC"
], [
    AC_MSG_ERROR(["nghttp2 not found"])
])
PKG_CHECK_MODULES([openssl], [openssl], [
    CHXHTTP_CXXFLAGS="$CHXHTTP_CXXFLAGS $openssl_CFLAGS"
    CHXHTTP_LDADD="$CHXHTTP_LDADD $openssl_LIBS"
], [
    AC_MSG_ERROR(["openssl not found"])
])

AX_BOOST_BASE([1.75.0], [
    AX_BOOST_JSON
    AX_BOOST_PROGRAM_OPTIONS
    CHXHTTP_CXXFLAGS="$CHXHTTP_CXXFLAGS $BOOST_CXXFLAGS"
    CHXHTTP_LDFLAGS="$CHXHTTP_LDFLAGS $BOOST_LDFLAGS"
    CHXHTTP_LDADD="$CHXHTTP_LDADD $__CHXHTTP_START_STATIC \
        $BOOST_JSON_LIB $BOOST_PROGRAM_OPTIONS_LIB \
        $__CHXHTTP_END_STATIC"
], [
    AC_MSG_ERROR([boost not found])
])

AC_PROG_CXX
AC_CONFIG_FILES([
    Makefile
    include/Makefile
    src/Makefile
])
AC_OUTPUT
