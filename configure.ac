AC_PREREQ([2.5])
AC_INIT([OpenDataPlane], m4_esyscmd(./scripts/git_hash.sh .), [lng-odp@lists.linaro.org])
AM_INIT_AUTOMAKE([1.9 tar-pax subdir-objects])
AC_CONFIG_SRCDIR([helper/config.h.in])
AM_CONFIG_HEADER([helper/config.h])

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])

##########################################################################
# Set correct platform library version
##########################################################################
ODP_LIBSO_VERSION=111:0:0
AC_SUBST(ODP_LIBSO_VERSION)

ODPHELPER_LIBSO_VERSION=110:0:1
AC_SUBST(ODPHELPER_LIBSO_VERSION)

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

AC_PROG_CXX

AC_PROG_INSTALL
AC_PROG_MAKE_SET

AM_PROG_AR
#Use libtool
LT_INIT([])
AC_SUBST([LIBTOOL_DEPS])
AM_PROG_LIBTOOL

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([bzero clock_gettime gethostbyname getpagesize gettimeofday memset munmap socket strchr strerror strrchr strstr strtoull])

# Checks for header files.
AC_HEADER_RESOLV
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_INT32_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

#########################################################################
# Get GCC version
#########################################################################

AX_COMPILER_VERSION
CC_VERSION=$ax_cv_c_compiler_version

CC_VERSION_MAJOR=$(echo $CC_VERSION | cut -d'.' -f1)
CC_VERSION_MINOR=$(echo $CC_VERSION | cut -d'.' -f2)
CC_VERSION_PATCH=$(echo $CC_VERSION | cut -d'.' -f3)

##########################################################################
# Allow valgrind suite to run against the defined tests
##########################################################################
AX_VALGRIND_CHECK

##########################################################################
# Which architecture optimizations will we use
##########################################################################
AS_CASE([$host],
  [x86*], [ARCH_DIR=x86],
  [i686*], [ARCH_DIR=x86],
  [mips64*], [ARCH_DIR=mips64],
  [powerpc*], [ARCH_DIR=powerpc],
  [aarch64*], [ARCH_DIR=arm],
  [arm*], [ARCH_DIR=arm],
  [ARCH_DIR=undefined]
)
AC_SUBST([ARCH_DIR])

##########################################################################
# Warn on the defaults if arch is undefined
##########################################################################
if test "${ARCH_DIR}" == "undefined";
then
    echo "ARCH_DIR is undefined, please add your ARCH_DIR based on host=${host}"
    exit 1
fi

##########################################################################
# Set correct pkgconfig version
##########################################################################
PKGCONFIG_VERSION=$(echo $VERSION | awk -F '.git' '{print $1}')
AC_SUBST(PKGCONFIG_VERSION)

##########################################################################
# Determine which platform to build for
##########################################################################
AC_ARG_WITH([platform],
    [AS_HELP_STRING([--with-platform=platform],
        [select platform to be used (linux-dpaa1|linux-dpaa2)])]
    )

AC_SUBST([with_platform])
AC_SUBST([platform_with_platform], ["platform/${with_platform}"])
AC_SUBST([platform_with_platform_test], ["platform/${with_platform}/test"])
AM_CONDITIONAL([BUILD_DPAA2], [test x${with_platform} = x"linux-dpaa2" ])
AM_CONDITIONAL([BUILD_DPAA1], [test x${with_platform} = x"linux-dpaa1" ])

if test "${with_platform}" == "linux-dpaa1";
then
AC_SUBST([platform_with_platform_test], [""])
fi
#########################################################################
# Flag to allow option for SSL usage. Currently this flag is not supported.
#########################################################################
AM_CONDITIONAL([USE_OPEN_SSL], [test "x${SSL_ENABLED}" = "x1"])
##########################################################################
# Run platform specific checks and settings
##########################################################################
IMPLEMENTATION_NAME="odp-linux"
if test "${with_platform}" == "linux-generic";
then
    m4_include([./platform/linux-generic/m4/configure.m4])
    m4_include([./test/platform/linux-generic/m4/configure.m4])
    IMPLEMENTATION_NAME="odp-linux"
elif test "${with_platform}" == "linux-dpaa2";
then
    m4_include([./platform/linux-dpaa2/m4/configure.m4])
elif test "${with_platform}" == "linux-dpaa1";
then
    m4_include([./platform/linux-dpaa1/m4/configure.m4])
else
    echo "UNSUPPORTED PLATFORM: ${with_platform}"
    exit 1
fi

ODP_CFLAGS="$ODP_CFLAGS -DIMPLEMENTATION_NAME=$IMPLEMENTATION_NAME"

##########################################################################
# Include m4 files
##########################################################################
m4_include([./doc/m4/configure.m4])
m4_include([./example/m4/configure.m4])
m4_include([./helper/m4/configure.m4])
m4_include([./test/m4/configure.m4])

##########################################################################
# Set SDK install path
##########################################################################
AC_ARG_WITH([sdk-install-path],
AC_HELP_STRING([--with-sdk-install-path=DIR path to external libs and headers],
	     [(or in the default path if not specified).]),
[SDK_INSTALL_PATH=$withval SDK_INSTALL_PATH_=1],[SDK_INSTALL_PATH_=])

AC_SUBST(SDK_INSTALL_PATH)

##########################################################################
# Set the install directory for test binaries/scripts
##########################################################################
AC_ARG_WITH([testdir],
    AC_HELP_STRING([--with-testdir=DIR installation directory for tests]),
	[if test "$withval" = "yes"; then
	     testdir=$libdir/odp/tests
	 else
	     testdir=$withval
	 fi], [])
AC_SUBST([testdir])

##########################################################################
# Set conditionals as computed within platform specific files
##########################################################################
AM_CONDITIONAL([netmap_support], [test x$netmap_support = xyes ])
AM_CONDITIONAL([PKTIO_IPC], [test x$pktio_ipc_support = xyes])
AM_CONDITIONAL([PKTIO_DPDK], [test x$pktio_dpdk_support = xyes ])
AM_CONDITIONAL([HAVE_PCAP], [test $have_pcap = yes])
AM_CONDITIONAL([SDK_INSTALL_PATH_], [test "x${SDK_INSTALL_PATH_}" = "x1"])
AM_CONDITIONAL([test_installdir], [test "$testdir" != ""])
AM_CONDITIONAL([cunit_support], [test x$cunit_support = xyes ])
AM_CONDITIONAL([test_vald], [test x$test_vald = xyes ])
AM_CONDITIONAL([test_perf], [test x$test_perf = xyes ])
AM_CONDITIONAL([test_cpp], [test x$test_cpp = xyes ])
AM_CONDITIONAL([test_helper], [test x$test_helper = xyes ])
AM_CONDITIONAL([test_example], [test x$test_example = xyes ])
AM_CONDITIONAL([HAVE_DOXYGEN], [test "x${DOXYGEN}" = "xdoxygen"])
AM_CONDITIONAL([user_guide], [test "x${user_guides}" = "xyes" ])
AM_CONDITIONAL([HAVE_MSCGEN], [test "x${MSCGEN}" = "xmscgen"])

##########################################################################
# Setup doxygen documentation
##########################################################################
DX_HTML_FEATURE(ON)
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)
DX_INIT_DOXYGEN($PACKAGE_NAME,
		${srcdir}/doc/application-api-guide/Doxyfile,
		${builddir}/doc/application-api-guide/output,
		${srcdir}/doc/helper-guide/Doxyfile,
		${builddir}/doc/helper-guide/output,
		${srcdir}/doc/platform-api-guide/Doxyfile,
		${builddir}/doc/platform-api-guide/output)

##########################################################################
# Enable/disable ODP_DEBUG_PRINT
##########################################################################
ODP_DEBUG_PRINT=0
AC_ARG_ENABLE([debug-print],
    [  --enable-debug-print    display debugging information],
    [if test "x$enableval" = "xyes"; then
	ODP_DEBUG_PRINT=1
	ODP_CFLAGS="$ODP_CFLAGS -DODP_IPSEC_DEBUG"
    fi])
ODP_CFLAGS="$ODP_CFLAGS -DODP_DEBUG_PRINT=$ODP_DEBUG_PRINT"

######################################################################
AC_ARG_ENABLE([ipsec-debug],
    [  --enable-ipsec-debug    include additional IPSec debug code],
    [if test "x$enableval" = "xyes"; then
       ODP_CFLAGS="$ODP_CFLAGS -DODP_IPSEC_DEBUG"
    fi])
######################################################################

##########################################################################
# Enable/disable ODP_DEBUG
##########################################################################
ODP_DEBUG=0
AC_ARG_ENABLE([debug],
    [  --enable-debug          include additional code],
    [if test "x$enableval" = "xyes"; then
	ODP_DEBUG=1
     else
	ODP_DEBUG=0
    fi])
ODP_CFLAGS="$ODP_CFLAGS -DODP_DEBUG=$ODP_DEBUG -DDPAA2_LOGLIB_DISABLE -DQODP_344"

##########################################################################
# Check for Build type (for platforms - DPAA1, DPAA2)
##########################################################################
if test "${with_platform}" == "linux-dpaa2";
then
AC_ARG_ENABLE([build_type],
[  --build-type    Specify build type as LS2080/LS2085/LS2088],
[case "${enableval}" in
  ls2080) build_type=LS2080 ;;
  ls2085) build_type=LS2085 ;;
  ls2088) build_type=LS2088 ;;
  ls1088) build_type=LS1088 ;;
  lx2160) build_type=LX2160 ;;
  *)  build_type=LS2085;;
esac],[build_type=LS2085])
fi
if test "${with_platform}" == "linux-dpaa1";
then
AC_ARG_ENABLE([build_type],
[  --build-type    Specify build type as LS1046, LS1043, P4080, T1040, T4240, T2080],
[case "${enableval}" in
  ls1043) build_type=LS1043 ;;
  ls1046) build_type=LS1046 ;;
  *)  build_type=LS1043;;
esac],[build_type=LS1043])
fi
AM_CONDITIONAL([BUILD_LS2080], [test x$build_type = xLS2080 ])
AM_CONDITIONAL([BUILD_LS2085], [test x$build_type = xLS2085 ])
AM_CONDITIONAL([BUILD_LS2088], [test x$build_type = xLS2088 ])
AM_CONDITIONAL([BUILD_LS1088], [test x$build_type = xLS1088 ])
AM_CONDITIONAL([BUILD_LX2160], [test x$build_type = xLX2160 ])
AM_CONDITIONAL([BUILD_LS1043], [test x$build_type = xLS1043 ])
AM_CONDITIONAL([BUILD_LS1046], [test x$build_type = xLS1046 ])
AM_CONDITIONAL([P4_SOC], [test "x${SOC}" = "xP4080"])
AM_CONDITIONAL([T1_SOC], [test "x${SOC}" = "xT1040"])
AM_CONDITIONAL([T4_SOC], [test "x${SOC}" = "xT4240"])

##########################################################################
# Default warning setup
##########################################################################
ODP_CFLAGS="$ODP_CFLAGS -W -Wall -Wstrict-prototypes -Wmissing-prototypes"
ODP_CFLAGS="$ODP_CFLAGS -Wmissing-declarations -Wold-style-definition -Wpointer-arith"
ODP_CFLAGS="$ODP_CFLAGS -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral"
ODP_CFLAGS="$ODP_CFLAGS -Wformat-security -Wundef -Wwrite-strings"
ODP_CFLAGS="$ODP_CFLAGS"
# Extra flags for example to suppress certain warning types
ODP_CFLAGS="$ODP_CFLAGS $ODP_CFLAGS_EXTRA"

#########################################################################
# Check if compiler supports cmpxchng16
##########################################################################
if test "${CC}" != "gcc" -o ${CC_VERSION_MAJOR} -ge 5; then
   my_save_cflags="$CFLAGS"

   CFLAGS=-mcx16
   AC_MSG_CHECKING([whether CC supports -mcx16])
   AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
	    [AC_MSG_RESULT([yes])]
	    [ODP_CFLAGS="$ODP_CFLAGS $CFLAGS"],
	    [AC_MSG_RESULT([no])]
	    )
   CFLAGS="$my_save_cflags"
fi

##########################################################################
# Default include setup
##########################################################################
AM_CFLAGS="$AM_CFLAGS $ODP_CFLAGS"
AM_CXXFLAGS="-std=c++11"

AC_CONFIG_FILES([Makefile
		 helper/Makefile
		 helper/test/Makefile
		 pkgconfig/libodp-linux.pc
		 pkgconfig/libodphelper-linux.pc
		 scripts/Makefile
		 ])

AC_SEARCH_LIBS([timer_create],[rt posix4])

##########################################################################
# distribute the changed variables among the Makefiles

AC_SUBST([LIBS])
AC_SUBST([AM_CPPFLAGS])
AC_SUBST([CPPFLAGS])
AC_SUBST([AM_CFLAGS])
AC_SUBST([CFLAGS])
AC_SUBST([AM_LDFLAGS])
AC_SUBST([LDFLAGS])
AC_SUBST([EXEEXT])

AC_OUTPUT
AC_MSG_RESULT([
	$PACKAGE $VERSION

	ODP Library version:	${ODP_LIBSO_VERSION}
	Helper Library version:	${ODPHELPER_LIBSO_VERSION}

	implementation_name:	${IMPLEMENTATION_NAME}
	ARCH_DIR		${ARCH_DIR}
	with_platform:		${with_platform}
	prefix:			${prefix}
	sysconfdir:		${sysconfdir}
	libdir:			${libdir}
	includedir:		${includedir}
	testdir:		${testdir}
	WITH_ARCH:              ${WITH_ARCH}

	cc:			${CC}
	cc version:             ${CC_VERSION}
	cppflags:		${CPPFLAGS}
	am_cppflags:		${AM_CPPFLAGS}
	am_cxxflags:		${AM_CXXFLAGS}
	cflags:			${CFLAGS}
	am_cflags:		${AM_CFLAGS}
	ldflags:		${LDFLAGS}
	am_ldflags:		${AM_LDFLAGS}
	libs:			${LIBS}
	defs:			${DEFS}
	cunit:			${cunit_support}
	test_vald:		${test_vald}
	test_perf:		${test_perf}
	test_cpp:		${test_cpp}
	test_helper:		${test_helper}
	test_example:		${test_example}
	user_guides:		${user_guides}
])
