/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.in by autoheader.  */
/* Define if your system defines struct sockaddr_storage */
#define HAVE_STRUCT_SOCKADDR_STORAGE 1

/* Define if your system uses access rights style file descriptor passing */
/* #undef HAVE_ACCRIGHTS_IN_MSGHDR */

/* Define if your system uses ancillary data style file descriptor passing */
#define HAVE_CONTROL_IN_MSGHDR 1

/* Define if the addr_cmp in libdnet is broken */
/* #undef HAVE_BROKEN_DNET */

/* Define to `unsigned int' if <sys/types.h> doesn't define.  */
/* #undef u_int */

/* Define to `unsigned long long' if <sys/types.h> doesn't define.  */
/* #undef u_int64_t */

/* Define to `unsigned int' if <sys/types.h> doesn't define.  */
/* #undef u_int32_t */

/* Define to `unsigned short' if <sys/types.h> doesn't define.  */
/* #undef u_int16_t */

/* Define to `unsigned char' if <sys/types.h> doesn't define.  */
/* #undef u_int8_t */

/* Define if timeradd is defined in <sys/time.h> */
#define HAVE_TIMERADD 1
#ifndef HAVE_TIMERADD
#define timeradd(tvp, uvp, vvp)                                         \
        do {                                                            \
                (vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;          \
                (vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;       \
                if ((vvp)->tv_usec >= 1000000) {                        \
                        (vvp)->tv_sec++;                                \
                        (vvp)->tv_usec -= 1000000;                      \
                }                                                       \
        } while (0)
#define	timersub(tvp, uvp, vvp)						\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;	\
		if ((vvp)->tv_usec < 0) {				\
			(vvp)->tv_sec--;				\
			(vvp)->tv_usec += 1000000;			\
		}							\
	} while (0)
#endif /* !HAVE_TIMERADD */

/* Define if isblank is defined in <ctype.h> */
#define HAVE_ISBLANK 1
#ifndef HAVE_ISBLANK
#define isblank(x)	((x) == ' ' || (x) == '\t')
#endif

/* #undef DL_NEED_UNDERSCORE */
/* #undef NODLOPEN */
#define DLOPENLIBC "/lib/i386-linux-gnu/libc.so.6"


/* Define kqueue should be disabled for libevent */
/* #undef DISABLE_KQUEUE */

/* Define poll should be disabled for libevent */
/* #undef DISABLE_POLL */

/* Defines which libc to preload */
#define DLOPENLIBC "/lib/i386-linux-gnu/libc.so.6"

/* Do symbols need underscores? */
/* #undef DL_NEED_UNDERSCORE */

/* Define if your system uses access rights style file descriptor passing */
/* #undef HAVE_ACCRIGHTS_IN_MSGHDR */

/* Define to 1 if you have the `asprintf' function. */
#define HAVE_ASPRINTF 1

/* Define to 1 if you have the <assert.h> header file. */
#define HAVE_ASSERT_H 1

/* Define if your system uses ancillary data style file descriptor passing */
#define HAVE_CONTROL_IN_MSGHDR 1

/* Define to 1 if you have the `daemon' function. */
#define HAVE_DAEMON 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you don't have `vprintf' but do have `_doprnt.' */
/* #undef HAVE_DOPRNT */

/* Define if our libdnet is a libdumbnet */
#define HAVE_DUMBNET 1

/* Define to 1 if you have the `dup2' function. */
#define HAVE_DUP2 1

/* Define to 1 if you have the `err' function. */
#define HAVE_ERR 1

/* Define to 1 if you have the <errno.h> header file. */
#define HAVE_ERRNO_H 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have the `fgetln' function. */
/* #undef HAVE_FGETLN */

/* Define to 1 if you have the `freeaddrinfo' function. */
#define HAVE_FREEADDRINFO 1

/* Define to 1 if you have the `getaddrinfo' function. */
#define HAVE_GETADDRINFO 1

/* Define to 1 if you have the `getnameinfo' function. */
#define HAVE_GETNAMEINFO 1

/* Define to 1 if you have the `getopt_long' function. */
#define HAVE_GETOPT_LONG 1

/* Define to 1 if you have the `gettimeofday' function. */
#define HAVE_GETTIMEOFDAY 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `isblank' function. */
#define HAVE_ISBLANK 1

/* Define to 1 if you have the `kqueue' function. */
/* #undef HAVE_KQUEUE */

/* Define if you have libedit */
#define HAVE_LIBEDIT 1

/* Define to 1 if you have the `event' library (-levent). */
#define HAVE_LIBEVENT 1

/* Define if you have libreadline */
/* #undef HAVE_LIBREADLINE */

/* Define to 1 if you have the `z' library (-lz). */
#define HAVE_LIBZ 1

/* Define to 1 if you have the `memmove' function. */
#define HAVE_MEMMOVE 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `memset' function. */
#define HAVE_MEMSET 1

/* Define to 1 if you have the <net/bpf.h> header file. */
/* #undef HAVE_NET_BPF_H */

/* Define to 1 if you have the <paths.h> header file. */
#define HAVE_PATHS_H 1

/* Define if libpcap has pcap_get_selectable_fd */
#define HAVE_PCAP_GET_SELECTABLE_FD 1

/* Define if Python knows about the dnet modules */
/* #undef HAVE_PYDNET */

/* Define if we want to link with Python support */
/* #undef HAVE_PYTHON */

/* Define to 1 if you have the `recvmsg' function. */
#define HAVE_RECVMSG 1

/* Define to 1 if you have the `sendmsg' function. */
#define HAVE_SENDMSG 1

/* Define to 1 if you have the `setgroups' function. */
#define HAVE_SETGROUPS 1

/* Define to 1 if you have the `setregid' function. */
#define HAVE_SETREGID 1

/* Define to 1 if you have the `setruid' function. */
/* #undef HAVE_SETRUID */

/* Define to 1 if you have the `SHA1Update' function. */
/* #undef HAVE_SHA1UPDATE */

/* Define if sockaddr struct has sa_len. */
/* #undef HAVE_SOCKADDR_SA_LEN */

/* Define to 1 if you have the <stdarg.h> header file. */
#define HAVE_STDARG_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strcasecmp' function. */
#define HAVE_STRCASECMP 1

/* Define to 1 if you have the `strchr' function. */
#define HAVE_STRCHR 1

/* Define to 1 if you have the `strdup' function. */
#define HAVE_STRDUP 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strlcat' function. */
/* #undef HAVE_STRLCAT */

/* Define to 1 if you have the `strlcpy' function. */
/* #undef HAVE_STRLCPY */

/* Define to 1 if you have the `strncasecmp' function. */
#define HAVE_STRNCASECMP 1

/* Define to 1 if you have the `strsep' function. */
#define HAVE_STRSEP 1

/* Define to 1 if you have the `strspn' function. */
#define HAVE_STRSPN 1

/* Define to 1 if you have the `strtoul' function. */
#define HAVE_STRTOUL 1

/* Define if your system defines struct sockaddr_storage */
#define HAVE_STRUCT_SOCKADDR_STORAGE 1

/* Set if you have sun_len in socketaddr_un */
/* #undef HAVE_SUN_LEN */

/* Define to 1 if you have the <syslog.h> header file. */
#define HAVE_SYSLOG_H 1

/* Define to 1 if you have the <sys/file.h> header file. */
#define HAVE_SYS_FILE_H 1

/* Define to 1 if you have the <sys/ioccom.h> header file. */
/* #undef HAVE_SYS_IOCCOM_H */

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

/* Define to 1 if you have the <sys/param.h> header file. */
#define HAVE_SYS_PARAM_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have <sys/wait.h> that is POSIX.1 compatible. */
#define HAVE_SYS_WAIT_H 1

/* Define if timeradd is define in <sys/time.h> */
#define HAVE_TIMERADD 1

/* Define to 1 if you have the <time.h> header file. */
#define HAVE_TIME_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the `vprintf' function. */
#define HAVE_VPRINTF 1

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ".libs/"

/* Do we need to call dlopen()? */
/* #undef NODLOPEN */

/* Name of package */
#define PACKAGE "honeyd"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME ""

/* Define to the full name and version of this package. */
#define PACKAGE_STRING ""

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME ""

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION ""

/* Define as the return type of signal handlers (`int' or `void'). */
#define RETSIGTYPE void

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. */
#define TIME_WITH_SYS_TIME 1

/* Version number of package */
#define VERSION "1.5c"

/* Define to 1 if `lex' declares `yytext' as a `char *' by default, not a
   `char[]'. */
#define YYTEXT_POINTER 1

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef gid_t */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef pid_t */

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef u_int */

/* Define to `unsigned short' if <sys/types.h> does not define. */
/* #undef u_int16_t */

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef u_int32_t */

/* Define to `unsigned long long' if <sys/types.h> does not define. */
/* #undef u_int64_t */

/* Define to `unsigned char' if <sys/types.h> does not define. */
/* #undef u_int8_t */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef uid_t */

/* Prototypes for missing functions */
#ifndef HAVE_STRLCPY
size_t	 strlcpy(char *, const char *, size_t);
#endif

#ifndef HAVE_STRLCAT
size_t	 strlcat(char *, const char *, size_t);
#endif

#ifndef HAVE_STRSEP
char	*strsep(char **, const char *);
#endif

#ifndef HAVE_DAEMON
int	daemon(int, int);
#endif
