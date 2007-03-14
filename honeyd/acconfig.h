/* Define if your system defines struct sockaddr_storage */
#undef HAVE_STRUCT_SOCKADDR_STORAGE

/* Define if your system uses access rights style file descriptor passing */
#undef HAVE_ACCRIGHTS_IN_MSGHDR

/* Define if your system uses ancillary data style file descriptor passing */
#undef HAVE_CONTROL_IN_MSGHDR

/* Define if the addr_cmp in libdnet is broken */
#undef HAVE_BROKEN_DNET

/* Define to `unsigned int' if <sys/types.h> doesn't define.  */
#undef u_int

/* Define to `unsigned long long' if <sys/types.h> doesn't define.  */
#undef u_int64_t

/* Define to `unsigned int' if <sys/types.h> doesn't define.  */
#undef u_int32_t

/* Define to `unsigned short' if <sys/types.h> doesn't define.  */
#undef u_int16_t

/* Define to `unsigned char' if <sys/types.h> doesn't define.  */
#undef u_int8_t

/* Define if timeradd is defined in <sys/time.h> */
#undef HAVE_TIMERADD
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
#undef HAVE_ISBLANK
#ifndef HAVE_ISBLANK
#define isblank(x)	((x) == ' ' || (x) == '\t')
#endif

#undef DL_NEED_UNDERSCORE
#undef NODLOPEN
#undef DLOPENLIBC

@BOTTOM@

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
