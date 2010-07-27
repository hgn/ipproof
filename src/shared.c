/*
** Copyright (C) 2009,2010 - Hagen Paul Pfeifer <hagen@jauu.net>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include "global.h"


static int conv_ip_mtu_discover(const char *s)
{
	size_t i;
	static const struct {
		const char *symname;
		int sym;
	} symtab[] = {
		{"IP_PMTUDISC_WANT", IP_PMTUDISC_WANT},
		{"IP_PMTUDISC_DO", IP_PMTUDISC_DO},
		{"IP_PMTUDISC_DONT", IP_PMTUDISC_DONT},
		{"IP_PMTUDISC_PROBE", IP_PMTUDISC_PROBE}
	};

	for (i=0 ; i < ARRAY_SIZE(symtab); i++)
		if (strcasecmp(s, symtab[i].symname) == 0)
			return symtab[i].sym;

	fputs("MTU_DISCOVER: Known arguments:\n", stderr);

	for (i=0 ; i < ARRAY_SIZE(symtab); i++)
		fprintf(stderr, "%s\n", symtab[i].symname);

	exit(1);
}


struct socket_options socket_options[] = {
  {"SO_KEEPALIVE", SOL_SOCKET,  SO_KEEPALIVE, SVT_BOOL, NULL, 0, {0}},
  {"SO_REUSEADDR", SOL_SOCKET,  SO_REUSEADDR, SVT_BOOL, NULL, 0, {0}},
  {"SO_BROADCAST", SOL_SOCKET,  SO_BROADCAST, SVT_BOOL, NULL, 0, {0}},
  {"SO_BROADCAST", SOL_SOCKET,  SO_BROADCAST, SVT_BOOL, NULL, 0, {0}},
  {"SO_BROADCAST", SOL_SOCKET,  SO_BROADCAST, SVT_BOOL,NULL,  0, {0}},
  {"TCP_NODELAY",  IPPROTO_TCP, TCP_NODELAY,  SVT_BOOL, NULL, 0, {0}},
#if !defined(WIN32)
  {"TCP_CONGESTION", IPPROTO_TCP, TCP_CONGESTION, SVT_STR, NULL, 0, {0}},
  {"TCP_CORK",     IPPROTO_TCP, TCP_CORK,  SVT_BOOL, NULL, 0, {0}},
  {"TCP_KEEPCNT",  IPPROTO_TCP, TCP_KEEPCNT,  SVT_INT, NULL, 0, {0}},
  {"TCP_KEEPIDLE",  IPPROTO_TCP, TCP_KEEPIDLE,  SVT_INT, NULL, 0, {0}},
  {"TCP_KEEPINTVL",  IPPROTO_TCP, TCP_KEEPINTVL,  SVT_INT, NULL, 0, {0}},
  {"TCP_SYNCNT",  IPPROTO_TCP, TCP_SYNCNT,  SVT_INT, NULL, 0, {0}},
  {"TCP_WINDOW_CLAMP",  IPPROTO_TCP, TCP_WINDOW_CLAMP,  SVT_INT, NULL, 0, {0}},
  {"TCP_QUICKACK",  IPPROTO_TCP, TCP_QUICKACK,  SVT_BOOL, NULL, 0, {0}},
  {"TCP_DEFER_ACCEPT",  IPPROTO_TCP, TCP_DEFER_ACCEPT,  SVT_BOOL, NULL, 0, {0}},
  {"TCP_MAXSEG",  IPPROTO_TCP, TCP_MAXSEG,  SVT_INT, NULL, 0, {0}},
  {"TCP_THIN_DUPACK",  IPPROTO_TCP, TCP_THIN_DUPACK,  SVT_INT, NULL, 0, {0}},
  {"TCP_THIN_LINEAR_TIMEOUTS",  IPPROTO_TCP, TCP_THIN_LINEAR_TIMEOUTS,  SVT_INT, NULL, 0, {0}},
  {"TCP_LINGER2",  IPPROTO_TCP, TCP_LINGER2,  SVT_INT, NULL, 0, {0}},
  {"IP_MTU_DISCOVER", IPPROTO_IP, IP_MTU_DISCOVER, SVT_TOINT, conv_ip_mtu_discover, 0, {0}},
  {"SO_RCVBUF",    SOL_SOCKET,  SO_RCVBUF,    SVT_INT,  NULL, 0, {0}},
  {"SO_SNDLOWAT",  SOL_SOCKET,  SO_SNDLOWAT,  SVT_INT,  NULL, 0, {0}},
  {"SO_RCVLOWAT",  SOL_SOCKET,  SO_RCVLOWAT,  SVT_INT,  NULL, 0, {0}},
  {"SO_SNDTIMEO",  SOL_SOCKET,  SO_SNDTIMEO,  SVT_TIMEVAL, NULL, 0, {0}},
  {"SO_RCVTIMEO",  SOL_SOCKET,  SO_RCVTIMEO,  SVT_TIMEVAL, NULL, 0, {0}},
#endif
  {NULL, 0, 0, 0, NULL, 0, {0}}
};


void xsetsockopt(int s, int level, int optname,
		const void *optval, socklen_t optlen, const char *str)
{
	int ret;

	msg("set socket option %s", str);

	ret = setsockopt(s, level, optname, optval, optlen);
	if (ret)
		err_sys_die(EXIT_FAILNET, "Can't set socketoption %s", str);
}


#if !defined(WIN32)
static int ignore_sigpipe(void)
{
	struct sigaction sa = { .sa_handler = SIG_IGN };

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	return sigaction(SIGPIPE, &sa, NULL);
}
#endif


static int parse_yesno(const char *optname, const char *optval)
{
	int ret;

	if (strcmp(optval, "1") == 0)
		return 1;
	if (strcmp(optval, "0") == 0)
		return 0;
	if (strcasecmp(optval, "on") == 0)
		return 1;
	if (strcasecmp(optval, "yes") == 0)
		return 1;
	if (strcasecmp(optval, "no") == 0)
		return 0;
	if (strcasecmp(optval, "off") == 0)
		return 0;

	ret = atoi(optval) != 0;
	err_msg("%s: unrecognized optval \"%s\" (only 0/1 allowed); assuming %d",
								optname, optval, ret);
	return ret;
}


/* return number of characters parsed (ie amount of digits) */
static int scan_int(const char *str, int *val)
{
	char *endptr;
	long num;
	size_t parsed;

	num = strtol(str, &endptr, 0);

	parsed = endptr - str;
	if (parsed) {
		if (num > INT_MAX)
			err_msg("%s > INT_MAX", str);
		if (num < INT_MIN)
			err_msg("%s < INT_MIN", str);
		*val = (int) num;
	}
	return parsed;
}


static const char *setsockopt_optvaltype_tostr(enum sockopt_val_types x)
{
	switch (x) {
	case SVT_BOOL: return "[ 0 | 1 ]";
	case SVT_INT: return "number";
	case SVT_TOINT: return "symname";
	case SVT_TIMEVAL: return "seconds:microseconds";
	case SVT_STR: return "string";
	default: return "";
	}
}


static const char *setsockopt_level_tostr(int level)
{
	switch (level) {
	case SOL_SOCKET: return "SOL_SOCKET";
	case IPPROTO_IP: return "IPPROTO_IP";
	case IPPROTO_TCP: return "IPPROTO_TCP";
#if  defined(HAVE_UDPLITE_SUPPORT) && defined(HAVE_SCTP_SUPPORT)
	case IPPROTO_SCTP: return "IPROTO_SCTP";
	case IPPROTO_UDPLITE: return "IPPROTO_UDPLITE";
#endif
	default: return NULL;
	}
}


ssize_t xread(int fd, void *buf, int len)
{
	return recv(fd, buf, len, 0);
}


int xclose(int fd)
{
#if defined(WIN32)
	return closesocket(fd);
#else
	return close(fd);
#endif
}


int xwrite(int fd, const char *buf, int len)
{
#if defined(WIN32)
	return send(fd, buf, len, 0);
#else
	return write(fd, buf, len);
#endif
}


void *xmalloc(size_t size)
{
	void *ptr = malloc(size);
	if (!ptr)
		err_sys_die(EXIT_FAILMEM, "failure in malloc!\n");
	return ptr;
}


void *xzalloc(size_t size)
{
	void *ptr = xmalloc(size);
	memset(ptr, 0, size);
	return ptr;
}


void xgetaddrinfo(const char *node, const char *service,
		struct addrinfo *hints, struct addrinfo **res)
{
	int ret;

	ret = getaddrinfo(node, service, hints, res);
	if (ret != 0) {
#if defined(WIN32)
		err_msg_die(EXIT_FAILNET, "Call to getaddrinfo() failed: %s!",
				strerror(ret));
#else
		err_msg_die(EXIT_FAILNET, "Call to getaddrinfo() failed: %s!",
				(ret == EAI_SYSTEM) ?  strerror(errno) : gai_strerror(ret));
#endif
	}

	return;
}

double xgettimeofday(void)
{
#if defined(WIN32)
	struct _timeb tv;
	_ftime(&tv);
	return (double)tv.time + (double)tv.millitm / 1000;
#else
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;
#endif
}


ssize_t write_len(int fd, const void *buf, size_t len)
{
	const char *bufptr = buf;
	ssize_t total = 0;

	if (len == 0)
		return SUCCESS;

	do {
		ssize_t written = xwrite(fd, bufptr, len);
		if (written < 0) {
			int real_errno;

			if (errno == EINTR || errno == EAGAIN)
				continue;

			real_errno = errno;
			err_msg("Could not write %u bytes: %s", len, strerror(errno));
			errno = real_errno;
			break;
		}
		total  += written;
		bufptr += written;
		len    -= written;
	} while (len > 0);

	return total > 0 ? SUCCESS : FAILURE;
}


ssize_t read_len(int fd, const void *buf, size_t len)
{
	const char *bufptr = buf;
	size_t read_actual = 0;

	if (len == 0)
		return SUCCESS;

	while (1) {

		ssize_t cur = xread(fd, (void *)bufptr, len - read_actual);

		if (cur < 0) {
			int real_errno;

			if (errno == EINTR || errno == EAGAIN)
				continue;

			real_errno = errno;
			err_msg("Could not read %u bytes: %s", len, strerror(errno));
			errno = real_errno;
			break;
		}

		if (cur == 0) {
			msg("read return 0");
			return 0;
		}

		bufptr += cur; read_actual += cur;

		if (read_actual >= len)
			break;
	}

	return read_actual;
}


void init_network_stack(void)
{
	int err;
#if defined(WIN32)
	WSADATA wsaData;

	err = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (err != 0) {
		/* Tell the user that we could not find a usable */
		/* Winsock DLL.                                  */
		err_msg_die(EXIT_FAILMISC, "WSAStartup failed with error: %d\n", err);
	}
#else
	/* SIGPIPE signal will be received if the peer has gone away
	 * and an attempt is made to write data to the peer. Ignoring this
	 * signal causes the write operation to receive an EPIPE error */
	err = ignore_sigpipe();
	if (err < 0)
		err_msg_die(EXIT_FAILMISC, "failure in ignoring SIGPIPE signal");
#endif

	/* initialize the random generator */
	srand((unsigned)time( NULL ));
}

void fini_network_stack(void)
{
#if defined(WIN32)
	WSACleanup();
#else
#endif
}

int xgetopt_long(int ac, char * const av[],
		const char *optstring,
		const struct option *longopts, int *longindex)
{
#if defined(WIN32)
		return _getopt_internal(ac, av, optstring,
				longopts, longindex, 0);
#else
		return getopt_long(ac, av, optstring, longopts, longindex);
#endif
}





#define	CC_AVAIL_ALGORITHMS "/proc/sys/net/ipv4/tcp_available_congestion_control"


static void die_print_cong_alg(int exit_val)
{
	static const char avail_cg[] = CC_AVAIL_ALGORITHMS;
	FILE *f;
	const char *data;
	char buf[4096];

	f = fopen(avail_cg, "r");
	if (!f)
		err_sys_die(EXIT_FAILMISC, "open %s", avail_cg);

	fputs("Known congestion control algorithms on this machine:\n", stderr);
	while ((data = fgets(buf, sizeof(buf), f)))
		fputs(buf, stderr);

	fclose(f);
	exit(exit_val);
}


static void die_print_setsockopts(int ret_val)
{
	unsigned i;

	fputs("Known setsockopt optnames:\n", stderr);
	fputs("level\t\toptname\t\t\toptval\n", stderr);

	for (i = 0; socket_options[i].sockopt_name; i++) {
		fprintf(stderr, "%s\t%s\t\t%s\n",
			setsockopt_level_tostr(socket_options[i].level),
			socket_options[i].sockopt_name,
			setsockopt_optvaltype_tostr(socket_options[i].sockopt_type));
	}

	exit(ret_val);
}


void parse_setsockopt_name(const char *optname, const char *optval, struct socket_options *so)
{
	unsigned i;

	for (i = 0; so[i].sockopt_name; i++) {
		if (strcasecmp(optname, so[i].sockopt_name))
			continue;

		switch (so[i].sockopt_type) {
		case SVT_BOOL:
			so[i].value = parse_yesno(optname, optval);
			goto found;
		case SVT_INT:
			if (!scan_int(optval, &so[i].value))
				err_msg("%s: unrecognized optval \"%s\" "
					"(integer argument required);skipped",
							optval, optname);
			goto found;
		case SVT_TIMEVAL: {
			int seconds, usecs = 0;
			int parsed = scan_int(optval, &seconds);

			if (parsed == 0) {
				err_msg("%s: unrecognized optval \"%s\" "
					"(integer argument required);skipped",
							optval, optname);
				return;
			}
			if (optval[parsed] == ':') {
				parsed = scan_int(&optval[parsed+1], &usecs);
				if (parsed == 0) {
					err_msg("%s: unrecognized optval \"%s\" "
					"(integer argument required after ':');skipped",
							optval, optname);
					return;
				}
			}
			so[i].tv.tv_sec = seconds;
			so[i].tv.tv_usec = usecs;
			goto found;
		}
		case SVT_STR:
			so[i].value_ptr = optval;
			goto found;
		case SVT_TOINT:
			assert(so[i].convert_to_int);
			so[i].value =
				so[i].convert_to_int(optval);
			goto found;
		default:
			err_msg("WARNING: Internal error: unrecognized "
				"sockopt_type (%s %s) (%s:%u)",
				optval, optname, __FILE__, __LINE__);
			return;
		}
	}
	err_msg("Unrecognized sockopt \"%s\" ignored", optname );
 found:
	so[i].user_issue = 1;
}


/*
 * performs all socketopts specified, except
 * for some highly protocol dependant options (e.g. TCP_MD5SIG).
 */
void set_socketopts(int fd, int protocol)
{
	int i, ret;
	const void *optval;
	socklen_t optlen;

	/* loop over all selectable socket options */
	for (i = 0; socket_options[i].sockopt_name; i++) {
		if (!socket_options[i].user_issue)
			continue;
		/*
		 * this switch statement checks that the particular
		 * socket option matches our selected socket-type
		 */
		switch (socket_options[i].level) {
		case SOL_SOCKET: break; /* works on every socket */
		/* fall-through begins here ... */
		case IPPROTO_IP:
		case IPPROTO_IPV6:
		case IPPROTO_TCP:
			if (protocol == IPPROTO_TCP)
				break;
		case IPPROTO_UDP:
			if (protocol == IPPROTO_UDP)
				break;
		default:
		/* and exit if socketoption and sockettype did not match */
		err_msg_die(EXIT_FAILMISC, "You selected an socket option which isn't "
					"compatible with this particular socket option");
		}

		/* ... and do the dirty: set the socket options */
		switch (socket_options[i].sockopt_type) {
		case SVT_BOOL:
		case SVT_INT:
		case SVT_TOINT:
			optlen = sizeof(socket_options[i].value);
			optval = &socket_options[i].value;
			msg("set socket option %s:%d", socket_options[i].sockopt_name, socket_options[i].value);
		break;
		case SVT_TIMEVAL:
			optlen = sizeof(socket_options[i].tv);
			optval = &socket_options[i].tv;
			/* TODO: print struct timeval */
			msg("set socket option %s", socket_options[i].sockopt_name);
		break;
		case SVT_STR:
			optlen = strlen(socket_options[i].value_ptr) + 1;
			optval = socket_options[i].value_ptr;
			msg("set socket option %s:%s", socket_options[i].sockopt_name, socket_options[i].value_ptr);
		break;
		default:
			err_msg_die(EXIT_FAILNET, "Unknown sockopt_type %d\n",
					socket_options[i].sockopt_type);
		}
		ret = setsockopt(fd, socket_options[i].level, socket_options[i].option, optval, optlen);
		if (ret)
			err_sys_die(EXIT_FAILOPT, "setsockopt option %d (name %s) failed",
					socket_options[i].sockopt_type, socket_options[i].sockopt_name);
	}
}


unsigned calc_hamming_dist(const char *data, size_t len)
{
	size_t i;
	unsigned v, c;

	for (i = 0; i < len; i++) {

		v = data[i];

		for (c = 0; v; c++)
			v &= v - 1;
	}

	return c;
}


/* set TCP_NODELAY opption on socket
** return the previous value (0, 1) or
** -1 if a error occur
*/
int set_nodelay(int fd, int flag)
{
	int ret = 0; socklen_t ret_size;

	if (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &ret, &ret_size) < 0)
		return -1;

	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0)
		return -1;

	return ret;
}

void msg(const char *format, ...)
{
	va_list ap;

	fprintf(stderr, "[%06lf] ", xgettimeofday());

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);

	fputs("\n", stderr);
}


static void err_doit(int sys_error, const char *file,
		const int line_no, const char *fmt, va_list ap)
{
	int errno_save;
	char buf[MAXERRMSG];

	errno_save = errno;

	vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
	if (sys_error) {
		size_t len = strlen(buf);
		snprintf(buf + len,  sizeof buf - len, " (%s)",
				strerror(errno_save));
	}

	fprintf(stderr, "ERROR [%s:%d]: %s\n", file, line_no, buf);
	fflush(NULL);

	errno = errno_save;
}


void x_err_ret(const char *file, int line_no, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	err_doit(0, file, line_no, fmt, ap);
	va_end(ap);
	return;
}


void x_err_sys(const char *file, int line_no, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	err_doit(1, file, line_no, fmt, ap);
	va_end(ap);
}

void msleep(unsigned long msec)
{
#if defined(WIN32)
	Sleep(msec);
#else
	struct timespec req;
	time_t sec;

	if (msec == 0)
		return;

	memset(&req, 0, sizeof(struct timespec));

	sec = msec / 1000;

	msec = msec - ( sec * 1000);
	req.tv_sec = sec;
	req.tv_nsec = msec * 1000000L;

	while (nanosleep(&req, &req) == -1)
		continue;
	return;
#endif
}


void xusleep(unsigned long usec)
{
#if defined(WIN32)
	struct timeval tv;
	fd_set dummy;

	SOCKET s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	FD_ZERO(&dummy);
	FD_SET(s, &dummy);

	tv.tv_sec = usec / 1000000L;
	tv.tv_usec = usec % 1000000L;

	select(0, 0, 0, &dummy, &tv);
#else
	usleep(usec);
#endif
}


int optarg_set_socketopts(const char *option_arg, struct socket_options *so)
{
	int ret = FAILURE;
	const char delimiter[] = ":";
	char *token, *cp;
	char *s1;

	/* special option to list all possibles socket options */
	if (streq(option_arg, "help"))
		die_print_setsockopts(EXIT_SUCCESS);

	if (streq(option_arg, "help-congestion-control"))
		die_print_cong_alg(EXIT_SUCCESS);

	cp = strdup(option_arg);
	token = strtok(cp, delimiter); /* first word */
	if (!token)
		goto out;

	s1 = strdup(token);

	token = strtok(NULL, delimiter);
	if (!token)
		goto out1;

	/* great, argument are meet our requirements */
	parse_setsockopt_name(s1, token, so);


	ret = SUCCESS;

out1:
	free(s1);
out:
	free(cp);

	return ret;
}

enum {
	/* SI byte prefixe 10^n */
	SI_IEC_PREFIX_KBIT = 0,
	SI_IEC_PREFIX_MBIT,
	SI_IEC_PREFIX_GBIT,
	/* IEC byte prefixe 2^n */
	SI_IEC_PREFIX_KIBIT,
	SI_IEC_PREFIX_MIBIT,
	SI_IEC_PREFIX_GIBIT,
	/* SI byte prefixe 10^n */
	SI_IEC_PREFIX_KB,
	SI_IEC_PREFIX_MB,
	SI_IEC_PREFIX_GB,
	/* IEC byte prefixe 2^n */
	SI_IEC_PREFIX_KIB,
	SI_IEC_PREFIX_MIB,
	SI_IEC_PREFIX_GIB,
	SI_IEC_PREFIX_MAX
};


static unsigned long long conversion_faktor_si_iec_to_bit[] = {
	/* SI_IEC_PREFIX_KBIT */
	1000ull,
	/* SI_IEC_PREFIX_MBIT */
	1000ull * 1000,
	/* SI_IEC_PREFIX_GBIT */
	1000ull * 1000 * 1000,
	/* SI_IEC_PREFIX_KIBIT */
	1024ull,
	/* SI_IEC_PREFIX_MIBIT */
	1024ull * 1024,
	/* SI_IEC_PREFIX_GIBIT */
	1024ull * 1024 * 1024,
	/* SI_IEC_PREFIX_KB */
	8ull * 1000,
	/* SI_IEC_PREFIX_MB */
	8ull * 1000 * 1000,
	/* SI_IEC_PREFIX_GB */
	8ull * 1000 * 1000 * 1000,
	/* SI_IEC_PREFIX_KIB */
	8ull * 1024,
	/* SI_IEC_PREFIX_MIB */
	8ull * 1024 * 1024,
	/* SI_IEC_PREFIX_GIB */
	8ull * 1024 * 1024 * 1024,
};


static int convert_si_iec_prefixes(const char *str)
{
	if (streq("kilobit", str)) {
		return SI_IEC_PREFIX_KBIT;
	} else if (streq("kbit", str)) {
		return SI_IEC_PREFIX_KBIT;
	} else if (streq("megabit", str)) {
		return SI_IEC_PREFIX_MBIT;
	} else if (streq("Mbit", str)) {
		return SI_IEC_PREFIX_MBIT;
	} else if (streq("gigabit", str)) {
		return SI_IEC_PREFIX_GBIT;
	} else if (streq("Gbit", str)) {
		return SI_IEC_PREFIX_GBIT;
	} else if (streq("kibibit", str)) {
		return SI_IEC_PREFIX_KIBIT;
	} else if (streq("Kibit", str)) {
		return SI_IEC_PREFIX_KIBIT;
	} else if (streq("mebibit", str)) {
		return SI_IEC_PREFIX_MIBIT;
	} else if (streq("Mibit", str)) {
		return SI_IEC_PREFIX_MIBIT;
	} else if (streq("gibibit", str)) {
		return SI_IEC_PREFIX_GIBIT;
	} else if (streq("Gibit", str)) {
		return SI_IEC_PREFIX_GIBIT;
	} else if (streq("kilobyte", str)) {
		return SI_IEC_PREFIX_KB;
	} else if (streq("kB", str)) {
		return SI_IEC_PREFIX_KB;
	} else if (streq("megabyte", str)) {
		return SI_IEC_PREFIX_MB;
	} else if (streq("MB", str)) {
		return SI_IEC_PREFIX_MB;
	} else if (streq("gigabyte", str)) {
		return SI_IEC_PREFIX_GB;
	} else if (streq("GB", str)) {
		return SI_IEC_PREFIX_GB;
	} else if (streq("kibibyte", str)) {
		return SI_IEC_PREFIX_KIB;
	} else if (streq("KiB", str)) {
		return SI_IEC_PREFIX_KIB;
	} else if (streq("mebibyte", str)) {
		return SI_IEC_PREFIX_MIB;
	} else if (streq("MIB", str)) {
		return SI_IEC_PREFIX_MIB;
	} else if (streq("gibibyte", str)) {
		return SI_IEC_PREFIX_GIB;
	} else if (streq("GiB", str)) {
		return SI_IEC_PREFIX_GIB;
	} else {
		return -1;
	}
}


long long byte_atoi(const char *string)
{
	int ret, prefix_index;
	double number;
	char buf[16];

	ret = sscanf( string, "%lf%15s", &number, buf);
	if (ret != 2) {
		msg("bandwidth argument inaccurate. Required is a number, directly"
				"followed by a suffix: GMKgmk (where the lower letters are SI units (10^n),"
					"the uppercase letters represent the IEC binary suffixes 2^n) - all units"
				"in bits, not bytes");
		return -1;
	}

	buf[sizeof(buf) - 1] = '\0';

	prefix_index = convert_si_iec_prefixes(buf);
	if (prefix_index < 0) {
		msg("prefix is not known: %s", buf);
		return -1;
	}

	if (prefix_index > (int)ARRAY_SIZE(conversion_faktor_si_iec_to_bit))
		err_msg_die(EXIT_FAILINT, "programmed error");

	return (long long) (number *= conversion_faktor_si_iec_to_bit[prefix_index]);
}


int xatoi(const char *str, int *ret)
{
	long sl;
	char *end_ptr;

	errno = 0;

	sl = strtol(str, &end_ptr, 10);

	if ((sl == LONG_MIN || sl == LONG_MAX) && errno != 0) {
		err_sys("strtol error conversation error encountered: %s", str);
		return FAILURE;
	} else if (end_ptr == str) {
		err_msg("error encountered during integer conversion: %s", str);
		return FAILURE;
	} else if (sl > INT_MAX) {
		err_msg("integer too large");
		return FAILURE;
	} else if (sl < INT_MIN) {
		err_msg("integer too small");
		return FAILURE;
	} else if ('\0' != *end_ptr) {
		err_msg("extra characters on input line: %s", end_ptr);
		return FAILURE;
	}

	*ret = sl;

	return SUCCESS;
}


/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
