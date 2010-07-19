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


#ifndef GLOBAL_H
#define GLOBAL_H

#if defined(WIN32)
#  define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/types.h>
#include <assert.h>
#include <signal.h>
#include <limits.h>


#if defined(WIN32)

#  define strcasecmp _stricmp
#  define snprintf _snprintf
#  define strdup _strdup

#  pragma comment(lib, "Ws2_32.lib")

#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <stdio.h>
#  include <windows.h>
#  include <sys/timeb.h>
#  include <io.h>
#  include <varargs.h>

#  include "coot-getopt.h"
#  include "pstdint.h"

#else /* UNIX */

#  include <unistd.h>
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <sys/resource.h>
#  include <inttypes.h>
#  include <getopt.h>
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <netdb.h>

#endif

#define	DEFAULT_AI_SOCKTYPE SOCK_STREAM
#define	DEFAULT_AI_PROTOCOL IPPROTO_TCP

#ifdef  _WIN64
typedef unsigned __int64 size_t;
typedef  __int64 ssize_t;
#else
# ifdef WIN32
typedef _W64 unsigned int size_t;
typedef _W64 int ssize_t;
# endif
#endif



/* what a horrible workaround */
#if defined(WIN32)
# pragma pack(push,1)
#endif
struct packet {
	uint16_t magic;
	uint16_t sequence_no;
	uint32_t data_len_tx;
	uint32_t data_len_rx;
	uint32_t server_delay;
	char data[0];
}
#if defined(WIN32)
;
# pragma pack(pop)
#else
__attribute__((__packed__));
#endif

#define MAGIC_COOKIE 0x23

#define PAYLOAD_BYTE_PATTERN 0xff

/* large enough to support 16128 jumbo ethernet frames - supported by intel
 * e1000 adapters */
#define	MAX_UDP_DATAGRAM 16384

#define DEFAULT_PORT "5001"

#define MAX_LINE 1000

/* 7.19.1 in C99 but anyway: 8K or 16K on most
 *  * machines - st_blksize via fstat(2) can[TM] be superior */
#ifndef BUFSIZ
# define BUFSIZ 8192
#endif

#ifdef DEBUG
static const int debug_enabled = 1;
#else
static const int debug_enabled = 0;
#endif

#define streq(a, b) (!strcmp((a),(b)))

/* conditonal because gcc does not support varargs.h */
#if defined(WIN32)

#  define likely(x)   x
#  define unlikely(x) x

#  define err_msg(format,  ...) \
	do { \
		x_err_ret(__FILE__, __LINE__,  format , __VA_ARGS__); \
	} while (0)

#  define err_sys(format, ...) \
	do { \
		x_err_sys(__FILE__, __LINE__,  format , __VA_ARGS__); \
	} while (0)

#  define err_sys_die(exitcode, format, ...) \
	do { \
		x_err_sys(__FILE__, __LINE__, format , __VA_ARGS__); \
		exit( exitcode ); \
	} while (0)

#  define err_msg_die(exitcode, format, ...) \
	do { \
		x_err_ret(__FILE__, __LINE__,  format , __VA_ARGS__); \
		exit( exitcode ); \
	} while (0)

#  define pr_debug(format, ...) \
	do { \
		if (debug_enabled) \
		msg(format, __VA_ARGS__); \
	} while (0)

#else /* UNIX */

# if !defined likely && !defined unlikely
#  define likely(x)   __builtin_expect(!!(x), 1)
#  define unlikely(x) __builtin_expect(!!(x), 0)
# endif

# define err_msg(format, args...) \
	do { \
		x_err_ret(__FILE__, __LINE__,  format , ## args); \
	} while (0)

# define err_sys(format, args...) \
	do { \
		x_err_sys(__FILE__, __LINE__,  format , ## args); \
	} while (0)

# define err_sys_die(exitcode, format, args...) \
	do { \
		x_err_sys(__FILE__, __LINE__, format , ## args); \
		exit( exitcode ); \
	} while (0)

# define err_msg_die(exitcode, format, args...) \
	do { \
		x_err_ret(__FILE__, __LINE__,  format , ## args); \
		exit( exitcode ); \
	} while (0)

# define pr_debug(format, args...) \
	do { \
		if (debug_enabled) \
		msg(format, ##args); \
	} while (0)
#endif

static int xwrite(int fd, const char *buf, int len)
{
#if defined(WIN32)
	return send(fd, buf, len, 0);
#else
	return write(fd, buf, len);
#endif
}

static ssize_t xread(int fd, void *buf, int len)
{
	return recv(fd, buf, len, 0);
}

static int xclose(int fd)
{
#if defined(WIN32)
	return closesocket(fd);
#else
	return close(fd);
#endif
}


/* determine the size of an array */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define BITSIZEOF(x)  (CHAR_BIT * sizeof(x))

/* set to maximum queue length specifiable by listen */
#define	DEFAULT_TCP_BACKLOG SOMAXCONN

#define EXIT_OK         EXIT_SUCCESS
#define EXIT_FAILMEM    1
#define EXIT_FAILOPT    2
#define EXIT_FAILMISC   3
#define EXIT_FAILNET    4
#define EXIT_FAILHEADER 6
#define EXIT_FAILEVENT  7
#define EXIT_FAILFILE   8
#define EXIT_FAILSSL    9
#define EXIT_FAILINT    10 /* INTernal error */

#define SUCCESS 0
#define FAILURE -1

#define	MAXERRMSG 1024

static double xgettimeofday(void)
{

#if defined(WIN32)

	struct _timeb tv;
	_ftime(&tv);
	return (double)tv.time + (double)tv.millitm * 1000;

#else

	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;

#endif
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


static void *xmalloc(size_t size)
{
	void *ptr = malloc(size);
	if (!ptr)
		err_sys_die(EXIT_FAILMEM, "failure in malloc!\n");
	return ptr;
}


static void *xzalloc(size_t size)
{
	void *ptr = xmalloc(size);
	memset(ptr, 0, size);
	return ptr;
}


static void xsetsockopt(int s, int level, int optname,
		const void *optval, socklen_t optlen, const char *str)
{
	int ret = setsockopt(s, level, optname, optval, optlen);
	if (ret)
		err_sys_die(EXIT_FAILNET, "Can't set socketoption %s", str);
}


static void xgetaddrinfo(const char *node, const char *service,
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


static ssize_t write_len(int fd, const void *buf, size_t len)
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


static ssize_t read_len(int fd, const void *buf, size_t len)
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


static void init_network_stack(void)
{
#if defined(WIN32)
	int err;
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
	signal(SIGPIPE, SIG_IGN);
#endif
}

static void fini_network_stack(void)
{
#if defined(WIN32)
	WSACleanup();
#else
#endif
}

static int xgetopt_long(int ac, char * const av[],
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


static void msleep(unsigned long msec)
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


static void xusleep(unsigned long usec)
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




#endif /* GLOBAL_H */



/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
