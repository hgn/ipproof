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

#define PROGRAMNAME "ipproof"
#define VERSIONSTRING "002"

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

/* some brand new linux tcp options */
#ifndef TCP_THIN_LINEAR_TIMEOUTS
# define TCP_THIN_LINEAR_TIMEOUTS 16
#endif

#ifndef TCP_THIN_DUPACK
# define TCP_THIN_DUPACK 17
#endif

#ifndef TCP_COOKIE_TRANSACTIONS
# define TCP_COOKIE_TRANSACTIONS 15
#endif

/* IP_MTU_DISCOVER values */

/* Never send DF frames */
#ifndef IP_PMTUDISC_DONT
# define IP_PMTUDISC_DONT  0
#endif

/* Use per route hints */
#ifndef IP_PMTUDISC_WANT
# define IP_PMTUDISC_WANT 1
#endif

/* Always DF */
#ifndef IP_PMTUDISC_DO
# define IP_PMTUDISC_DO 2
#endif

/* Ignore dst pmtu */
#ifndef IP_PMTUDISC_PROBE
# define IP_PMTUDISC_PROBE 3
#endif


/*  a horrible workaround */
#if defined(WIN32)
# pragma pack(push,1)
#endif
struct packet {
	uint8_t magic;
	uint8_t sequence_no;
	uint32_t data_len_tx;
	uint32_t data_len_rx;
	uint16_t server_delay; /* delay and delay variance encoded in ms */
	uint16_t server_delay_var;
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


struct socket_options {
	const char *sockopt_name;
	int   level;
	int   option;
	int   sockopt_type;
	int (*convert_to_int)(const char *);
	int  user_issue;
	union {
		int value;
		struct timeval tv;
		const char *value_ptr;
	};
};


/* shared.c */
void msg(const char *, ...);
void x_err_ret(const char *, int, const char *, ...);
void x_err_sys(const char *, int, const char *, ...);
void xsetsockopt(int, int, int, const void *, socklen_t, const char *);
void xusleep(unsigned long);
void msleep(unsigned long);
int xwrite(int fd, const char *buf, int len);
int xclose(int fd);
ssize_t xread(int fd, void *buf, int len);
void *xmalloc(size_t);
void *xzalloc(size_t);
void xgetaddrinfo(const char *node, const char *service, struct addrinfo *hints, struct addrinfo **res);
double xgettimeofday(void);
ssize_t write_len(int fd, const void *buf, size_t len);
ssize_t read_len(int fd, const void *buf, size_t len);
void init_network_stack(void);
void fini_network_stack(void);
int xgetopt_long(int ac, char * const av[], const char *optstring, const struct option *longopts, int *longindex);
int optarg_set_socketopts(const char *, struct socket_options *);
void set_socketopts(int, int);
long long byte_atoi(const char *);



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




enum sockopt_val_types {
	SVT_BOOL = 0,
	SVT_INT,
	SVT_TOINT,
	SVT_TIMEVAL,
	SVT_STR
};

#endif /* GLOBAL_H */


/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
