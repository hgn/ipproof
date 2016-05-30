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
#define VERSIONSTRING "011"

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

#ifndef BITS_PER_LONG
# define BITS_PER_LONG	__WORDSIZE
#endif

#define BIT(nr) (1UL << (nr))
#define BIT_MASK(nr) (1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr) ((nr) / BITS_PER_LONG)
#define BITS_PER_BYTE 8
#define BITS_TO_LONGS(nr) DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

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

typedef uint16_t le16;
typedef uint16_t be16;
typedef uint32_t le32;
typedef uint32_t be32;

#define PREAMBEL_COOKIE 0xA0
#define PREAMBEL_COOKIE_MASK 0xE0
#define PREAMBEL_COOKIE_IS_VALID(x) ((x & PREAMBEL_COOKIE_MASK) == PREAMBEL_COOKIE)

#define PREAMBEL_EXTENDED_HEADER 0x10
#define PREAMBEL_EXTENDED_HEADER_IS(x) (x & PREAMBEL_EXTENDED_HEADER)

#define PREAMBEL_FLOW_END 0x8
#define PREAMBEL_FLOW_END_IS(x) (x & PREAMBEL_FLOW_END)

#if defined(WIN32)
# pragma pack(push,1)
#endif
struct header_minimal {
        uint8_t preambel;
        uint8_t flow_id;
        be16 sequence_number;
        be32 data_length_tx;
        le16 data_length_rx;
        char data[0];
}
#if defined(WIN32)
;
# pragma pack(pop)
#else
__attribute__((__packed__));
#endif


#if defined(WIN32)
# pragma pack(push,1)
#endif
struct header_extended {
        uint8_t preambel;
        uint8_t reserved;
        be16 flow_id;
        be32 sequence_number;
        be32 data_length_tx;
        be32 data_length_rx;
        be16 server_delay;
        be16 server_delay_var;
        char data[0];
}
#if defined(WIN32)
;
# pragma pack(pop)
#else
__attribute__((__packed__));
#endif


enum {
        HEADER_FORMAT_MINIMAL,
        HEADER_FORMAT_EXTENDED
};


/*  a horrible workaround */
#if defined(WIN32)
# pragma pack(push,1)
#endif
struct packet {
	uint8_t magic;
	uint8_t sequence_no;
	uint16_t data_len_tx;
	uint16_t data_len_rx;
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

/*  extended header definition, extended header available
 *  if EXTENDED_PATTERN is set in packet->magic. If extended
 *  header is active then the original data_len_tx and
 *  data_len_rx fields are ignored */
#if defined(WIN32)
# pragma pack(push,1)
#endif
struct extended_header {
        uint32_t data_len_tx;
        uint32_t data_len_rx;
        uint32_t sequence_no;
        uint32_t id;
}
#if defined(WIN32)
;
# pragma pack(pop)
#else
__attribute__((__packed__));
#endif

/* 101010 */
#define MAGIC_COOKIE 0x2A
#define MAGIC_COOKIE_MASK 0xFE

/* if active then the extended mode is activated and
 * MUST be used */
#define EXTENDED_COOKIE_PATTERN 0x1
#define EXTENDED_COOKIE_PATTERN_MASK 0x1

#define PAYLOAD_BYTE_PATTERN 'X'

/* We support the maximum IP layer header size here, we *have*
 * already application layer fragmentation by using -n <n> option.
 */
#define	MAX_UDP_DATAGRAM 65535

#define DEFAULT_PORT "5001"

#define MAX_LINE 1024

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

#define FACTOR_MS_S 1000
#define FACTOR_US_S 1000000
#define	FACTOR_NS_S 1000000000

#define VERBOSE_NORMAL(verbose) (verbose && verbose > 0)
#define VERBOSE_EXTENSIVE(verbose) (verbose && verbose > 1)
#define VERBOSE_ULTRA(verbose) (verbose && verbose > 2)

/* conditional because gcc does not support varargs.h */
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

enum {
        VMSG_DEBUG,
        VMSG_INFO,
        VMSG_INFO2,
        VMSG_ERROR
};

enum {
        FORMAT_HUMAN,
        FORMAT_JSON,
};

#define FORMAT_DEFAULT FORMAT_HUMAN

/* shared.c */
//void vmsg(int level, const char *, ...);
void msg(const char *, ...);
void x_err_ret(const char *, int, const char *, ...);
void x_err_sys(const char *, int, const char *, ...);
void xsetsockopt(int, int, int, const void *, socklen_t, const char *);
void xusleep(unsigned long);
void msleep(unsigned long);
int xwrite(int, const char *, int);
int xclose(int);
ssize_t xread(int fd, void *, int);
void *xmalloc(size_t);
void *xzalloc(size_t);
void xgetaddrinfo(const char *, const char *, struct addrinfo *, struct addrinfo **);
double xgettimeofday(void);
ssize_t write_len(int fd, const void *, size_t);
ssize_t read_len(int fd, const void *, size_t);
void init_network_stack(void);
void fini_network_stack(void);
int xgetopt_long(int ac, char * const av[], const char *, const struct option *, int *);
int optarg_set_socketopts(const char *, struct socket_options *);
void set_socketopts(int, int);
long long a_to_bit_s(const char *);
int xatoi(const char *, int *);
const char *format_str(unsigned int format);
int is_format_human(unsigned int format);
int is_format_json(unsigned int format);



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


int xrand(void);


/* returns random between [min, max) */
int rand_range(int min, int max);



#endif /* GLOBAL_H */
