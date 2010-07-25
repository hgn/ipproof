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

#define DEFAULT_PACKET_SIZE 1000
#define DEFAULT_PACKET_INTERVAL 1

extern struct socket_options socket_options[];

struct conn_data {
	uint8_t sequence_no;
	int sequence_initialized;
};

struct opts {
	const char *port;
	unsigned packet_size;
	unsigned packet_interval;
	unsigned verbose_level;
	unsigned iterations;
	int iteration_limit;
	int af_family;
	int ai_socktype;
	int ai_protocol;
};


static int rx_tx_data_tcp(int fd, struct conn_data *conn_data)
{
	int ret;
	char *data_rx, *data_tx;
	struct packet packet;
	uint32_t data_len_tx, data_len_rx;
	uint16_t server_delay, server_delay_var;
	uint8_t sequence_no;


	data_rx = data_tx = NULL;

	msg("   read header (%d byte)", sizeof(struct packet));
	ret = read_len(fd, &packet, sizeof(struct packet));
	if (ret != sizeof(struct packet)) {
		xclose(fd);
		return FAILURE;
	}

	/* some sanity checks */
	if (packet.magic != MAGIC_COOKIE) {
		msg("not a valid packet (cookie mismatch)");
		xclose(fd);
		return FAILURE;
	}

	data_len_tx      = ntohl(packet.data_len_tx);
	data_len_rx      = ntohl(packet.data_len_rx);
	sequence_no      = packet.sequence_no;
	server_delay     = ntohs(packet.server_delay);
	server_delay_var = ntohs(packet.server_delay_var);

	if (!conn_data->sequence_initialized) {
		conn_data->sequence_no = sequence_no;
		conn_data->sequence_initialized++;
	}

	if (conn_data->sequence_no++ != sequence_no) {
		/* this IS an TCP/IP stack error - but CAN happend for
		 * UDP/DCCP/whatver based protocols */
		msg("   ERROR: drift in sequence number detected - (is %u, should %u)",
				sequence_no, conn_data->sequence_no - 1);
	}


	msg("   client data [tx data %u, rx data: %u, server delay %u ms, server delay variation %u ms, sequence number: %u]",
			data_len_tx, data_len_rx, server_delay, server_delay_var, packet.sequence_no);


	data_rx = xzalloc(data_len_tx);

	msg("   read %u bytes of data from client", data_len_tx);
	ret = read_len(fd, data_rx, data_len_tx);
	if (ret != (int)data_len_tx) {
		err_msg("failure in read from client: expect %u byte, read %u byte",
				data_len_tx, ret);
		free(data_rx);
		xclose(fd);
		return FAILURE;
	}

	data_tx = xzalloc(data_len_rx);
	memset(data_tx, 0xff, data_len_rx);

	if (server_delay > 0) {
		msg("   sleep for %u ms", server_delay);
		/* FIXME: add variation */
		msleep(server_delay);
	}

	/* write data_len data back to the client */
	msg("   write %u byte of data back to the client", data_len_rx);
	ret = write_len(fd, data_tx, data_len_rx);
	if (ret != SUCCESS) {
		free(data_tx);
		free(data_rx);
		xclose(fd);
		return FAILURE;
	}

	if (data_rx)
		free(data_rx);

	if (data_tx)
		free(data_tx);

	return SUCCESS;
}

static void process_cli_request_udp(int server_fd)
{
	ssize_t sret; int ret, flags = 0;
	struct sockaddr_storage sa;
	socklen_t sa_len = sizeof(sa);
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	static char packet[MAX_UDP_DATAGRAM];

	sret = recvfrom(server_fd, &packet, sizeof(packet), flags,
			(struct sockaddr *)&sa, &sa_len);
	if (sret < 0) {
		err_sys("failure in recvfrom() - return code %d", sret);
		return;
	}

	ret = getnameinfo((struct sockaddr *)&sa, sa_len, hbuf,
			NI_MAXHOST, sbuf, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
	if (ret != 0)
		err_msg_die(EXIT_FAILNET, "getnameinfo error: %s",  gai_strerror(ret));

	msg("received %d bytes from %s:%s", sret, hbuf, sbuf);

	//sendto(sd,msg,n,flags,(struct sockaddr *)&cliAddr,cliLen);
}

static void process_cli_request_tcp(int server_fd, struct opts *opts)
{
	int connected_fd = -1, ret;
	struct sockaddr_storage sa;
	socklen_t sa_len = sizeof sa;
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	struct conn_data conn_data;

	conn_data.sequence_initialized = 0;

	msg("block in accept(2)");
	connected_fd = accept(server_fd, (struct sockaddr *) &sa, &sa_len);
	if (connected_fd == -1) {
		err_sys("accept error");
		exit(EXIT_FAILNET);
	}

	/* set all previously set socket option */
	set_socketopts(connected_fd, opts->ai_protocol);

	ret = getnameinfo((struct sockaddr *)&sa, sa_len, hbuf,
			NI_MAXHOST, sbuf, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
	if (ret != 0)
		err_msg_die(EXIT_FAILNET, "getnameinfo error: %s",  gai_strerror(ret));

	msg("accept from %s:%s", hbuf, sbuf);

	while (rx_tx_data_tcp(connected_fd, &conn_data) == SUCCESS)
		;
}

static const char *network_family_str(int family)
{
	switch (family) {
	case AF_INET:  return "AF_INET (IPv4)";  break;
	case AF_INET6: return "AF_INET6 (IPv6)"; break;
	default:       return "unknown";  break;
	}
}


static const char *network_protocol_str(int protocol)
{
	switch (protocol) {
	case IPPROTO_UDP:  return "IPPROTO_UDP";  break;
	case IPPROTO_TCP: return "IPPROTO_TCP"; break;
	default:       return "unknown";  break;
	}
}



static int init_srv_socket(const struct opts *opts)
{
	int ret, fd = -1, on = 1;
	struct addrinfo hosthints, *hostres, *addrtmp;
	struct protoent *protoent;

	memset(&hosthints, 0, sizeof(struct addrinfo));

	hosthints.ai_family   = opts->af_family;
	hosthints.ai_socktype = opts->ai_socktype;
	hosthints.ai_protocol = opts->ai_protocol;
#if defined(WIN32)
	hosthints.ai_flags    = AI_PASSIVE;
#else
	hosthints.ai_flags    = AI_ADDRCONFIG | AI_PASSIVE;
#endif

	xgetaddrinfo(NULL, opts->port, &hosthints, &hostres);

	for (addrtmp = hostres; addrtmp != NULL ; addrtmp = addrtmp->ai_next) {
		fd = socket(addrtmp->ai_family, addrtmp->ai_socktype, addrtmp->ai_protocol);
		if (fd < 0)
			continue;

		protoent = getprotobynumber(addrtmp->ai_protocol);
		if (protoent)
			pr_debug("socket created - protocol %s(%d)",
					protoent->p_name, protoent->p_proto);


		/* For multicast sockets it is maybe necessary to set
		 * socketoption SO_REUSEADDR, cause multiple receiver on
		 * the same host will bind to this local socket.
		 * In all other cases: there is no penalty - hopefully! ;-)
		 */
		xsetsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on), "SO_REUSEADDR");

		ret = bind(fd, addrtmp->ai_addr, addrtmp->ai_addrlen);
		if (ret) {
			err_sys("bind failed");
			xclose(fd);
			fd = -1;
			continue;
		}

		if (opts->ai_protocol == IPPROTO_TCP) {
			ret = listen(fd, 1);
			if (ret < 0) {
				err_sys("bind failed");
				xclose(fd);
				fd = -1;
				continue;
			}
		}

		/* great, found a valuable socket */
		break;
	}

	if (fd < 0)
		err_msg_die(EXIT_FAILNET,
				"Don't found a suitable TCP socket to connect to the client"
				", giving up");

	msg("bind to port %s via %s using %s socket [%s:%s]",
			opts->port, network_protocol_str(opts->ai_protocol),
			network_family_str(addrtmp->ai_family),
			addrtmp->ai_family == AF_INET ? "0.0.0.0" : "::", opts->port);

	freeaddrinfo(hostres);

	return fd;
}


static void print_usage(const char *me)
{
	fprintf(stdout, "%s <options>\n"
			"  --port, -p <port>\n"
			"  --protocol, -t <tcp | udp> \n"
			"  --setsockopt (-S) <option:arg1:arg2:...>\tset the socketoption \"option\" with argument arg1, arg2, ...\n"
			"  --verbose, -v\n", me);
}


int main(int ac, char *av[])
{
	int socket_fd, c, ret;
	struct opts opts;

	memset(&opts, 0, sizeof(opts));

	opts.port             = DEFAULT_PORT;
	opts.packet_interval  = DEFAULT_PACKET_INTERVAL;
	opts.packet_size      = DEFAULT_PACKET_SIZE;
	opts.ai_socktype      = DEFAULT_AI_SOCKTYPE;
	opts.ai_protocol      = DEFAULT_AI_PROTOCOL;
	opts.af_family        = AF_UNSPEC;
	opts.iteration_limit  = 0;
	opts.port             = strdup(DEFAULT_PORT);

	msg(PROGRAMNAME " - " VERSIONSTRING);

	init_network_stack();

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"verbose",      0, 0, 'v'},
			{"ipv4",         1, 0, '4'},
			{"ipv6",         1, 0, '6'},
			{"port",         1, 0, 'p'},
			{"help",         1, 0, 'h'},
			{"transport",    1, 0, 't'},
			{"setsockopt",   1, 0, 'S'},
			{0, 0, 0, 0}
		};
		c = xgetopt_long(ac, av, "p:t:S:vh46",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case '4':
				opts.af_family = AF_INET;
				break;
			case '6':
				opts.af_family = AF_INET6;
				break;
			case 'v':
				opts.verbose_level++;
				break;
			case 'p':
				free((void *)opts.port);
				opts.port = strdup(optarg);
				break;
			case 'S':
				ret = optarg_set_socketopts(optarg, socket_options);
				if (ret != SUCCESS) {
					err_msg("socket option %s not supported", optarg);
					print_usage(av[0]);
					exit(EXIT_FAILOPT);
				}
				break;
			case 't':
				if (!strcasecmp("tcp", optarg)) {
					opts.ai_socktype = SOCK_STREAM;
					opts.ai_protocol = IPPROTO_TCP;
				} else if (!strcasecmp("udp", optarg)) {
					opts.ai_socktype = SOCK_DGRAM;
					opts.ai_protocol = IPPROTO_UDP;
				} else {
					err_msg("protocol %s not supported", optarg);
					print_usage(av[0]);
					exit(EXIT_FAILOPT);
				}
				break;
			case 'h':
				print_usage(av[0]);
				exit(EXIT_SUCCESS);
				break;
			case '?':
				break;

			default:
				err_msg("getopt returned character code 0%o ?", c);
				return EXIT_FAILURE;
		}
	}

	msg("initialize server socket");
	socket_fd = init_srv_socket(&opts);

	/* set all previously set socket option */
	set_socketopts(socket_fd, opts.ai_protocol);

	switch (opts.ai_protocol) {
	case IPPROTO_TCP:
		while (!opts.iteration_limit || opts.iterations--)
			process_cli_request_tcp(socket_fd, &opts);
		break;
	case IPPROTO_UDP:
		while (!opts.iteration_limit || opts.iterations--)
			process_cli_request_udp(socket_fd);
		break;
	default:
		err_msg("programmed error in switch/case label");
		break;
	}

	xclose(socket_fd);

	fini_network_stack();

    return EXIT_SUCCESS;
}


/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
