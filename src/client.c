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
#define DEFAULT_PACKET_INTERVAL 1000000  /* eq 1 second */

struct opts {
	char *hostname;
	char *port;
	unsigned tx_packet_size;
	unsigned rx_packet_size;
	unsigned long packet_interval; /* in usec */
	unsigned verbose_level;
	unsigned iterations;
	uint32_t server_delay;
	int iteration_limit;
	int check_payload;
	int af_family; /* AF_UNSPEC, AF_INET or AF_INET6 */
	int ai_socktype;
	int ai_protocol;
};


static int tx_data(struct opts *o, struct packet *packet, int fd)
{
	int ret;

	msg("transmit %u byte header to server ", o->tx_packet_size + sizeof(struct packet));
	ret = write_len(fd, packet, o->tx_packet_size + sizeof(struct packet));
	if (ret != SUCCESS) {
		err_msg("failure in socket write (header)");
		return FAILURE;
	}

	return SUCCESS;
}


static int init_cli_socket(struct opts *opts)
{
	int ret, fd = -1;
	struct addrinfo hosthints, *hostres, *addrtmp;
	struct protoent *protoent;

	memset(&hosthints, 0, sizeof(struct addrinfo));

	hosthints.ai_family   = opts->af_family;
	hosthints.ai_socktype = opts->ai_socktype;
	hosthints.ai_protocol = opts->ai_protocol;
/* M$ till vista/win 7 does not support AI_ADDRCONFIG */
#if defined(WIN32)
	hosthints.ai_flags    = 0;
#else
	hosthints.ai_flags    = AI_ADDRCONFIG;
#endif

	xgetaddrinfo(opts->hostname, opts->port, &hosthints, &hostres);

	for (addrtmp = hostres; addrtmp != NULL ; addrtmp = addrtmp->ai_next) {
		fd = socket(addrtmp->ai_family, addrtmp->ai_socktype, addrtmp->ai_protocol);
		if (fd < 0)
			continue;

		protoent = getprotobynumber(addrtmp->ai_protocol);
		if (protoent)
			pr_debug("socket created - protocol %s(%d)",
					protoent->p_name, protoent->p_proto);

		ret = connect(fd, addrtmp->ai_addr, addrtmp->ai_addrlen);
		if (ret == -1)
			err_sys_die(EXIT_FAILNET, "Can't connect to %s", opts->hostname);

		/* great, found a valuable socket */
		break;
	}

	if (fd < 0)
		err_msg_die(EXIT_FAILNET,
				"Don't found a suitable TCP socket to connect to the client"
				", giving up");

	freeaddrinfo(hostres);

	pr_debug("open a active TCP socket on port %s", opts->port);

	return fd;
}


static void print_usage(const char *me)
{
	fprintf(stdout, "%s <options>\n"
			"Options:\n"
			"   --ipv4 (-4)\t\t\tenforces to use AF_INET socket (default AF_UNSPEC)\n"
			"   --ipv6 (-6)\t\t\tenforces to use AF_INET6 socket (default AF_UNSPEC)\n"
			"   --hostname (-e) <hostname>\t\tspecify the destiantion host\n"
			"   --port (-p) <port>\t\t\tdestination port of connection\n"
			"   --interval (-i)\t\t\tinterval between the generation (and reception) of packets\n"
			"   --iterations (-n) <number>\t\tlimit the number of transmissions\n"
			"   --txpacketsize (-s) <number>\t\tsize of the generated packet (excluding TCP/IP header)\n"
			"   --rxpacketsize (-r) <number>\t\tsize of the received packet (excluding TCP/IP header)\n"
			"   --serverdelay (-d) <number>\t\tnumber of seconds until the server echo the data back\n"
			"   --check (-c)\t\t\tcheck payload for bit errors\n"
			"   --verbose (-v)\t\t\tverbose output to STDOUT\n", me);
}


int main(int ac, char *av[])
{
	int socket_fd, c;
	size_t sret;
	char *data_rx;
	struct packet *packet;
	struct opts opts;
	double start, end;

	memset(&opts, 0, sizeof(opts));

	opts.packet_interval  = DEFAULT_PACKET_INTERVAL;
	opts.tx_packet_size   = DEFAULT_PACKET_SIZE;
	opts.rx_packet_size   = DEFAULT_PACKET_SIZE;
	opts.ai_socktype      = DEFAULT_AI_SOCKTYPE;
	opts.ai_protocol      = DEFAULT_AI_PROTOCOL;
	opts.server_delay     = 0;
	opts.iteration_limit  = 0;
	opts.port             = strdup(DEFAULT_PORT);
	opts.check_payload    = 0;
	opts.af_family        = AF_UNSPEC;

	init_network_stack();

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"ipv4",         1, 0, '4'},
			{"ipv6",         1, 0, '6'},
			{"verbose",      1, 0, 'v'},
			{"hostname",     1, 0, 'e'},
			{"interval",     1, 0, 'i'},
			{"iterations",   1, 0, 'n'},
			{"txpacketsize", 1, 0, 's'},
			{"rxpacketsize", 1, 0, 'r'},
			{"serverdelay",  1, 0, 'd'},
			{"port",         1, 0, 'p'},
			{"check",        1, 0, 'c'},
			{"help",         1, 0, 'h'},
			{"transport",    1, 0, 't'},
			{0, 0, 0, 0}
		};
		c = xgetopt_long(ac, av, "t:i:s:t:e:p:n:d:r:vhc46",
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
			case 'i':
				opts.packet_interval = atoi(optarg);
				break;
			case 'n':
				opts.iterations = atoi(optarg);
				opts.iteration_limit = 1;
				break;
			case 's':
				opts.tx_packet_size = atoi(optarg);
				break;
			case 'r':
				opts.rx_packet_size = atoi(optarg);
				break;
			case 'd':
				opts.server_delay = atoi(optarg);
				break;
			case 'e':
				opts.hostname = strdup(optarg);
				break;
			case 'p':
				free(opts.port);
				opts.port = strdup(optarg);
				break;
			case 'c':
				opts.check_payload = 1;
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

	if (!opts.hostname) {
		err_msg("no hostname given, -h");
		print_usage(av[0]);
		exit(EXIT_FAILOPT);
	}

	if (opts.tx_packet_size < sizeof(struct packet)) {
		err_msg("require at least %u byte of data (due to header data)",
				sizeof(struct packet));
		exit(EXIT_FAILOPT);
	}

	packet = xzalloc(opts.tx_packet_size);

	/* subtracting header overhead */
	opts.tx_packet_size -= sizeof(struct packet);


	packet->magic        = htons(MAGIC_COOKIE);
	packet->sequence_no  = 0;
	packet->data_len_tx  = htonl(opts.tx_packet_size);
	packet->data_len_rx  = htonl(opts.rx_packet_size);
	packet->server_delay = htonl(opts.server_delay);

	memset(packet->data, PAYLOAD_BYTE_PATTERN, opts.tx_packet_size);

	/* this is a simple buffer container. Received data is
	 * writen there */
	if (opts.tx_packet_size)
		data_rx = xzalloc(opts.tx_packet_size);

	/* connect to server */
	socket_fd = init_cli_socket(&opts);

	while (!opts.iteration_limit || opts.iterations--) {
		int ret;

		start = xgettimeofday();

		ret = tx_data(&opts, packet, socket_fd);
		if (ret != SUCCESS)
			break;

		packet->sequence_no = htons(ntohs(packet->sequence_no) + 1);

		/* wait and read data from server */
		if (opts.rx_packet_size) {
			fprintf(stderr, "block in read (waiting for %u bytes)\n",
					opts.rx_packet_size);
			sret = read_len(socket_fd, data_rx, opts.rx_packet_size);
			if (sret != (size_t) opts.rx_packet_size) {
				err_msg("failure in socket read (data)");
				break;
			}

			end = xgettimeofday();

			msg("   received %u byte payload (Application Layer RTT: %.6lf ms)",
					opts.rx_packet_size, end - start);


			/* check for byte error (this can be extended to count the number
			 * of toggled bits within the byte. This can be happened if using
			 * UDP by disabling the checksum functionality (setsockopt()) or
			 * in really rare cases by TCP */
			if (opts.check_payload && opts.rx_packet_size > sizeof(struct packet)) {

				int byte_error = 0; unsigned i;
				char *buf_ptr = data_rx + sizeof(struct packet);

				for (i = 0; i < opts.rx_packet_size - sizeof(struct packet); i++) {
					if ((unsigned char)buf_ptr[i] != PAYLOAD_BYTE_PATTERN) {
						byte_error++;
					}
				}
				if (byte_error)
					fprintf(stderr, ", %d byte(s) ERROR(s) detected\n", byte_error);
			}

		}

		if (opts.packet_interval > 0) {
			msg("   going to sleep for %u us", opts.packet_interval);
			xusleep(opts.packet_interval);
		}
	}


	xclose(socket_fd);
	free(opts.port);

	fini_network_stack();

    return EXIT_SUCCESS;
}


/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
