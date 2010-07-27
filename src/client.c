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

extern struct socket_options socket_options[];

struct opts {
	char *hostname;
	char *port;
	unsigned tx_packet_size;
	unsigned rx_packet_size;
	unsigned long packet_interval; /* in usec */
	unsigned verbose_level;
	unsigned iterations;
	uint16_t server_delay;
	uint16_t server_delay_var;
	int iteration_limit_enabled;
	int check_payload;
	int af_family; /* AF_UNSPEC, AF_INET or AF_INET6 */
	int ai_socktype;
	int ai_protocol;

	/* variables to model random packet distribution */
	int random_enabled;
	unsigned random_min;
	unsigned random_max;
	unsigned random_bandwidth; /* bit/s */
};


static int is_random_traffic_enabled(const struct opts *opts)
{
	return opts->ai_protocol == IPPROTO_UDP && opts->random_enabled;
}


/* returns random between [min, max) */
int rand_range(int min, int max)
{
      return (int)((double)rand() / (RAND_MAX + 1) * (max - min) + min);
}


static int tx_data(struct opts *o, struct packet *packet, int fd)
{
	ssize_t ret, size;

	size = o->tx_packet_size + sizeof(struct packet);

	if (is_random_traffic_enabled(o)) {
		if (o->random_min == o->random_max) {
			size = o->random_min;
			packet->data_len_tx = (uint32_t)htonl(size);
		} else {
			size = (rand() % (o->random_max - o->random_min)) + o->random_min;
			packet->data_len_tx = (uint32_t)htonl(size);
		}
	}

	if (size < (int)sizeof(struct packet))
		err_msg_die(EXIT_FAILINT, "packet too small - programmed error");

	msg("transmit %u byte", size);

	ret = write_len(fd, packet, size);
	if (ret != SUCCESS) {
		err_msg("failure in socket write operation");
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

		/* set all previously set socket option */
		set_socketopts(fd, opts->ai_protocol);

		/* Connect to peer
		 ** There are three advantages to call connect for all types
		 ** of our socket protocols (especially udp)
		 **
		 ** 1. We don't need to specify a destination address (only call write)
		 ** 2. Performance advantages (kernel level)
		 ** 3. Error detection (e.g. destination port unreachable at udp)
		 */
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
			"   --ipv4 (-4)\t\t\t\tenforces to use AF_INET socket (default AF_UNSPEC)\n"
			"   --ipv6 (-6)\t\t\t\tenforces to use AF_INET6 socket (default AF_UNSPEC)\n"
			"   --hostname (-e) <hostname>\t\tspecify the destiantion host\n"
			"   --port (-p) <port>\t\t\tdestination port of connection\n"
			"   --interval (-i)\t\t\tinterval between the generation (and reception) of packets\n"
			"   --iterations (-n) <number>\t\tlimit the number of transmissions\n"
			"   --txpacketsize (-s) <number>\t\tsize of the generated packet (excluding TCP/IP header)\n"
			"   --rxpacketsize (-r) <number>\t\tsize of the received packet (excluding TCP/IP header)\n"
			"   --server-delay (-d) <number>\t\tnumber of us until the server echo the data back\n"
			"   --server-delay-variation (-D) <number>\tnumber of additional us which are random add the server echo the data back\n"
			"   --check (-c)\t\t\t\tcheck payload for bit errors\n"
			"   --setsockopt (-S) <option:arg1:arg2:...>\tset the socketoption \"option\" with argument arg1, arg2, ...\n"
			"   --random (-R) <min:max:bw>\t\t\tgenerator to generate randomly generated traffic pattern\n"
			"   --verbose (-v)\t\t\t\tverbose output to STDOUT\n", me);
}

/* in MBit */
#define	MAX_BANDWIDTH 1000

static int setup_random_traffic(struct opts *opts, int min, int max, long long bw)
{
	/* sanity checks first */
	if (min < (int)sizeof(struct packet) || min > MAX_UDP_DATAGRAM) {
		err_msg("packet minimum is unacceptable. Is %d, must %d - %d",
				min, sizeof(struct packet), MAX_UDP_DATAGRAM);
		return FAILURE;
	}

	if (max < (int)sizeof(struct packet) || max > MAX_UDP_DATAGRAM) {
		err_msg("packet maximum is unacceptable. Is %d, must %d - %d",
				max, sizeof(struct packet), MAX_UDP_DATAGRAM);
		return FAILURE;
	}

	if (min > max) {
		err_msg("packet minimum %d is larger as maximum %d", min, max);
		return FAILURE;
	}

	if (bw <= 0 || (bw / 1000000) > MAX_BANDWIDTH) {
		err_msg("bandwidth is unacceptable: %d bit/s (must between %d and %d)",
				bw, 0, MAX_BANDWIDTH * 1000000);
		return FAILURE;
	}

	msg("random traffic generator [min %d byte, max: %d byte, bandwidth: %d bit/s]",
			min, max, bw);

	opts->random_min = min;
	opts->random_max = max;
	opts->random_bandwidth = bw;

	return SUCCESS;
}


static int optarg_set_random_traffic(const char *option_arg, struct opts *opts)
{
	int ret = FAILURE;
	const char delimiter[] = ":;,";
	char *token, *cp;
	int min, max;
	long long bw;

	cp = strdup(option_arg);
	token = strtok(cp, delimiter); /* first word */
	if (!token)
		goto out;

	ret = xatoi(token, &min);
	if (ret != SUCCESS)
		goto out;

	token = strtok(NULL, delimiter);
	if (!token)
		goto out;

	ret = xatoi(token, &max);
	if (ret != SUCCESS)
		goto out;

	token = strtok(NULL, delimiter);
	if (!token)
		goto out;

	bw = a_to_bit_s(token);
	if (bw < 0)
		goto out;

	if (setup_random_traffic(opts, min, max, bw) != SUCCESS)
		goto out;

	opts->random_enabled = 1;

	ret = SUCCESS;

out:
	free(cp);

	return ret;
}

static int xgetopts(int ac, char **av, struct opts *opts)
{
	int ret, c;
	int32_t val32;
	int option_index = 0;

	memset(opts, 0, sizeof(*opts));

	opts->packet_interval  = DEFAULT_PACKET_INTERVAL;
	opts->tx_packet_size   = DEFAULT_PACKET_SIZE;
	opts->rx_packet_size   = DEFAULT_PACKET_SIZE;
	opts->ai_socktype      = DEFAULT_AI_SOCKTYPE;
	opts->ai_protocol      = DEFAULT_AI_PROTOCOL;
	opts->server_delay     = 0;
	opts->server_delay_var = 0;
	opts->iteration_limit_enabled  = 0;
	opts->port             = strdup(DEFAULT_PORT);
	opts->check_payload    = 0;
	opts->af_family        = AF_UNSPEC;
	opts->random_enabled   = 0;

	while (1) {
		static struct option long_options[] = {
			{"ipv4",         1, 0, '4'},
			{"ipv6",         1, 0, '6'},
			{"verbose",      1, 0, 'v'},
			{"hostname",     1, 0, 'e'},
			{"interval",     1, 0, 'i'},
			{"iterations",   1, 0, 'n'},
			{"txpacketsize", 1, 0, 's'},
			{"rxpacketsize", 1, 0, 'r'},
			{"server-delay",  1, 0, 'd'},
			{"server-delay-variation",  1, 0, 'D'},
			{"port",         1, 0, 'p'},
			{"check",        1, 0, 'c'},
			{"help",         0, 0, 'h'},
			{"transport",    1, 0, 't'},
			{"setsockopt",   1, 0, 'S'},
			{"random",       1, 0, 'R'},
			{0, 0, 0, 0}
		};
		c = xgetopt_long(ac, av, "t:i:s:t:e:p:n:d:D:r:S:R:vhc46",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case '4':
				opts->af_family = AF_INET;
				break;
			case '6':
				opts->af_family = AF_INET6;
				break;
			case 'v':
				opts->verbose_level++;
				break;
			case 'i':
				opts->packet_interval = atoi(optarg);
				break;
			case 'n':
				opts->iterations = atoi(optarg);
				opts->iteration_limit_enabled = 1;
				break;
			case 's':
				opts->tx_packet_size = atoi(optarg);
				break;
			case 'r':
				opts->rx_packet_size = atoi(optarg);
				break;
			case 'd':
				val32 = atoi(optarg);
				if (val32 > UINT16_MAX || val32 < 0)
					err_msg_die(EXIT_FAILOPT, "client delay out of range: shoud 0-%d, is %d",
							UINT16_MAX, val32);
				opts->server_delay = (uint16_t)val32;
				break;
			case 'D':
				val32 = atoi(optarg);
				if (val32 > UINT16_MAX || val32 < 0)
					err_msg_die(EXIT_FAILOPT, "client delay variation out of range: shoud 0-%d, is %d",
							UINT16_MAX, val32);
				opts->server_delay_var = (uint16_t)val32;
				break;
			case 'e':
				opts->hostname = strdup(optarg);
				break;
			case 'p':
				free(opts->port);
				opts->port = strdup(optarg);
				break;
			case 'c':
				opts->check_payload = 1;
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
					opts->ai_socktype = SOCK_STREAM;
					opts->ai_protocol = IPPROTO_TCP;
				} else if (!strcasecmp("udp", optarg)) {
					opts->ai_socktype = SOCK_DGRAM;
					opts->ai_protocol = IPPROTO_UDP;
				} else {
					err_msg("protocol %s not supported", optarg);
					exit(EXIT_FAILOPT);
				}
				break;
			case 'h':
				print_usage(av[0]);
				exit(EXIT_SUCCESS);
				break;
			case 'R':
				ret = optarg_set_random_traffic(optarg, opts);
				if (ret != SUCCESS) {
					err_msg("failure in parsing traffic pattern", optarg);
					exit(EXIT_FAILOPT);
				}
				break;
			case '?':
				break;

			default:
				err_msg("getopt returned character code 0%o ?", c);
				return EXIT_FAILURE;
		}
	}

	if (!opts->hostname) {
		err_msg("no hostname given (via commandline option \"-e <hostname>\")");
		print_usage(av[0]);
		exit(EXIT_FAILOPT);
	}

	if (opts->tx_packet_size < sizeof(struct packet)) {
		err_msg("require at least %u byte of data (due to header data)",
				sizeof(struct packet));
		exit(EXIT_FAILOPT);
	}

	if (opts->ai_protocol == IPPROTO_UDP && opts->tx_packet_size > MAX_UDP_DATAGRAM) {
		err_msg("UDP datagram size to send to large and exceed Ethernet Jumbogram size (%d > %d(max))\n"
				"If you want to adjust this value see MAX_UDP_DATAGRAM)",
				opts->tx_packet_size, MAX_UDP_DATAGRAM);
		exit(EXIT_FAILOPT);
	}

	if (opts->random_enabled && opts->ai_protocol != IPPROTO_UDP)
		err_msg_die(EXIT_FAILOPT, "random option only useful for UDP sockets (-t udp)");

	return SUCCESS;
}


/* calculate the average inter-frame delay in usec */
static int calculate_random_traffic_delay(const struct opts *opts)
{
	int avg, delay;

	if (opts->random_min == opts->random_max)
		avg = opts->random_min;
	else
		avg = ((opts->random_max - opts->random_min) / 2) + opts->random_min;

	if (avg < (int)sizeof(struct packet))
		avg = sizeof(struct packet);

	/* calculation is done in byte */
	delay = ((double)avg / (((double)opts->random_bandwidth) / 8)) * 1000000;

	fprintf(stderr, "packet delay:%d [avg:%d   bw %d]\n", delay, avg, opts->random_bandwidth / 8);

	if (delay < 0 || delay > 100000000) {
		err_msg("delay to large: is %d and should between 0 and 100000000)"
				". Adjusting to 1000000", delay);
		delay = 100000000;
	}

	return delay;
}


int main(int ac, char *av[])
{
	int socket_fd, ret, delay_target = 0;
	size_t sret;
	char *data_rx;
	struct packet *packet;
	struct opts opts;
	double start, end, last_packet_time;

	init_network_stack();

	msg(PROGRAMNAME " - " VERSIONSTRING);

	ret = xgetopts(ac, av, &opts);
	if (ret != SUCCESS)
		err_msg_die(EXIT_FAILOPT, "failure in commandline options");

	packet = xzalloc(opts.tx_packet_size);

	/* subtracting header overhead */
	opts.tx_packet_size -= sizeof(struct packet);


	packet->magic            = MAGIC_COOKIE;
	packet->sequence_no      = 0;
	packet->data_len_tx      = htonl(opts.tx_packet_size);
	packet->data_len_rx      = htonl(opts.rx_packet_size);
	packet->server_delay     = htons(opts.server_delay);
	packet->server_delay_var = htons(opts.server_delay_var);

	memset(packet->data, PAYLOAD_BYTE_PATTERN, opts.tx_packet_size);

	/* this is a simple buffer container. Received data is
	 * written there */
	if (opts.tx_packet_size)
		data_rx = xzalloc(opts.tx_packet_size);

	if (is_random_traffic_enabled(&opts))
		delay_target = calculate_random_traffic_delay(&opts);


	/* connect to server */
	socket_fd = init_cli_socket(&opts);

	last_packet_time = xgettimeofday();

	while (!opts.iteration_limit_enabled || opts.iterations--) {

		int adjust;

		start = xgettimeofday();

		adjust = delay_target - ((start - last_packet_time) * 1000000);

		if (adjust > 0)
			opts.packet_interval = adjust;

		if (opts.packet_interval > 0) {
			msg("delay transmission of next packet for %u us", opts.packet_interval);
			xusleep(opts.packet_interval);
		}

		ret = tx_data(&opts, packet, socket_fd);
		if (ret != SUCCESS)
			break;

		last_packet_time = xgettimeofday();


		packet->sequence_no = packet->sequence_no + 1;

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

			msg("   received %u byte payload [application layer RTT: %.6lf ms]",
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

	}


	xclose(socket_fd);
	free(opts.port);

	fini_network_stack();

    return EXIT_SUCCESS;
}


/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
