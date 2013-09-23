/*
** Copyright (C) 2009-2013 - Hagen Paul Pfeifer <hagen@jauu.net>
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

#define DEFAULT_PACKET_SIZE 500
#define DEFAULT_PACKET_INTERVAL 1000000  /* eq 1 second */

extern struct socket_options socket_options[];

enum {
        PAYLOAD_PATTERN_STATIC,
        PAYLOAD_PATTERN_RANDOM,
        PAYLOAD_PATTERN_RANDOM_ASCII
};

#define DEFAULT_PAYLOAD_PATTERN PAYLOAD_PATTERN_STATIC

struct opts {
	char *hostname;
	char *bind_addr;
	char *port;
	unsigned int tx_packet_size, rx_packet_size;
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

        int payload_pattern;

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


static int tx_data(struct opts *o, int header_format, char *packet, int fd, int counter)
{
	ssize_t ret, size;
        struct header_extended *he;
        struct header_minimal *hm;

	size = o->tx_packet_size;

	if (is_random_traffic_enabled(o)) {
                /* random traffic only allowed if minimum
                 * data size is >= extended header size. Thus
                 * we know that the extended header is in use */
                he = (struct header_extended *)packet;
		if (o->random_min == o->random_max) {
			size = o->random_min;
		} else {
			size = (rand() % (o->random_max - o->random_min)) + o->random_min;
		}
	}

        switch (header_format) {
        case HEADER_FORMAT_MINIMAL:
                hm = (struct header_minimal *)packet;
                hm->data_length_tx = htonl((int32_t)size);
                break;
        case HEADER_FORMAT_EXTENDED:
                he = (struct header_extended *)packet;
                he->data_length_tx = htonl((int32_t)size);
                break;
        default:
                assert(0);
                break;
        }

	if (o->verbose_level && counter % 100 == 0) {
		msg("transmit %u byte", size);
	}

	ret = write_len(fd, packet, size);
	if (ret != SUCCESS) {
		err_msg("failure in socket write operation");
		return FAILURE;
	}

	return SUCCESS;
}


static int bind_client_socket(struct opts *opts, int fd)
{
	int ret;
	struct addrinfo hosthints, *hostres, *addrtmp;

	memset(&hosthints, 0, sizeof(struct addrinfo));

	hosthints.ai_family   = opts->af_family;
	hosthints.ai_socktype = opts->ai_socktype;
	hosthints.ai_protocol = opts->ai_protocol;
#if defined(WIN32)
	hosthints.ai_flags    = AI_PASSIVE;
#else
	hosthints.ai_flags    = AI_ADDRCONFIG | AI_PASSIVE;
#endif

	xgetaddrinfo(opts->bind_addr, NULL, &hosthints, &hostres);

	for (addrtmp = hostres; addrtmp != NULL ; addrtmp = addrtmp->ai_next) {
		ret = bind(fd, addrtmp->ai_addr, addrtmp->ai_addrlen);
		if (ret) {
			err_sys("bind failed");
                        return -1;
		}

		/* great,  */
		return 0;
	}

        return -1;
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

		if (opts->bind_addr) {
			ret = bind_client_socket(opts, fd);
			if (ret != 0) {
				pr_debug("Cannot bind");
				close(fd);
				continue;
			}
		}


		/* Connect to peer
		 ** There are three advantages to call connect for all types
		 ** of our socket protocols (especially udp)
		 **
		 ** 1. We don't need to specify a destination address (only call write)
		 ** 2. Performance advantages (kernel level)
		 ** 3. Error detection (e.g. destination port unreachable at udp)
		 */
		ret = (int)connect(fd, addrtmp->ai_addr, addrtmp->ai_addrlen);
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

static void die_version(void)
{
	printf(PROGRAMNAME " - " VERSIONSTRING "\n");
	exit(EXIT_SUCCESS);
}


static void print_usage(const char *me)
{
	fprintf(stdout, "%s <options>\n"
			"Options:\n"
			"   --ipv4 (-4)\n\tenforces to use AF_INET socket (default AF_UNSPEC)\n"
			"   --ipv6 (-6)\n\tenforces to use AF_INET6 socket (default AF_UNSPEC)\n"
			"   --hostname (-e) <hostname>\n\tspecify the destination host\n"
                        "   --port (-p) <port>\n\tdestination port of connection (default: 5001) \n"
			"   --interval (-i)\n\tinterval between the generation (and reception) of packets in us\n"
			"   --iterations (-n) <number>\n\tlimit the number of transmissions\n"
			"   --txpacketsize (-s) <number>\n\tsize of the generated packet (excluding TCP/IP header)\n"
			"   --rxpacketsize (-r) <number>\n\tsize of the received packet (excluding TCP/IP header)\n"
			"   --server-delay (-d) <number>\n\tnumber of us until the server echo the data back\n"
			"   --server-delay-variation (-D) <number>\n\tnumber of additional us which are random add the server echo the data back\n"
			"   --check (-c)\n\tcheck payload for bit errors\n"
			"      \tNote: only valid if payload pattern == static\n"
			"   --setsockopt (-S) <option:arg1:arg2:...>\n\tset the socket option \"option\" with argument arg1, arg2, ...\n"
                        "   --random (-R) <min (byte):max (byte):bw (bit/s)>\n\tgenerator to generate randomly generated traffic pattern\n"
			"      \t(e.g. -R 100:500:5000kbit)\n"
                        "   --payload-pattern <static | ascii-random | random>\n\tconfigures the packet payload pattern\n"
                        "   --bind (b) <address>\n\tbind socket to local address\n"
			"   --verbose (-v)\n\tverbose output to STDOUT\n"
			"\n"
			"Examples:\n"
			"   ipproof-client -4 -vv -e example.com -r 0 -t udp -R 1000:1000:5000kbit\n"
			"   IPv4/UDP to example.com, no data back, send 1000byte packet with 5000kbit/s\n"
			"\n", me);
}

/* in MBit */
#define	MAX_BANDWIDTH 1000

static int setup_random_traffic(struct opts *opts, int min, int max, long long bw)
{
	/* sanity checks first */
	if (min < (int)sizeof(struct header_extended) || min > MAX_UDP_DATAGRAM) {
		err_msg("packet minimum is unacceptable. Is %d, must %d - %d",
				min, sizeof(struct header_extended), MAX_UDP_DATAGRAM);
		return FAILURE;
	}

	if (max < (int)sizeof(struct header_extended) || max > MAX_UDP_DATAGRAM) {
		err_msg("packet maximum is unacceptable. Is %d, must %d - %d",
				max, sizeof(struct packet), MAX_UDP_DATAGRAM);
		return FAILURE;
	}

	if (min > max) {
		err_msg("packet minimum %d is larger as maximum %d", min, max);
		return FAILURE;
	}

	if (bw <= 0 || (bw / FACTOR_US_S) > MAX_BANDWIDTH) {
		err_msg("bandwidth is unacceptable: %d bit/s (must between %d and %d)",
				bw, 0, MAX_BANDWIDTH * FACTOR_US_S);
		return FAILURE;
	}

	msg("random traffic generator [min %d byte, max: %d byte, bandwidth: %d bit/s]",
			min, max, bw);

	opts->random_min = min;
	opts->random_max = max;
	opts->random_bandwidth = (unsigned int)bw;

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
	if (!token) {
		ret = FAILURE;
		goto out;
	}

	bw = a_to_bit_s(token);
	if (bw < 0) {
		ret = FAILURE;
		goto out;
	}

	if (setup_random_traffic(opts, min, max, bw) != SUCCESS) {
		ret = FAILURE;
		goto out;
	}

	opts->random_enabled = 1;

	ret = SUCCESS;

out:
	free(cp);

	return ret;
}


static void print_opts(struct opts *opts)
{
	msg("ipproof options:");
	msg("  Network protocol:\t\t%s", opts->af_family==2 ? "IPv4" : "IPv6");
	msg("  Verbose:\t\t%d",          opts->verbose_level);
	msg("  Hostname:\t\t%s",         opts->hostname);
	msg("  Interval:\t\t%d",         opts->packet_interval);
	msg("  Iterations:\t\t%d",       opts->iterations);
	msg("  Txpacketsize:\t\t%d",     opts->tx_packet_size);
	msg("  Rxpacketsize:\t\t%d",     opts->rx_packet_size);
	msg("  Port:\t\t\t%s",           opts->port);
	msg("  Payload-pattern:\t%s", opts->payload_pattern == 0 ? "static" :
								  (opts->payload_pattern == 1 ? "random" : "random-ascii"));
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
	opts->bind_addr        = NULL;
	opts->payload_pattern  = DEFAULT_PAYLOAD_PATTERN;

	while (1) {
		static struct option long_options[] = {
			{"ipv4",            0, 0, '4'},
			{"ipv6",            0, 0, '6'},
			{"verbose",         0, 0, 'v'},
			{"version",         0, 0, 'V'},
			{"hostname",        1, 0, 'e'},
			{"interval",        1, 0, 'i'},
			{"iterations",      1, 0, 'n'},
			{"txpacketsize",    1, 0, 's'},
			{"rxpacketsize",    1, 0, 'r'},
			{"server-delay",    1, 0, 'd'},
			{"server-delay-variation",  1, 0, 'D'},
			{"port",            1, 0, 'p'},
			{"check",           0, 0, 'c'},
			{"help",            0, 0, 'h'},
			{"transport",       1, 0, 't'},
			{"setsockopt",      1, 0, 'S'},
			{"random",          1, 0, 'R'},
            {"bind",            1, 0, 'b'},
            {"payload-pattern", 1, 0, 'P'},
			{0, 0, 0, 0}
		};
                c = xgetopt_long(ac, av, "t:i:s:t:e:p:P:n:d:D:r:S:R:b:vhc46V",
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
			case 'V':
				die_version();
				break;
			case 'i':
				opts->packet_interval = atoi(optarg);
				break;
			case 'n':
				opts->iterations = atoi(optarg);
				opts->iteration_limit_enabled = 1;
				break;
			case 'b':
				opts->bind_addr = strdup(optarg);
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
			case 'P':
				if (!strcasecmp("static", optarg)) {
					opts->payload_pattern  = PAYLOAD_PATTERN_STATIC;
				} else if (!strcasecmp("random", optarg)) {
					opts->payload_pattern  = PAYLOAD_PATTERN_RANDOM;
				} else if (!strcasecmp("ascii-random", optarg)) {
					opts->payload_pattern  = PAYLOAD_PATTERN_RANDOM_ASCII;
				} else {
					err_msg("payload pattern %s not supported!", optarg);
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

	if (opts->tx_packet_size < (int)sizeof(struct header_minimal)) {
		err_msg("tx_packet_size require at least %u byte of data (due to minimal header requirement)",
		        sizeof(struct packet));
		exit(EXIT_FAILOPT);
	}

	if (opts->random_enabled && opts->ai_protocol != IPPROTO_UDP)
		err_msg_die(EXIT_FAILOPT, "random option only useful for UDP sockets (-t udp)");

	if (opts->check_payload && opts->payload_pattern  != PAYLOAD_PATTERN_STATIC) {
		err_msg_die(EXIT_FAILOPT, "check option only valid with static payload pattern!");
	}

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
	delay = (int)(((double)avg / (((double)opts->random_bandwidth) / 8)) * FACTOR_US_S);

	msg("packet delay: %d usec [avg-packet-size: %d byte   bw: %d bits/s]",
		delay, avg, opts->random_bandwidth);

	if (delay < 0 || delay > 100000000) {
		err_msg("delay to large: is %d and should between 0 and 100000000)"
				". Adjusting to 1000000", delay);
		delay = 100000000;
	}

	return delay;
}


static double measurement_start, measurement_end;
unsigned long bytes_sent, bytes_received;


void print_throughput(void)
{
        unsigned long tx_throughput, rx_throughput;
        double delta_time;

        delta_time = measurement_end - measurement_start;

        if (bytes_sent)
                tx_throughput = (unsigned long)((bytes_sent * 8) / delta_time);
        else
                tx_throughput = 0;

        if (bytes_received)
                rx_throughput = (unsigned long)((bytes_received * 8) / delta_time);
        else
                rx_throughput = 0;

        msg("TX: %lu bytes in %.3lf seconds, throughput: %lu bit/s",
                bytes_sent, delta_time, tx_throughput);
        msg("RX: %lu bytes in %.3lf seconds, throughput: %lu bit/s",
                bytes_received, delta_time, rx_throughput);
}



#if defined(WIN32)
static BOOL WINAPI console_ctrl_handler(DWORD signum)
{
        switch (signum)
        {
        case CTRL_C_EVENT:
                break;
        case CTRL_BREAK_EVENT:
                break;
        case CTRL_CLOSE_EVENT:
                break;
        case CTRL_LOGOFF_EVENT:
                break;
        case CTRL_SHUTDOWN_EVENT:
                break;
        }

	measurement_end = xgettimeofday();
        print_throughput();

        return FALSE;
}
#else
static void signal_callback_handler(int signum)
{
		measurement_end = xgettimeofday();
		print_throughput();
		exit(0);
}
#endif


static void init_packet_payload(struct opts *opts, int header_format, char *packet)
{
	int header_size;
        unsigned int i;
        char *blob;
        struct header_extended *he;
        struct header_minimal *hm;

        switch (header_format) {
        case HEADER_FORMAT_MINIMAL:
                hm = (struct header_minimal *)packet;
                blob = hm->data;
                header_size = (int)sizeof(struct header_minimal);
                break;
        case HEADER_FORMAT_EXTENDED:
                he = (struct header_extended *)packet;
                blob = he->data;
                header_size = (int)sizeof(struct header_extended);
                break;
        default:
                err_msg_die(EXIT_FAILURE, "Programmed error");
                break;
        }


	switch (opts->payload_pattern) {
	case PAYLOAD_PATTERN_RANDOM:
		for (i = 0; i < opts->tx_packet_size - header_size; i++)
			blob[i] = (char)(rand());
		break;
	case PAYLOAD_PATTERN_RANDOM_ASCII:
		for (i = 0; i < opts->tx_packet_size - header_size; i++)
			blob[i] = (char)(rand_range('a', 'z'));
		break;
	case PAYLOAD_PATTERN_STATIC:
		memset(blob, PAYLOAD_BYTE_PATTERN, opts->tx_packet_size - header_size);
		break;
	default:
		err_msg_die(EXIT_FAILOPT, "programmed error");
		break;
	}
}


static void register_ctrl_handler(void)
{
#if defined(WIN32)
	SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
#else
	signal(SIGINT, signal_callback_handler);
#endif
}


static char *construct_extended_packet(struct opts *opts)
{
        char *packet;
        struct header_extended *header_extended;

        packet = xzalloc(opts->tx_packet_size);
        header_extended = (struct header_extended *)packet;

        header_extended->preambel = PREAMBEL_COOKIE;
        header_extended->preambel = header_extended->preambel | PREAMBEL_EXTENDED_HEADER;

        header_extended->flow_id = (be16)xrand();
        header_extended->sequence_number = 0;

        header_extended->data_length_tx = htonl(opts->tx_packet_size);
        header_extended->data_length_rx = htonl(opts->rx_packet_size);

        header_extended->server_delay     = htons(opts->server_delay);
        header_extended->server_delay_var = htons(opts->server_delay_var);

        return packet;
}


static char *construct_minimal_packet(struct opts *opts)
{
        char *packet;
        struct header_minimal *header_minimal;

        packet = xzalloc(opts->tx_packet_size);
        header_minimal = (struct header_minimal *)packet;

        header_minimal->preambel =PREAMBEL_COOKIE;

        header_minimal->flow_id = (uint8_t)rand();
        header_minimal->sequence_number = 0;
        header_minimal->data_length_tx = htonl(opts->tx_packet_size);
        header_minimal->data_length_rx = htons((int16_t)opts->rx_packet_size);

        if (opts->verbose_level)
                msg("usable payload size below %d bytes, use minimal header encoding",
                    sizeof(struct header_extended));

        return packet;
}


static print_header_summary(int header_format, char *packet)
{
        struct header_minimal *hm;
        struct header_extended *he;

        switch (header_format) {
        case HEADER_FORMAT_MINIMAL:
                hm = (struct header_minimal *)packet;
                break;
        case HEADER_FORMAT_EXTENDED:
                he = (struct header_extended *)packet;
                break;
        }
}


int main(int ac, char **av)
{
	int socket_fd, ret, delay_target = 0;
	size_t sret;
	char *data_rx = 0;
	struct opts opts;
	double start, end, last_packet_time;
	unsigned long counter = 0, printout_level = 100;
        char *blob;
        int header_format;

	init_network_stack();

	ret = xgetopts(ac, av, &opts);
	if (ret != SUCCESS)
		err_msg_die(EXIT_FAILOPT, "failure in commandline options");

	print_opts(&opts);

	msg(PROGRAMNAME " - " VERSIONSTRING);

        if (opts.verbose_level > 2)
                printout_level = 1;


        if (opts.tx_packet_size >= sizeof(struct header_extended)) {
                header_format = HEADER_FORMAT_EXTENDED;
                blob = construct_extended_packet(&opts);
        } else {
                header_format = HEADER_FORMAT_MINIMAL;
                blob = construct_minimal_packet(&opts);
        }

        init_packet_payload(&opts, header_format, blob);
        

	//packet = xzalloc(opts.tx_packet_size);

	/* subtracting header overhead */
	//opts.tx_packet_size -= sizeof(struct packet);


	//packet->magic            = MAGIC_COOKIE;
	//packet->sequence_no      = 0;
	//packet->data_len_tx      = htons(opts.tx_packet_size);
	//packet->data_len_rx      = htons(opts.rx_packet_size);
	//packet->server_delay     = htons(opts.server_delay);
	//packet->server_delay_var = htons(opts.server_delay_var);

	/* this is a simple buffer container. Received data is
	 * written there */
	if (opts.rx_packet_size)
		data_rx = xzalloc(opts.rx_packet_size);

	if (is_random_traffic_enabled(&opts))
		delay_target = calculate_random_traffic_delay(&opts);

	//init_packet_payload(&opts, packet);

#if 0
        if (opts.tx_packet_size >= sizeof(struct extended_header)) {
                struct extended_header *eh;
                packet->magic |= EXTENDED_COOKIE_PATTERN;
                eh = packet->data;
                eh->data_len_tx = htonl(opts.tx_packet_size);
                eh->data_len_rx = htonl(opts.rx_packet_size);
                eh->sequence_no = 0;
                eh->id = 
        }
#endif


	/* connect to server */
	socket_fd = init_cli_socket(&opts);

	register_ctrl_handler();

	measurement_start = last_packet_time = xgettimeofday();


        print_header_summary(header_format, blob);

	while (!opts.iteration_limit_enabled || opts.iterations--) {
		int adjust;
		if (opts.verbose_level && counter % printout_level == 0) {
			msg("transmit packet %u of size %d [byte]", counter,
					opts.tx_packet_size);
		}

		bytes_sent += opts.tx_packet_size;

		start = xgettimeofday();

		adjust = (int)(delay_target - ((start - last_packet_time) * FACTOR_US_S));

		if (adjust > 0)
			opts.packet_interval = adjust;

		if (opts.packet_interval > 0) {
			if (opts.verbose_level > 1)
				msg("delay transmission of next packet for %u us", opts.packet_interval);
			xusleep(opts.packet_interval);
		}

		ret = tx_data(&opts, header_format, blob, socket_fd, counter);
		if (ret != SUCCESS)
			break;

		last_packet_time = xgettimeofday();

                if (header_format == HEADER_FORMAT_MINIMAL) {
                        struct header_minimal *hm;
                        hm = (struct header_minimal *)blob;
                        hm->sequence_number = htons(ntohs((int16_t)hm->sequence_number) + 1);
                } else {
                        struct header_extended *he;
                        he = (struct header_extended *)blob;
                        he->sequence_number = htonl(ntohl(he->sequence_number) + 1);
                }

		/* wait and read data from server */
		if (opts.rx_packet_size) {

			if (opts.verbose_level > 1)
				msg("  block in read (waiting for %u bytes)",
						opts.rx_packet_size);
			sret = read_len(socket_fd, data_rx, opts.rx_packet_size);
			if (sret != (size_t) opts.rx_packet_size) {
				err_msg("failure in socket read (data)");
				break;
			}

			bytes_received += opts.rx_packet_size;

			end = xgettimeofday();

			if (opts.verbose_level > 1) {
				msg("  received %u byte payload [application layer RTT: %.6lf ms]",
						opts.rx_packet_size, end - start);
			}

#if 0
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

#endif

		}

		counter++;

	}

	measurement_end = xgettimeofday();

	xclose(socket_fd);
	free(opts.port);

	fini_network_stack();

	print_throughput();

	return EXIT_SUCCESS;
}

