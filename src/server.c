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
#include <math.h>


#define DEFAULT_PACKET_SIZE 1000
#define DEFAULT_PACKET_INTERVAL 1

extern struct socket_options socket_options[];

struct conn_data {
	unsigned int sequence_no;
	int sequence_initialized;
        unsigned long raw_bytes_read;
        unsigned long raw_bytes_send;
};

struct opts {
	char *port;
        char *bind_addr;
	unsigned packet_size;
	unsigned packet_interval;
	unsigned verbose_level;
	unsigned iterations;
	int iteration_limit;
	int af_family;
	int ai_socktype;
	int ai_protocol;
};


struct packet_data {
        unsigned int data_len_tx;
        unsigned int data_len_rx;
        unsigned int flow_id;
        unsigned int sequence_no;
        unsigned int server_delay;
        unsigned int server_delay_var;
};


/* Returns 0 for success or negative error code for error.
 * This function can be used for minimal or extended header
 * because the first byte is identical */ 
static int verify_cookie(struct opts *opts, char *packet, int *header_format, int *flow_end)
{
        char cookie;
        struct header_minimal *hm;

        hm = (struct header_minimal *)packet;
        cookie = packet[0];

        if (!PREAMBEL_COOKIE_IS_VALID(cookie)) {
                return -ENOSPC;
        }

        if (PREAMBEL_EXTENDED_HEADER_IS(cookie))
                *header_format = HEADER_FORMAT_EXTENDED;
        else
                *header_format = HEADER_FORMAT_MINIMAL;


        if (PREAMBEL_FLOW_END_IS(cookie))
                *flow_end = 1;
        else
                *flow_end = 0;

        if (VERBOSE_ULTRA(opts->verbose_level)) {
                msg("      cookie information [extended header: %s, flow end indicator: %s, cookie: correct]",
                    *header_format == HEADER_FORMAT_MINIMAL ? "minimal" : "extended",
                    *flow_end == 1 ? "yes" : "no");
        }

        return 0;
}


static int parse_header_data(struct opts *opts, struct packet_data *pd, char *buf, int header_format)
{
        struct header_minimal *hm;
        struct header_extended *he;

        memset(pd, 0, sizeof(*pd));

        switch (header_format) {
        case HEADER_FORMAT_MINIMAL:
                hm = (struct header_minimal *)buf;
                pd->data_len_tx      = ntohl(hm->data_length_tx);
                pd->data_len_rx      = ntohs(hm->data_length_rx);
                pd->sequence_no      = ntohs(hm->sequence_number);
                pd->flow_id          = hm->flow_id;
                pd->server_delay     = 0;
                pd->server_delay_var = 0;
                break;
        case HEADER_FORMAT_EXTENDED:
                he = (struct header_extended *)buf;
                pd->data_len_tx      = ntohl(he->data_length_tx);
                pd->data_len_rx      = ntohl(he->data_length_rx);
                pd->sequence_no      = ntohl(he->sequence_number);
                pd->flow_id          = ntohs(he->flow_id);
                pd->server_delay     = ntohs(he->server_delay);
                pd->server_delay_var = ntohs(he->server_delay_var);
                break;
        default:
                err_msg_die(EXIT_FAILNET, "Unknown header -> programmed error");
        }

        if (VERBOSE_EXTENSIVE(opts->verbose_level)) {
                msg("    header info [data-tx: %u, data-rx: %u, flow-id: %u, seq-no: %u, delay: %u, delay-var: %u]",
                    pd->data_len_tx, pd->data_len_rx, pd->flow_id, pd->sequence_no,
                    pd->server_delay, pd->server_delay_var);
        }

        return 0;
}


static void server_sleep(struct opts *opts, struct packet_data *packet_data)
{
        int sleep_time;

        if (packet_data->server_delay == 0 && packet_data->server_delay_var == 0)
                return;

        sleep_time = packet_data->server_delay;

        if (packet_data->server_delay_var) {
                sleep_time += rand_range(-((int)packet_data->server_delay_var), (int)packet_data->server_delay_var);
        }
        
        if (VERBOSE_EXTENSIVE(opts->verbose_level))
                msg("    sleep for %u ms [delay %d, delay-var: %d]",
                    sleep_time, packet_data->server_delay, abs(packet_data->server_delay - sleep_time));
        
        msleep(sleep_time);
}


static void check_sequence_number(struct packet_data *packet_data, struct conn_data *conn_data)
{

        if (!conn_data->sequence_initialized) {
                conn_data->sequence_no = packet_data->sequence_no;
                conn_data->sequence_initialized++;
                return;
        }

        if (++conn_data->sequence_no != packet_data->sequence_no) {
                msg("ERROR: drift in sequence number detected - (should %u, is: %u)",
                    conn_data->sequence_no, packet_data->sequence_no);
        }
}


static int rx_tx_data_tcp(int fd, struct conn_data *conn_data, struct opts *opts)
{
        int ret, flow_end, header_format = HEADER_FORMAT_MINIMAL;
        char *buf_tx, *buf_rx, packet_header[sizeof(struct header_extended)];
        size_t header_size;
        struct packet_data packet_data;

        if (VERBOSE_NORMAL(opts->verbose_level))
                msg("  try to read next message");

        if (VERBOSE_ULTRA(opts->verbose_level)) {
                msg("      read header cookie/preambel of 1 byte");
        }

        ret = (int)read_len(fd, packet_header, 1);
        if (ret != 1) {
                xclose(fd);
                return FAILURE;
        }

        ret = verify_cookie(opts, packet_header, &header_format, &flow_end);
        if (ret != 0) {
                msg("Cookie not valid!");
                return FAILURE;
        }

        /* minimal or extended header encoding? */
        header_size = header_format == HEADER_FORMAT_MINIMAL ?
                      sizeof(struct header_minimal) : sizeof(struct header_extended);

        if (VERBOSE_ULTRA(opts->verbose_level)) {
                msg("      try to read header of %d byte", header_size);
        }

        /* we subtract by 1 because we already read the very first
         * byte (the cookie aka preambel) */
        ret = (int)read_len(fd, packet_header + 1, header_size - 1);
        if (ret != header_size - 1) {
                msg("Failed to read complete header of length %d", header_size - 1);
                return FAILURE;
        }

        ret = parse_header_data(opts, &packet_data, packet_header, header_format);
        if (ret != 0) {
                msg("packet header format malformed");
                return FAILURE;
        }


        conn_data->raw_bytes_read += (unsigned long)header_size;


        check_sequence_number(&packet_data, conn_data);

        packet_data.data_len_tx -= (unsigned int)header_size;
        buf_rx = xzalloc(packet_data.data_len_tx);

        if (VERBOSE_EXTENSIVE(opts->verbose_level)) {
                msg("    read %u bytes of data from client",
                    packet_data.data_len_tx);
        }
        ret = (int)read_len(fd, buf_rx, packet_data.data_len_tx);
        if (ret != (int)packet_data.data_len_tx) {
                err_msg("failure in read from client: expect %u byte, read %u byte",
                        packet_data.data_len_tx, ret);
                goto err_rx;
        }

        conn_data->raw_bytes_read += ret;

        /*
         * it the client enforce artificial server delay and/or server
         * delay variation we will sleep here for the given amount
         * of time
         */
        server_sleep(opts, &packet_data);

        if (packet_data.data_len_rx > 0) {

                buf_tx = xzalloc(packet_data.data_len_rx);
                memset(buf_tx, PAYLOAD_BYTE_PATTERN, packet_data.data_len_rx);

                /* write data_len data back to the client */
                if (VERBOSE_NORMAL(opts->verbose_level))
                        msg("  write %u byte of data back to the client", packet_data.server_delay);

                ret = (int)write_len(fd, buf_rx, packet_data.data_len_rx);
                if (ret != SUCCESS) {
                        msg("Failed to send data back! This should NOT happened");
                        goto err_tx;
                }

                conn_data->raw_bytes_send += packet_data.data_len_rx;
        }


        if (packet_data.data_len_rx > 0)
                free(buf_tx);
        free(buf_rx);

        return SUCCESS;

err_tx:
        free(buf_tx);
err_rx:
        free(buf_rx);
        xclose(fd);
        return FAILURE;
}


static double start, now, last_output;
static int unitilized;
static unsigned long no_run;
static unsigned bytes_received;

static void reset_state(double now)
{
        bytes_received = 0;
        no_run         = 0;
        last_output = start = now;
}


static void process_cli_request_udp(struct opts *opts, int server_fd)
{
	ssize_t sret; int ret, flags = 0;
	struct sockaddr_storage sa;
	socklen_t sa_len = sizeof(sa);
	char *data_rx;
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	static char buf[MAX_UDP_DATAGRAM];
        struct header_minimal *hm;
        struct header_extended *he;
	unsigned int sequence_no;
	uint32_t data_len_tx, data_len_rx;
	uint16_t server_delay, server_delay_var;
        int header_format, flow_end;
        int flow_id;

	sret = recvfrom(server_fd, (char *)&buf, sizeof(buf), flags,
			(struct sockaddr *)&sa, &sa_len);
	if (sret < 0) {
		err_sys("failure in recvfrom() - return code %d", sret);
		return;
	}

	now = xgettimeofday();

	if (sret < (int)sizeof(*hm)) {
		err_msg("packet to small (is %d byte, must at least %u byte",
				sret, sizeof(*hm));
		return;
	}

        ret = verify_cookie(opts, buf, &header_format, &flow_end);
        if (ret != 0) {
                err_msg("Packet with invalid cookie received - ignore packet");
                reset_state(now);
                return;
        }

	/* accounting */
	bytes_received += (unsigned int)sret;

        switch (header_format) {
        case HEADER_FORMAT_MINIMAL:
                hm = (struct header_minimal *)buf;
                data_len_tx = ntohl(hm->data_length_tx);
                data_len_rx = ntohs(hm->data_length_rx);
                sequence_no = ntohs(hm->sequence_number);
                flow_id     = hm->flow_id;
                server_delay = 0;
                server_delay_var = 0;
                break;
        case HEADER_FORMAT_EXTENDED:
                he = (struct header_extended *)buf;
                data_len_tx = ntohl(he->data_length_tx);
                data_len_rx = ntohl(he->data_length_rx);
                sequence_no = ntohl(he->sequence_number);
                flow_id     = ntohs(he->flow_id);
                server_delay = ntohs(he->server_delay);
                server_delay_var = ntohs(he->server_delay_var);
                break;
        default:
                err_msg_die(EXIT_FAILNET, "Unknown header -> programmed error");
                reset_state(now);
                return;
        }


	if (sequence_no == 0) {
		/* new UDP client connection, we reset everything */
		bytes_received = 0;
		no_run = 0;
		last_output = start = now;

		if (opts->verbose_level > 0) {
			ret = getnameinfo((struct sockaddr *)&sa, sa_len, hbuf,
					NI_MAXHOST, sbuf, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
			if (ret != 0)
				err_msg_die(EXIT_FAILNET, "getnameinfo error: %s",  gai_strerror(ret));

                        msg("new connections from %s:%s [flow-id: %d, %s]", hbuf, sbuf,
                            flow_id,
                            header_format == HEADER_FORMAT_MINIMAL ?
                                "minimal header encoding" : "extended header encoding");
		}
	}

	/* print output for every received packet if verbose
	 * is a little bit verboser[TM] */
	if (opts->verbose_level >= 1) {
		ret = getnameinfo((struct sockaddr *)&sa, sa_len, hbuf,
				NI_MAXHOST, sbuf, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
		if (ret != 0)
			err_msg_die(EXIT_FAILNET, "getnameinfo error: %s",  gai_strerror(ret));

		msg("received %d bytes from %s:%s [seq #: %d]", sret, hbuf, sbuf, sequence_no);
	}

	if (opts->verbose_level && ((int)last_output != (int)now)) {
		msg("RX: %lu bytes in %.3lf seconds, throughput: %ld bit/s",
				bytes_received, now - last_output, (unsigned)((bytes_received * 8) / (now - start)));
		start = now;
		last_output = now;
		bytes_received = 0;

	}

	if (data_len_rx > 0) {

		data_rx = xzalloc(data_len_rx);
		memset(data_rx, PAYLOAD_BYTE_PATTERN, data_len_rx);

		if (server_delay > 0) {
			msg("   sleep for %u ms", server_delay);
			/* FIXME: add variation */
			msleep(server_delay);
		}

		/* write data_len data back to the client */
		if (opts->verbose_level > 1)
			msg("   write %u byte of data back to the client", data_len_rx);
		sendto(server_fd, data_rx, data_len_rx, 0,(struct sockaddr *)&sa, sa_len);

		free(data_rx);
	}

	no_run++;
}

static void print_throughput(struct conn_data *conn_data, double measurement_start, double measurement_end)
{
        unsigned long tx_throughput, rx_throughput;
        double delta_time;

        delta_time = measurement_end - measurement_start;

        if (conn_data->raw_bytes_send)
                tx_throughput = (unsigned long)((conn_data->raw_bytes_send * 8) / delta_time);
        else
                tx_throughput = 0;

        if (conn_data->raw_bytes_read)
                rx_throughput = (unsigned long)((conn_data->raw_bytes_read * 8) / delta_time);
        else
                rx_throughput = 0;

        msg("TX: %lu bytes in %.3lf seconds, throughput: %lu bit/s",
                conn_data->raw_bytes_send, delta_time, tx_throughput);
        msg("RX: %lu bytes in %.3lf seconds, throughput: %lu bit/s",
                conn_data->raw_bytes_read, delta_time, rx_throughput);
}


static void process_cli_request_tcp(int server_fd, struct opts *opts)
{
	int connected_fd = -1, ret;
	struct sockaddr_storage sa;
	socklen_t sa_len = sizeof sa;
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	struct conn_data conn_data;
        double measurement_start, measurement_end;

	conn_data.sequence_initialized = 0;
        conn_data.raw_bytes_read = 0;
        conn_data.raw_bytes_send = 0;

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

	msg("connection established from %s:%s", hbuf, sbuf);

        measurement_start = xgettimeofday();

	while (rx_tx_data_tcp(connected_fd, &conn_data, opts) == SUCCESS)
		;

        measurement_end = xgettimeofday();

        print_throughput(&conn_data, measurement_start, measurement_end);
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

	xgetaddrinfo(opts->bind_addr, opts->port, &hosthints, &hostres);

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

		ret = bind(fd, addrtmp->ai_addr, (int)addrtmp->ai_addrlen);
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
				"Don't found a suitable socket to connect to the client"
				", giving up");

	msg("bind to port %s via %s using %s socket [%s:%s]",
			opts->port, network_protocol_str(opts->ai_protocol),
			network_family_str(addrtmp->ai_family),
			addrtmp->ai_family == AF_INET ? "0.0.0.0" : "::", opts->port);

	freeaddrinfo(hostres);

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
                "  --port, -p <port>\n"
                "  --protocol, -t <tcp | udp> \n"
                "  --bind, -b <bind-addr>\n\tlocal address to bind on\n"
                "  --setsockopt (-S) <option:arg1:arg2:...>\n\tset the socketoption \"option\" with argument arg1, arg2, ...\n"
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
        opts.bind_addr        = NULL;

	init_network_stack();

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"verbose",      0, 0, 'v'},
			{"version",      0, 0, 'V'},
			{"ipv4",         1, 0, '4'},
			{"ipv6",         1, 0, '6'},
			{"port",         1, 0, 'p'},
			{"help",         1, 0, 'h'},
			{"transport",    1, 0, 't'},
			{"setsockopt",   1, 0, 'S'},
                        {"bind",         1, 0, 'b'},
			{0, 0, 0, 0}
		};
                c = xgetopt_long(ac, av, "p:b:t:S:vh46V",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 'V':
				die_version();
				break;
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
                        case 'b':
                                opts.bind_addr = strdup(optarg);
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

	msg(PROGRAMNAME " - " VERSIONSTRING);

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
			process_cli_request_udp(&opts, socket_fd);
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
