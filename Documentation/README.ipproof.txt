ipproof(1)
==========

NAME
----

ipproof-client - Client application of the ip proof application
ipproof-server - Server application of the ip proof application


SYNOPSIS
--------

'ipproof-client' [-v] [-h] [-b] [-4] [-6] [-t <protocol>] [-i <interval-time>] [-p <port>]
              [-n <iterations>] [-d <server-delay>] [-D <server-delay-variation>]
              [-c ] [-S <socketoption>] [-R <min:max:bw>] [-s <tx-packet-size>]
              [-r <rx-packet-size>] [-c <enable | disable>]
              -e <hostname>

'ipproof-server' [-v] [-h] [-4] [-6]



DESCRIPTION
-----------
The server component (server) is the passive component of the IP proof test application.
The server component must be start before the client is started. The server will bind to the
the assigned port (default: 5001) and wait for incoming packets. Each packet has a own protocol
header. In this header additional information are encoded. For example if the server shall piggy
back the information to the client. If yes this will emulate a typical echo client server
application similar to RFC 862.


CLIENT OPTIONS
--------------

The following options are client side options.

-v::
--verbose::
          Verbose output. Prints more messages and intrinsic information to STDOUT

-h::
--help::
          Print help screen and exit.

-4::
--ipv4::
          Enforce the use of IPv4. Default depends on the host operating system
          and the system wide configuration.

-6::
--ipv6::
          Enforce the use of IPv6. Default depends on the host operating system
          and the system wide configuration.

-t <protocol>::
--transport <protocol>::
          Selects the transport protocol where <protocol> can be UDP or TCP.
          Default is UDP.

-c::
--check::
          Check the integrity of received data and terminate programm if
          check detect a failure. Default is to check the integrity of data
          packets.

-i <interval-time>::
--interval <interval-time>::
          Wait interval in microseconds (usec) between two packets. The default
          is 1000000 us (1 sec). Option -R will overwrite this option.

-p <port>::
--port <port>::
          Port where the server and client meet each other. Default port is 6666.

-e <hostname>::
--destination <hostname>::
          Destination address of the server. This can be a numeric IPv4/IPv6 (127.0.0.1, ::1)
          address or a hostname (e.g. localhost). Hostnames may require a dynamic DNS resolver
          and a functioning and configured DNS system. The hostname is a required argument.

-s <size>::
--txpacketsize <size>::
          Packet size in bytes of the payload send to the server. This excludes the Network layer and Transport
          layer protocol overhead. Network layer protocol overhead includes the standard IPv4
          or IPv6 header (including potential IPv4 options or IPv6 extension header) and the
          transport protocol header overhead (UDP or TCP).

-t <size>::
--rxpacketsize <size>::
          Packet size in bytes of the payload send from server to client. This excludes the
          Network layer and Transport layer protocol overhead. Network layer protocol overhead
          includes the standard IPv4 or IPv6 header (including potential IPv4 options or IPv6
          extension header) and the transport protocol header overhead (UDP or TCP).

-d <usec>::
--server-delay <msec>::
          Server delay in milliseconds between two successive packets send
          from the server to the client. Default is to wait 0 second.

-D <usec>::
--server-delay-variance <msec>::
          Variacnce in milliseconds between two seccussice packets. This
          options can be used to introduce an artificial behavior. E.g.
          emulate WEB server processing delay et cetera.

-S <arg:opt1:opt2>::
--setsockopt <arg:opt1:opt2>::
          Set the socket option for the socket like TCP_QUICKACK, TCP_QUICKACK, and
          so on. The specification and which options are availabe differs from plattform to
          plattform.  Via "-S help" all valid socket options can be displayed!

-R <min:max:bw>::
--random <min:max:bw>::
          The random option was introduced to a) specify a fix bandwidth (min
          and max can be identical) and b) to stress test a particular traffic
          pattern. Min and max are bytes where the bandwidth argument must be
          suffixed (e.g. kB, kbyte, Mbyte, ....). E.g. "530:1470:10kB"

SERVER OPTIONS
--------------

The following options are server side options.

-v::
--verbose::
          Verbose output.

-h::
--help::
          Print help screen and exit.

-4::
--ipv4::
          Enforce the use of IPv4. Default depends on the host operating system
          and the system wide configuration.

-6::
--ipv6::
          Enforce the use of IPv6. Default depends on the host operating system
          and the system wide configuration.

EXAMPLES
--------

Start server and explicit bind to a IPv4 address. The server will generate
output messages about the status of incoming packets.

------------
$ ./server -4
------------

Start client and send each second a packet with size 1000 byte. This example
assume that the server application runs at the same machine (127.0.0.1). NOTE:
the 1000 bytes are based on the application layer. During transport a IPv4 and UDP
header are generated and added to the packet. If the packet is transported via Ethernet
a Ethernet header (14 byte) are added too.

------------
$ ./client -4 -e -i 1 -s 1000 127.0.0.1
------------

To generate random traffic pattern the following option can be selected

------------
$ ./server -6 -t udp
------------

------------
$ ./client -6 -t udp -r 0 -R 530:1470:10kB -e 2a01:198:200:576::1
------------



Author
------
Written by Hagen Paul Pfeifer
WWW: http://jauu.net
EMail: hagen@jauu.net


Licence
-------
ipproof is licensed under the GPLv2


Documentation
--------------
Documentation by Hagen Paul Pfeifer <hagen@jauu.net>.

