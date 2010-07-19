ipproof(1)
==========

NAME
----
ipproof-cli (client) - Client application of the ip proof application
ipproof-srv (server) - Server application of the ip proof application


SYNOPSIS
--------

'ipproof-cli' [-v] [-h] [-b] [-4] [-6] [-t <protocol>] [-c <count>] [-i <interval>] [-p <port>]
              [-e <hostname>] [-s <size>] [-c <enable | disable>]

'ipproof-srv' [-v] [-h] [-4] [-6]



DESCRIPTION
-----------
The server component (ipproof-src) is the passive component of the IP proof test application.
The server component must be start before the client is started. The server will bind to the
the assigned port (default: 6666) and wait for incoming packets. Each packet has a own protocol
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

-b::
--broadcast::
          Allow to send to a IPv4 broadcast address.

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

-c <count>::
--count <count>::
          Stop after <count> packets. Default is infinity: the client never
          stop the packet generation.

-i <interval>::
--interval <interval>::
          Wait interval seconds between sending each packet. The default
          is not to wait which itself generates at much packets then the host
          operating system is feasible.

-p <port>::
--port <port>::
          Port where the server and client meet each other. Default port is 6666.

-e <hostname>::
--destination <hostname>::
          Destination address of the server. This can be a numeric IPv4/IPv6 (127.0.0.1, ::1)
          address or a hostname (e.g. localhost). The hostname is a required argument.

-s <size>::
--size <size>::
          Packet size in bytes of the payload. This excludes the Network layer and Transport
          layer protocol overhead. Network layer protocol overhead includes the standard IPv4
          or IPv6 header (including potential IPv4 options or IPv6 extension header) and the
          transport protocol header overhead (UDP or TCP).

-c <enable | disable>::
--check <enable | disable>::
          Enable or disable the verification check of the payload at the server side. Default
          is to check the integrity of the data.


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
$ ipproof-srv -4
------------

Start client and send each second a packet with size 1000 byte. This example
assume that the server application runs at the same machine (127.0.0.1). NOTE:
the 1000 bytes are based on the application layer. During transport a IPv4 and UDP
header are generated and added to the packet. If the packet is transported via Ethernet
a Ethernet header (14 byte) are added too.

------------
$ ipproof-client -4 -e -i 1 -s 1000 127.0.0.1
------------


Author
------
Written by Hagen Paul Pfeifer
WWW: http://jauu.net
EMail: hagen@jauu.net


Licence
-------
ipprov is licensed under the GPLv2


Documentation
--------------
Documentation by Hagen Paul Pfeifer <hagen@jauu.net>.
