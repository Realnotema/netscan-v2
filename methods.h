#ifndef METHODS_H
#define METHODS_H

/* <--- Return flags ---> */
#define OPENED 0
#define CLOSED 1

/* <--- Pcap flags ---> */
#define UDP_FILTER "udp"
#define TCP_FILTER "port 2202"
#define BUFSIZE_RECV 1024
#define ETHERNET_SIZE 14

/* <--- Selection flags ---> */
#define WO_PORT 0
#define WITH_PORT 1
#define WO_FLAG 0
#define WITH_FLAG 1

int scanTCP_SYN(const char *destip, const int destport);

#endif