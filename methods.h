#ifndef METHODS_H
#define METHODS_H

/* <--- Return flags ---> */
#define SCAN_OPENED 0
#define SCAN_CLOSED 1
#define SCAN_FILTERED_CLOSED 2
#define SCAN_PROBLEMS -1

/* <--- Pcap flags ---> */
#define UDP_FILTER "udp port"
#define TCP_FILTER "tcp port"
#define BUFSIZE_RECV 1024
#define ETHERNET_SIZE 14

/* <--- Selection flags ---> */
#define WO_PORT 0
#define WITH_PORT 1
#define WO_FLAG 0
#define WITH_FLAG 1

int scanTCP_SYN(const char *ip, const int port);

#endif