#include <libnet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include "methods.h"

int generate_random_port() {
    return rand() % 65534 + 1025;
}

int generate_session(Init *session, const char *ip) {
    char errbuf_pcap[PCAP_ERRBUF_SIZE];
    char errbuf_net[LIBNET_ERRBUF_SIZE];
    if (pcap_findalldevs(&session->device, errbuf_pcap) != 0) {
        fprintf(stderr, "=> No device: %s\n", errbuf_pcap);
        return SCAN_PROBLEMS;
    }
    session->lc = libnet_init(LIBNET_RAW4, session->device->name, errbuf_net);
    if (session->lc == NULL) {
        fprintf(stderr, "=> Can't initialise libnet: %s\n", errbuf_net);
        return SCAN_PROBLEMS;
    }
    session->tcp_tag = session->ip_tag = LIBNET_PTAG_INITIALIZER;
    session->ip_addr = libnet_name2addr4(session->lc, ip, LIBNET_DONT_RESOLVE);
    if (session->ip_addr == -1) {
        fprintf(stderr, "=> Problems with func name2addr4: %s\n", errbuf_net);
        return SCAN_PROBLEMS;
    }
    return SCAN_NEXT;
}

struct tcphdr *sniff_tcp(Init *session, int port) {
    struct bpf_program fp;
    pcap_t *handle;
    struct pcap_pkthdr header;
    const u_char *packet;
    struct tcphdr *tcp_header;
    int tcp_header_length;
    bpf_u_int32 net = 0, mask = 0;
    char errbuf_pcap[PCAP_ERRBUF_SIZE];
    char errbuf_net[LIBNET_ERRBUF_SIZE];
    char * filter = (char *) malloc(14 * sizeof(char));
    sprintf(filter, "%s %d", TCP_FILTER, port);
    handle = pcap_open_live(session->device->name, BUFSIZE_RECV, 1, 1000, errbuf_pcap);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", session->device->name, errbuf_pcap);
        return NULL;
    }
    if (pcap_lookupnet(session->device->name, &net, &mask, errbuf_pcap) == -1) {
        fprintf(stderr, "Can't get netmask for %s: %s\n", session->device->name, errbuf_pcap);
        return NULL;
    }
    if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
        fprintf(stderr, "Can't compile filter: %s\n", errbuf_pcap);
        return NULL;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Can't install filter: %s\n", errbuf_pcap);
        return NULL;
    }
    packet = pcap_next(handle, &header);
    if (packet == 0) {
        // May be filtered!
        return NULL;
    }
    struct ether_header *eth_header = (struct ether_header *)packet;
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl << 2));
    tcp_header_length = tcp_header->th_off;
    return tcp_header;
}

/* <--- Sending and sniffing TCP SYN packet --->*/
int scanTCP_SYN(const char *ip, const int port) {
    /* <--- Error bufers --->*/
    char errbuf_pcap[PCAP_ERRBUF_SIZE];
    char errbuf_net[LIBNET_ERRBUF_SIZE];

    /* <--- Pcap variables --->*/
    struct tcphdr *tcp;
    struct ip *iphdr;
    u_int size_ip;

    Init session;
    if (generate_session(&session, ip) == SCAN_PROBLEMS) {
        return SCAN_PROBLEMS;
    }
    /* <--- Sending packet --->*/
    session.tcp_tag = libnet_build_tcp(
        generate_random_port(),
        port,
        0,
        0,
        TH_SYN,
        1024,
        0,
        0,
        0,
        NULL,
        0,
        session.lc,
        session.tcp_tag
    );
    if (session.tcp_tag == -1) {
        fprintf(stderr, "=> TCP tag building problem: %s\n", errbuf_net);
        return SCAN_PROBLEMS;
    }
    if (libnet_autobuild_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, IPPROTO_TCP, session.ip_addr, session.lc) == -1) {
        fprintf(stderr, "=> IPv4 build problem: %s\n", errbuf_net);
        return SCAN_PROBLEMS;
    }
    int bytes_written = libnet_write(session.lc);
    if (bytes_written == -1) {
        fprintf(stderr, "=> Send problem: %s\n", errbuf_net);
        return SCAN_PROBLEMS;
    }
    libnet_destroy(session.lc);
    struct tcphdr *tcp_header = sniff_tcp(&session, port);
    if (tcp_header == NULL) {
        return SCAN_CLOSED;
    }
    if ((tcp_header->th_flags & TH_SYN) && (tcp_header->th_flags & TH_ACK)) {
        return SCAN_OPENED;
    } else {
        return SCAN_CLOSED;
    }
}