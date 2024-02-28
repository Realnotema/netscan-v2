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
    return rand() % 65535 + 1025;
}

/* <--- Sending and sniffing TCP SYN packet --->*/
int scanTCP_SYN(const char *destip, const int destport) {
    /* <--- Libnet variables --->*/
    char errbuf_net[LIBNET_ERRBUF_SIZE];
    libnet_ptag_t tcp_tag, ip_tag;
    u_int32_t ip_addr;

    /* <--- Pcap variables --->*/
    pcap_if_t *device;
    pcap_t *handle;
    bpf_u_int32 net = 0, mask = 0;
    struct bpf_program fp;
    struct pcap_pkthdr header;
    char errbuf_pcap[PCAP_ERRBUF_SIZE];
    struct tcphdr *tcp;
    struct ip *iphdr;
    u_int size_ip;
    const u_char *packet;

    /* <--- Sending packet --->*/
    pcap_findalldevs(&device, errbuf_pcap);
    libnet_t *lc = libnet_init(LIBNET_RAW4, device->name, errbuf_net);
    tcp_tag = ip_tag = LIBNET_PTAG_INITIALIZER;
    ip_addr = libnet_name2addr4(lc, destip, LIBNET_DONT_RESOLVE);
    tcp_tag = libnet_build_tcp(
        1234,
        destport,
        0,
        0,
        TH_SYN,
        1024,
        0,
        0,
        0,
        NULL,
        0,
        lc,
        tcp_tag
    );
    libnet_autobuild_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, IPPROTO_TCP, ip_addr, lc);
    int bytes_written = libnet_write(lc);
    libnet_destroy(lc);

    /* <--- Sniffing packet --->*/
    handle = pcap_open_live(device->name, BUFSIZE_RECV, 1, 1000, errbuf_pcap);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device->name, errbuf_pcap);
        exit(EXIT_FAILURE);
    }
    if (pcap_lookupnet(device->name, &net, &mask, errbuf_pcap) == -1) {
        fprintf(stderr, "Can't get netmask for %s: %s\n", device->name, errbuf_pcap);
        exit(EXIT_FAILURE);
    }
    if (pcap_compile(handle, &fp, TCP_FILTER, 0, net) == -1) {
        fprintf(stderr, "Can't compile filter: %s\n", errbuf_pcap);
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Can't install filter: %s\n", errbuf_pcap);
        exit(EXIT_FAILURE);
    }
    packet = pcap_next(handle, &header);
    struct ether_header *eth_header = (struct ether_header *)packet;
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl));
    int tcp_header_length = tcp_header->th_off;
    if ((tcp_header->th_flags & TH_SYN) && (tcp_header->th_flags & TH_ACK)) {
        printf("open\n");
        return OPENED;
    } else return CLOSED;
}
