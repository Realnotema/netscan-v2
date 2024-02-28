#include <libnet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

/* <--- Pcap flags --->*/
#define UDP_FILTER "udp"
#define TCP_FILTER "port 2202"
#define BUFSIZE_RECV 1024
#define ETHERNET_SIZE 14

/* <--- Tehnique flags --->*/
#define CONNECT_TEHNIQUE 1
#define HALF_CONNECT_TECHNIQUE 2
#define DATAGRAMM_TECHNIQUE 3

/* <--- Selection flags --->*/
#define WO_PORT 0
#define WITH_PORT 1
#define WO_FLAG 0
#define WITH_FLAG 1

typedef struct Target {
    char *ip;
    char *port;
    int technique;
} Target;

int main(int argc, char *argv[]) {
    char *ip = "85.143.113.117";
    int port = 2203;

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
    if (pcap_findalldevs(&device, errbuf_pcap) != 0) {
        fprintf(stderr, "No device: %s\n", errbuf_pcap);
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "=> Using %s device\n", device->name);
    libnet_t *lc = libnet_init(LIBNET_RAW4, device->name, errbuf_net);
    if (lc == NULL) {
        fprintf(stderr, "Can't initialise libnet: %s\n", errbuf_net);
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "=> Libnet initialisation...\n");
    tcp_tag = ip_tag = LIBNET_PTAG_INITIALIZER;
    ip_addr = libnet_name2addr4(lc, ip, LIBNET_DONT_RESOLVE);
    if (ip_addr == -1) {
        fprintf(stderr, "Problems with func name2addr4: %s\n", errbuf_net);
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "=> IP is ready...\n");
    tcp_tag = libnet_build_tcp(
        1234,
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
        lc,
        tcp_tag
    );
    if (tcp_tag == -1) {
        fprintf(stderr, "=> TCP tag building problem: %s\n", errbuf_net);
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "=> TCP segment is ready\n");
    if (libnet_autobuild_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, IPPROTO_TCP, ip_addr, lc) == -1) {
        fprintf(stderr, "=> IPv4 build problem: %s\n", errbuf_net);
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "=> IPv4 builded\n");
    int bytes_written = libnet_write(lc);
    if (bytes_written == -1) {
        fprintf(stderr, "=> Send problem: %s\n", errbuf_net);
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "=> Packet sended!\nWaiting for answer...\n");
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
    if (packet == 0) {
        fprintf(stderr, "Timeout. Port may be closed or filtered: %s\n", errbuf_pcap);
        exit(EXIT_FAILURE);
    }
    struct tcphdr *tcp_header;
    int tcp_header_length;
    struct ether_header *eth_header = (struct ether_header *)packet;
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl << 2));
    tcp_header_length = tcp_header->th_off;
    if ((tcp_header->th_flags & TH_SYN) && (tcp_header->th_flags & TH_ACK)) {
        printf("opened\n");
    } else printf("closed\n");
    return 0;
}
