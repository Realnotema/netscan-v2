#include <libnet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/tcp.h>

/* <--- Pcap filters flags --->*/
#define UDP_FILTER "udp"
#define TCP_FILTER "port 2202"
#define BUFSIZE_RECV 1024

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
    /* <--- Libnet variables --->*/
    char errbuf_net[LIBNET_ERRBUF_SIZE];
    libnet_ptag_t tcp_tag, ip_tag;
    u_int32_t ip_addr;

    /* <--- Pcap variables --->*/
    pcap_if_t *device;
    pcap_t *handle;
    bpf_u_int32 net = 0, mask = 0;
    struct bpf_program fp;
    const struct u_char *packet;
    struct pcap_pkthdr header;
    char errbuf_pcap[PCAP_ERRBUF_SIZE];

    /* <--- Sending packet --->*/
    pcap_findalldevs(&device, errbuf_pcap);
    libnet_t *lc = libnet_init(LIBNET_RAW4, device->name, errbuf_net);
    tcp_tag = ip_tag = LIBNET_PTAG_INITIALIZER;
    ip_addr = libnet_name2addr4(lc, "85.143.113.117", LIBNET_DONT_RESOLVE);
    tcp_tag = libnet_build_tcp(
        1234,
        2202,
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
    printf("Lol!: %u\n", header.len);
    return 0;
}
