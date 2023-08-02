#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h> // For ether_header

struct libnet_ipv4_hdr
{
    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
    u_int8_t ip_tos;
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
    u_int8_t  th_flags;       /* control flags */
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void print_mac(uint8_t *m) {
    printf("%02x-%02x-%02x-%02x-%02x-%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        printf("%u bytes captured\n", header->caplen);

        // Use ether_header type to get Ethernet header
        struct ether_header* eth_hdr = (struct ether_header*)packet;
        printf("smac : ");
        print_mac(eth_hdr->ether_shost);
        printf("\n");
        printf("dmac : ");
        print_mac(eth_hdr->ether_dhost);
        printf("\n");

        // Check if it's an IP packet (ethertype 0x0800)
        if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
            const u_char* ip_packet = packet + sizeof(struct ether_header);
            struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)ip_packet;

            // Check if it's a TCP packet (IP protocol number 6)
            if (ip_hdr->ip_p == IPPROTO_TCP) {
                const u_char* tcp_packet = ip_packet + (ip_hdr->ip_hl * 4);
                struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)tcp_packet;

                // Print source and destination IP
                char src_ip_str[INET_ADDRSTRLEN];
                char dst_ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip_str, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip_str, INET_ADDRSTRLEN);
                printf("src ip : %s\n", src_ip_str);
                printf("dst ip : %s\n", dst_ip_str);

                // Print source and destination TCP ports
                printf("src port : %u\n", ntohs(tcp_hdr->th_sport));
                printf("dst port : %u\n", ntohs(tcp_hdr->th_dport));
            }
        }
    }

    pcap_close(pcap);
    return 0;
}

