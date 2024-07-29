#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <ctype.h>

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

void print_payload_ascii(const u_char *payload, int len) {
    for (int i = 0; i < len && i < 20; i++) {
        if (isprint(payload[i])) {
            printf("%c", payload[i]);
        } else {
            printf(".");
        }
    }
    printf("\n");
}

void handle_packet(const u_char *packet, struct pcap_pkthdr packet_header) {
    struct ether_header *eth_header;
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    struct icmphdr *icmp_header;
    const u_char *payload;

    int ethernet_size = sizeof(struct ether_header);
    int ip_size;
    int tcp_size;
    int payload_size;

    eth_header = (struct ether_header*)(packet);

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        ip_header = (struct ip*)(packet + ethernet_size);
        ip_size = ip_header->ip_hl * 4;

        // Ethernet header
        printf("Src MAC: %s\n", ether_ntoa((struct ether_addr*)eth_header->ether_shost));
        printf("Dst MAC: %s\n", ether_ntoa((struct ether_addr*)eth_header->ether_dhost));

        // IP header
        printf("Src IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("Dst IP: %s\n", inet_ntoa(ip_header->ip_dst));

        if (ip_header->ip_p == IPPROTO_TCP) {
            tcp_header = (struct tcphdr*)(packet + ethernet_size + ip_size);
            tcp_size = tcp_header->th_off * 4;

            payload = packet + ethernet_size + ip_size + tcp_size;
            payload_size = packet_header.caplen - (ethernet_size + ip_size + tcp_size);

            // TCP header
            printf("Src Port: %d\n", ntohs(tcp_header->th_sport));
            printf("Dst Port: %d\n", ntohs(tcp_header->th_dport));

            // Payload
            printf("Payload (ASCII): ");
            print_payload_ascii(payload, payload_size);
            printf("\n");
        } else if (ip_header->ip_p == IPPROTO_ICMP) {
            icmp_header = (struct icmphdr*)(packet + ethernet_size + ip_size);

            payload = packet + ethernet_size + ip_size + sizeof(struct icmphdr);
            payload_size = packet_header.caplen - (ethernet_size + ip_size + sizeof(struct icmphdr));

            // Payload
            printf("Payload (ASCII): ");
            print_payload_ascii(payload, payload_size);
            printf("\n");
        } else {
            printf("Not a TCP or ICMP packet\n\n");
        }
    } else {
        printf("Not an IP packet\n\n");
    }
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
        printf("Packet captured: length %d\n", header->len);
        handle_packet(packet, *header);
    }

    pcap_close(pcap);
    return 0;
}
