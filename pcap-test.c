#include "tcp.h"

void print_hex_dump(const unsigned char *data, int length) {
    printf("Hex Dump (First 20 Bytes): ");
    for (int i = 0; i < length && i < 20; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}


void print_mac(const char* label, unsigned char *mac) {
    printf("%s %02X:%02X:%02X:%02X:%02X:%02X\n", label,
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}


void print_ip(const char* label, unsigned int ip) {
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    printf("%s %u.%u.%u.%u\n", label, bytes[0], bytes[1], bytes[2], bytes[3]);
}


void print_payload(const unsigned char *payload, int length) {
    printf("Payload (Hex, max 20 bytes): ");
    if (length == 0) {
        printf("[No Data]");
    } else {
        for (int i = 0; i < length && i < 20; i++) {
            printf("%02X ", payload[i]);
        }
    }
    printf("\n");
}


void process_packet(const unsigned char *packet, struct pcap_pkthdr *header) {
    struct eth_header *eth = (struct eth_header *)packet;


    print_hex_dump(packet, header->caplen);


    printf("Ethernet Type: 0x%04X\n", ntohs(eth->type));
    if (ntohs(eth->type) != 0x0800) {  // 0x0800 = IPv4
        printf("Not an IP packet\n");
        return;
    }

    struct ip_header *ip_hdr = (struct ip_header *)(packet + sizeof(struct eth_header));


    printf("IP Protocol: %d\n", ip_hdr->protocol);
    if (ip_hdr->protocol != 6) {  // 6 = TCP
        printf("Not a TCP packet\n");
        return;
    }

    int ip_header_size = (ip_hdr->ihl_version & 0x0F) * 4;
    printf("IP Header Size: %d bytes\n", ip_header_size);

    struct tcp_header *tcp_hdr = (struct tcp_header *)(packet + sizeof(struct eth_header) + ip_header_size);
    int tcp_header_size = ((tcp_hdr->offset_reserved >> 4) & 0x0F) * 4;
    printf("TCP Header Size: %d bytes\n", tcp_header_size);

    int payload_offset = sizeof(struct eth_header) + ip_header_size + tcp_header_size;
    printf("Payload Offset: %d bytes\n", payload_offset);

    const unsigned char *payload = packet + payload_offset;
    int payload_length = header->caplen - payload_offset;
    if (payload_length < 0) payload_length = 0;





    print_mac("Source MAC:", eth->src_mac);
    print_mac("Destination MAC:", eth->dst_mac);


    print_ip("Source IP:", ntohl(ip_hdr->src_ip));
    print_ip("Destination IP:", ntohl(ip_hdr->dst_ip));


    printf("Source Port: %d\n", ntohs(tcp_hdr->src_port));
    printf("Destination Port: %d\n", ntohs(tcp_hdr->dst_port));


    print_payload(payload, payload_length);
}


int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("syntax: pcap-test <interface>\n");
        printf("sample: pcap-test wlan0\n");
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) failed - %s\n", argv[1], errbuf);
        return -1;
    }

    printf(" capturing TCP packets on %s\n", argv[1]);

    while (true) {
        struct pcap_pkthdr* header;
        const unsigned char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);

        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            fprintf(stderr, "pcap_next_ex() error: %s\n", pcap_geterr(pcap));
            break;
        }

        process_packet(packet, header);
    }

    pcap_close(pcap);
    return 0;
}
