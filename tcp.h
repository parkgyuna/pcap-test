
#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct eth_header {
    unsigned char dst_mac[6];
    unsigned char src_mac[6];
    unsigned short type;
};

struct ip_header {
    unsigned char ihl_version;
    unsigned char tos;
    unsigned short total_length;
    unsigned short identification;
    unsigned short flags_fragment;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    unsigned int src_ip;
    unsigned int dst_ip;
};


struct tcp_header {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int seq_number;
    unsigned int ack_number;
    unsigned char offset_reserved;
    unsigned char flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_pointer;
};
