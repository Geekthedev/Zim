#ifndef ZIM_PACKET_PARSER_H
#define ZIM_PACKET_PARSER_H

#include "network.h"

// Function prototypes
void parse_packet(Packet *packet);
void update_statistics(Packet *packet);

// Statistics structure
typedef struct {
    unsigned long total_packets;
    unsigned long tcp_packets;
    unsigned long udp_packets;
    unsigned long icmp_packets;
    unsigned long other_packets;
    unsigned long total_bytes;
    
    // Source IP tracking for graph display
    struct {
        char ip[MAX_ADDR_STR_LEN];
        unsigned long count;
    } top_sources[10];
} PacketStats;

// Global statistics object
extern PacketStats stats;

#endif // ZIM_PACKET_PARSER_H