#ifndef ZIM_NETWORK_H
#define ZIM_NETWORK_H

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include "config.h"

// Packet structure
typedef struct {
    struct timeval timestamp;
    unsigned int size;
    unsigned int protocol;
    
    // Addressing information
    char src_mac[18];
    char dst_mac[18];
    char src_ip[MAX_ADDR_STR_LEN];
    char dst_ip[MAX_ADDR_STR_LEN];
    unsigned short src_port;
    unsigned short dst_port;
    
    // Headers
    struct ethhdr *eth_header;
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    
    // Payload
    unsigned char payload[MAX_PAYLOAD_SIZE];
    unsigned int payload_size;
    
    // Raw packet data
    unsigned char buffer[MAX_PACKET_SIZE];
} Packet;

// Function prototypes
int find_default_interface(char *interface, size_t len);
int create_raw_socket(const char *interface, int promiscuous);
int apply_filter(int sock_fd, const char *filter);
int capture_packet(int sock_fd, Packet *packet);

#endif // ZIM_NETWORK_H