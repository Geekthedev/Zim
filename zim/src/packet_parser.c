#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include "packet_parser.h"
#include "utils.h"

// Initialize global statistics
PacketStats stats = {0};

void parse_ethernet_header(Packet *packet) {
    struct ethhdr *eth_header = (struct ethhdr *)packet->buffer;
    packet->eth_header = eth_header;
    
    // Convert MAC addresses to string format
    sprintf(packet->src_mac, "%02X:%02X:%02X:%02X:%02X:%02X",
            eth_header->h_source[0], eth_header->h_source[1],
            eth_header->h_source[2], eth_header->h_source[3],
            eth_header->h_source[4], eth_header->h_source[5]);
            
    sprintf(packet->dst_mac, "%02X:%02X:%02X:%02X:%02X:%02X",
            eth_header->h_dest[0], eth_header->h_dest[1],
            eth_header->h_dest[2], eth_header->h_dest[3],
            eth_header->h_dest[4], eth_header->h_dest[5]);
}

void parse_ip_header(Packet *packet) {
    struct iphdr *ip_header = (struct iphdr *)(packet->buffer + sizeof(struct ethhdr));
    packet->ip_header = ip_header;
    
    // Set protocol
    packet->protocol = ip_header->protocol;
    
    // Convert IP addresses to string format
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = ip_header->saddr;
    dst_addr.s_addr = ip_header->daddr;
    
    strncpy(packet->src_ip, inet_ntoa(src_addr), MAX_ADDR_STR_LEN - 1);
    packet->src_ip[MAX_ADDR_STR_LEN - 1] = '\0';
    
    strncpy(packet->dst_ip, inet_ntoa(dst_addr), MAX_ADDR_STR_LEN - 1);
    packet->dst_ip[MAX_ADDR_STR_LEN - 1] = '\0';
}

void parse_tcp_header(Packet *packet) {
    struct tcphdr *tcp_header = (struct tcphdr *)(packet->buffer + 
                                sizeof(struct ethhdr) + 
                                (packet->ip_header->ihl * 4));
    packet->tcp_header = tcp_header;
    
    // Set ports
    packet->src_port = ntohs(tcp_header->source);
    packet->dst_port = ntohs(tcp_header->dest);
    
    // Extract payload
    int header_size = sizeof(struct ethhdr) + (packet->ip_header->ihl * 4) + (tcp_header->doff * 4);
    
    if (packet->size > header_size) {
        packet->payload_size = packet->size - header_size;
        if (packet->payload_size > MAX_PAYLOAD_SIZE) {
            packet->payload_size = MAX_PAYLOAD_SIZE;
        }
        memcpy(packet->payload, packet->buffer + header_size, packet->payload_size);
    }
}

void parse_udp_header(Packet *packet) {
    struct udphdr *udp_header = (struct udphdr *)(packet->buffer + 
                                sizeof(struct ethhdr) + 
                                (packet->ip_header->ihl * 4));
    packet->udp_header = udp_header;
    
    // Set ports
    packet->src_port = ntohs(udp_header->source);
    packet->dst_port = ntohs(udp_header->dest);
    
    // Extract payload
    int header_size = sizeof(struct ethhdr) + (packet->ip_header->ihl * 4) + sizeof(struct udphdr);
    
    if (packet->size > header_size) {
        packet->payload_size = packet->size - header_size;
        if (packet->payload_size > MAX_PAYLOAD_SIZE) {
            packet->payload_size = MAX_PAYLOAD_SIZE;
        }
        memcpy(packet->payload, packet->buffer + header_size, packet->payload_size);
    }
}

void parse_packet(Packet *packet) {
    // Parse ethernet header
    parse_ethernet_header(packet);
    
    // Check if it's an IP packet
    if (ntohs(packet->eth_header->h_proto) == ETH_P_IP) {
        // Parse IP header
        parse_ip_header(packet);
        
        // Parse protocol-specific headers
        switch (packet->protocol) {
            case PROTO_TCP:
                parse_tcp_header(packet);
                break;
            case PROTO_UDP:
                parse_udp_header(packet);
                break;
            case PROTO_ICMP:
                // ICMP parsing would go here
                break;
            default:
                // Unknown protocol
                break;
        }
    }
}

void update_statistics(Packet *packet) {
    stats.total_packets++;
    stats.total_bytes += packet->size;
    
    // Update protocol-specific counts
    switch (packet->protocol) {
        case PROTO_TCP:
            stats.tcp_packets++;
            break;
        case PROTO_UDP:
            stats.udp_packets++;
            break;
        case PROTO_ICMP:
            stats.icmp_packets++;
            break;
        default:
            stats.other_packets++;
            break;
    }
    
    // Update source IP statistics for graph display
    if (packet->src_ip[0] != '\0') {
        int found = 0;
        int empty_slot = -1;
        
        // Look for existing entry or empty slot
        for (int i = 0; i < 10; i++) {
            if (stats.top_sources[i].ip[0] == '\0' && empty_slot == -1) {
                empty_slot = i;
            } else if (strcmp(stats.top_sources[i].ip, packet->src_ip) == 0) {
                stats.top_sources[i].count++;
                found = 1;
                break;
            }
        }
        
        // Add new entry if not found and empty slot available
        if (!found && empty_slot != -1) {
            strncpy(stats.top_sources[empty_slot].ip, packet->src_ip, MAX_ADDR_STR_LEN - 1);
            stats.top_sources[empty_slot].ip[MAX_ADDR_STR_LEN - 1] = '\0';
            stats.top_sources[empty_slot].count = 1;
        }
    }
}