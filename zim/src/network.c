#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include "network.h"
#include "utils.h"

int find_default_interface(char *interface, size_t len) {
    struct ifaddrs *ifaddr, *ifa;
    
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }
    
    // Look for the first non-loopback interface that is up
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
            
        // Skip loopback
        if (strcmp(ifa->ifa_name, "lo") == 0)
            continue;
            
        // Check if interface is up
        if (!(ifa->ifa_flags & IFF_UP))
            continue;
            
        // Found a suitable interface
        strncpy(interface, ifa->ifa_name, len - 1);
        interface[len - 1] = '\0';
        freeifaddrs(ifaddr);
        return 0;
    }
    
    freeifaddrs(ifaddr);
    return -1;
}

int create_raw_socket(const char *interface, int promiscuous) {
    int sock_fd;
    struct ifreq ifr;
    
    // Create raw socket
    sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd < 0) {
        perror("socket");
        return -1;
    }
    
    // Set interface to promiscuous mode if requested
    if (promiscuous) {
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
        
        // Get interface flags
        if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr) < 0) {
            perror("ioctl SIOCGIFFLAGS");
            close(sock_fd);
            return -1;
        }
        
        // Set promiscuous flag
        ifr.ifr_flags |= IFF_PROMISC;
        
        // Set interface flags
        if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr) < 0) {
            perror("ioctl SIOCSIFFLAGS");
            close(sock_fd);
            return -1;
        }
        
        printf("Promiscuous mode enabled on %s\n", interface);
    }
    
    // Bind to specific interface
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    
    if (ioctl(sock_fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        close(sock_fd);
        return -1;
    }
    
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    
    if (bind(sock_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sock_fd);
        return -1;
    }
    
    return sock_fd;
}

int apply_filter(int sock_fd, const char *filter) {
    // Note: This is a placeholder for BPF filtering.
    // In a real implementation, this would use libpcap's pcap_compile and pcap_setfilter,
    // or the Linux socket filter (BPF) directly.
    // For simplicity, we're not implementing the actual filter here.
    
    // Return success to allow the program to continue
    return 0;
}

int capture_packet(int sock_fd, Packet *packet) {
    int packet_size;
    
    // Initialize packet structure
    memset(packet, 0, sizeof(Packet));
    
    // Capture a packet
    packet_size = recvfrom(sock_fd, packet->buffer, MAX_PACKET_SIZE, 0, NULL, NULL);
    if (packet_size < 0) {
        perror("recvfrom");
        return -1;
    }
    
    // Skip empty packets
    if (packet_size == 0) {
        return 0;
    }
    
    // Get timestamp
    gettimeofday(&packet->timestamp, NULL);
    
    // Set packet size
    packet->size = packet_size;
    
    return packet_size;
}