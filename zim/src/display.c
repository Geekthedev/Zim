#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include "display.h"
#include "packet_parser.h"
#include "config.h"

// Terminal control
static struct termios old_termios, new_termios;
static int term_configured = 0;

// Display state
static int display_mode = 0;  // 0: Packet list, 1: Statistics, 2: Graph
static int auto_scroll = 1;
static int detailed_view = 0;

// Initialize terminal for non-blocking input
void display_init(void) {
    // Save current terminal attributes
    tcgetattr(STDIN_FILENO, &old_termios);
    new_termios = old_termios;
    
    // Disable canonical mode and echo
    new_termios.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_termios);
    
    // Set non-blocking mode for stdin
    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
    
    term_configured = 1;
    
    // Clear screen
    printf("\033[2J\033[H");
}

// Restore terminal settings
void display_cleanup(void) {
    if (term_configured) {
        // Restore terminal attributes
        tcsetattr(STDIN_FILENO, TCSANOW, &old_termios);
        
        // Reset colors
        printf("%s", COLOR_RESET);
    }
}

// Check for keyboard input
int display_check_input(void) {
    char c;
    int ret = read(STDIN_FILENO, &c, 1);
    
    if (ret > 0) {
        switch (c) {
            case 'm':
                // Toggle display mode
                display_mode = (display_mode + 1) % 3;
                printf("\033[2J\033[H");  // Clear screen
                break;
            case 's':
                // Toggle auto-scroll
                auto_scroll = !auto_scroll;
                break;
            case 'd':
                // Toggle detailed view
                detailed_view = !detailed_view;
                break;
            case 'h':
                // Display help
                return 'h';
            case 'q':
                // Quit
                return 'q';
        }
        return c;
    }
    
    return 0;
}

// Display packet information
void display_packet(Packet *packet) {
    // Get current time
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", 
             localtime(&packet->timestamp.tv_sec));
    
    // Choose color based on protocol
    const char *color;
    const char *proto_str;
    
    switch (packet->protocol) {
        case PROTO_TCP:
            color = COLOR_BLUE;
            proto_str = "TCP";
            break;
        case PROTO_UDP:
            color = COLOR_GREEN;
            proto_str = "UDP";
            break;
        case PROTO_ICMP:
            color = COLOR_YELLOW;
            proto_str = "ICMP";
            break;
        default:
            color = COLOR_WHITE;
            proto_str = "???";
            break;
    }
    
    // Print basic packet info
    if (display_mode == 0) {  // Packet list mode
        printf("%s[%s]%s %s%s%s %s%s%s:%d -> %s:%d %d bytes\n",
               COLOR_CYAN, time_str, COLOR_RESET,
               color, proto_str, COLOR_RESET,
               COLOR_BOLD, packet->src_ip, COLOR_RESET, packet->src_port,
               packet->dst_ip, packet->dst_port,
               packet->size);
               
        // If detailed view is enabled, print more information
        if (detailed_view) {
            printf("  MAC: %s -> %s\n", packet->src_mac, packet->dst_mac);
            
            // Display TCP flags if it's a TCP packet
            if (packet->protocol == PROTO_TCP && packet->tcp_header != NULL) {
                printf("  Flags: %s%s%s%s%s%s\n",
                       packet->tcp_header->syn ? "SYN " : "",
                       packet->tcp_header->ack ? "ACK " : "",
                       packet->tcp_header->fin ? "FIN " : "",
                       packet->tcp_header->rst ? "RST " : "",
                       packet->tcp_header->psh ? "PSH " : "",
                       packet->tcp_header->urg ? "URG " : "");
            }
            
            // Display first few bytes of payload
            if (packet->payload_size > 0) {
                printf("  Payload (%d bytes): ", packet->payload_size);
                for (int i = 0; i < packet->payload_size && i < 16; i++) {
                    printf("%02X ", packet->payload[i]);
                }
                printf("\n");
            }
            
            printf("\n");
        }
    }
}

// Display network statistics
void display_statistics(void) {
    printf("\033[H");  // Move cursor to home position
    
    printf("%s======== Network Statistics ========%s\n\n", COLOR_BOLD, COLOR_RESET);
    
    printf("Total Packets: %s%lu%s\n", COLOR_BOLD, stats.total_packets, COLOR_RESET);
    printf("Total Bytes: %lu\n\n", stats.total_bytes);
    
    printf("Protocol Breakdown:\n");
    printf("  %sTCP:%s %lu (%.1f%%)\n", COLOR_BLUE, COLOR_RESET, 
           stats.tcp_packets, 
           stats.total_packets > 0 ? (stats.tcp_packets * 100.0 / stats.total_packets) : 0);
           
    printf("  %sUDP:%s %lu (%.1f%%)\n", COLOR_GREEN, COLOR_RESET, 
           stats.udp_packets, 
           stats.total_packets > 0 ? (stats.udp_packets * 100.0 / stats.total_packets) : 0);
           
    printf("  %sICMP:%s %lu (%.1f%%)\n", COLOR_YELLOW, COLOR_RESET, 
           stats.icmp_packets, 
           stats.total_packets > 0 ? (stats.icmp_packets * 100.0 / stats.total_packets) : 0);
           
    printf("  %sOther:%s %lu (%.1f%%)\n", COLOR_WHITE, COLOR_RESET, 
           stats.other_packets, 
           stats.total_packets > 0 ? (stats.other_packets * 100.0 / stats.total_packets) : 0);
}

// Display IP source graph
void display_source_graph(void) {
    printf("\033[H");  // Move cursor to home position
    
    printf("%s======== Top IP Sources ========%s\n\n", COLOR_BOLD, COLOR_RESET);
    
    // Sort top sources by count
    for (int i = 0; i < 9; i++) {
        for (int j = i + 1; j < 10; j++) {
            if (stats.top_sources[j].count > stats.top_sources[i].count) {
                // Swap
                char temp_ip[MAX_ADDR_STR_LEN];
                unsigned long temp_count = stats.top_sources[i].count;
                
                strncpy(temp_ip, stats.top_sources[i].ip, MAX_ADDR_STR_LEN);
                strncpy(stats.top_sources[i].ip, stats.top_sources[j].ip, MAX_ADDR_STR_LEN);
                strncpy(stats.top_sources[j].ip, temp_ip, MAX_ADDR_STR_LEN);
                
                stats.top_sources[i].count = stats.top_sources[j].count;
                stats.top_sources[j].count = temp_count;
            }
        }
    }
    
    // Find maximum count for scaling
    unsigned long max_count = 0;
    for (int i = 0; i < 10; i++) {
        if (stats.top_sources[i].count > max_count) {
            max_count = stats.top_sources[i].count;
        }
    }
    
    // Display graph
    if (max_count > 0) {
        const int graph_width = 50;
        
        for (int i = 0; i < 10; i++) {
            if (stats.top_sources[i].ip[0] == '\0') {
                continue;
            }
            
            int bar_width = (stats.top_sources[i].count * graph_width) / max_count;
            if (bar_width < 1) bar_width = 1;
            
            printf("%-15s [%5lu] ", stats.top_sources[i].ip, stats.top_sources[i].count);
            
            for (int j = 0; j < bar_width; j++) {
                printf("█");
            }
            printf("\n");
        }
    } else {
        printf("No data available yet.\n");
    }
}

// Update display based on current mode
void display_update(void) {
    switch (display_mode) {
        case 1:  // Statistics mode
            display_statistics();
            break;
        case 2:  // Graph mode
            display_source_graph();
            break;
        default:  // Packet list mode (no special update needed)
            break;
    }
}

// Display help information
void display_help(void) {
    printf("\033[2J\033[H");  // Clear screen
    
    printf("%s======== Zim Help ========%s\n\n", COLOR_BOLD, COLOR_RESET);
    
    printf("Keyboard Commands:\n");
    printf("  %sq%s - Quit the application\n", COLOR_BOLD, COLOR_RESET);
    printf("  %sh%s - Show this help screen\n", COLOR_BOLD, COLOR_RESET);
    printf("  %sm%s - Cycle through display modes (packet list, statistics, graph)\n", COLOR_BOLD, COLOR_RESET);
    printf("  %ss%s - Toggle auto-scroll in packet list mode\n", COLOR_BOLD, COLOR_RESET);
    printf("  %sd%s - Toggle detailed packet view\n", COLOR_BOLD, COLOR_RESET);
    
    printf("\nDisplay Modes:\n");
    printf("  %sPacket List%s - Shows captured packets in real-time\n", COLOR_BOLD, COLOR_RESET);
    printf("  %sStatistics%s - Shows packet count and protocol breakdown\n", COLOR_BOLD, COLOR_RESET);
    printf("  %sGraph%s - Shows graph of top source IP addresses\n", COLOR_BOLD, COLOR_RESET);
    
    printf("\nPress any key to return...\n");
    
    // Wait for keypress
    while (display_check_input() == 0) {
        usleep(100000);  // 100ms
    }
    
    printf("\033[2J\033[H");  // Clear screen
}