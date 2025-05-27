#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include "network.h"
#include "packet_parser.h"
#include "display.h"
#include "logger.h"
#include "filter.h"
#include "utils.h"
#include "config.h"

// Global variables
volatile sig_atomic_t running = 1;
ZimConfig config;

// Signal handler for graceful exit
void signal_handler(int signal) {
    running = 0;
    printf("\nShutting down Zim...\n");
}

void print_welcome() {
    printf("\n");
    printf("███████╗██╗███╗   ███╗\n");
    printf("╚══███╔╝██║████╗ ████║\n");
    printf("  ███╔╝ ██║██╔████╔██║\n");
    printf(" ███╔╝  ██║██║╚██╔╝██║\n");
    printf("███████╗██║██║ ╚═╝ ██║\n");
    printf("╚══════╝╚═╝╚═╝     ╚═╝\n");
    printf("\n");
    printf("Network Packet Sniffer & Analyzer v1.0.0\n");
    printf("----------------------------------------\n");
    printf("Press 'h' for help | 'q' to quit\n\n");
}

void print_usage(char *program_name) {
    printf("Usage: %s [options]\n", program_name);
    printf("Options:\n");
    printf("  -i <interface>  Specify network interface (default: first available)\n");
    printf("  -f <filter>     Specify BPF filter string\n");
    printf("  -l <file>       Log packets to specified file\n");
    printf("  -c <count>      Capture only <count> packets\n");
    printf("  -p              Promiscuous mode (capture all packets)\n");
    printf("  -h              Show this help message\n");
}

int parse_arguments(int argc, char *argv[], ZimConfig *config) {
    int opt;
    
    // Set defaults
    config->interface[0] = '\0';
    config->filter[0] = '\0';
    config->log_file[0] = '\0';
    config->packet_count = 0;  // 0 means capture indefinitely
    config->promiscuous = 0;
    
    while ((opt = getopt(argc, argv, "i:f:l:c:ph")) != -1) {
        switch (opt) {
            case 'i':
                strncpy(config->interface, optarg, MAX_INTERFACE_LEN - 1);
                break;
            case 'f':
                strncpy(config->filter, optarg, MAX_FILTER_LEN - 1);
                break;
            case 'l':
                strncpy(config->log_file, optarg, MAX_FILENAME_LEN - 1);
                break;
            case 'c':
                config->packet_count = atoi(optarg);
                break;
            case 'p':
                config->promiscuous = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return -1;
        }
    }
    
    return 1;
}

int main(int argc, char *argv[]) {
    int sock_fd;
    int result;
    struct timespec sleep_time = {0, 100000000}; // 100ms
    
    // Parse command line arguments
    result = parse_arguments(argc, argv, &config);
    if (result <= 0) {
        return result == 0 ? 0 : 1;
    }
    
    // Set up signal handler for Ctrl+C
    signal(SIGINT, signal_handler);
    
    // Display welcome message
    print_welcome();
    
    // Initialize modules
    display_init();
    
    // If no interface specified, find the first available one
    if (config.interface[0] == '\0') {
        if (find_default_interface(config.interface, MAX_INTERFACE_LEN) != 0) {
            fprintf(stderr, "Error: Could not find a default interface.\n");
            return 1;
        }
    }
    
    printf("Using interface: %s\n", config.interface);
    
    // Initialize packet logger if log file specified
    if (config.log_file[0] != '\0') {
        if (logger_init(config.log_file) != 0) {
            fprintf(stderr, "Error: Could not initialize logger.\n");
            return 1;
        }
        printf("Logging to file: %s\n", config.log_file);
    }
    
    // Create raw socket
    sock_fd = create_raw_socket(config.interface, config.promiscuous);
    if (sock_fd < 0) {
        fprintf(stderr, "Error: Failed to create raw socket.\n");
        logger_cleanup();
        return 1;
    }
    
    // Apply filter if specified
    if (config.filter[0] != '\0') {
        if (apply_filter(sock_fd, config.filter) != 0) {
            fprintf(stderr, "Error: Failed to apply filter: %s\n", config.filter);
            close(sock_fd);
            logger_cleanup();
            return 1;
        }
        printf("Applied filter: %s\n", config.filter);
    }
    
    printf("Starting packet capture...\n");
    
    // Main capture loop
    unsigned long packet_count = 0;
    while (running) {
        // Process keyboard input
        int key = display_check_input();
        if (key == 'q') {
            running = 0;
            continue;
        } else if (key == 'h') {
            display_help();
        }
        
        // Process a packet if available
        Packet packet;
        if (capture_packet(sock_fd, &packet) > 0) {
            packet_count++;
            
            // Parse packet
            parse_packet(&packet);
            
            // Update statistics
            update_statistics(&packet);
            
            // Log packet if logging enabled
            if (config.log_file[0] != '\0') {
                logger_log_packet(&packet);
            }
            
            // Display packet info
            display_packet(&packet);
            
            // Check if we've reached the capture limit
            if (config.packet_count > 0 && packet_count >= config.packet_count) {
                running = 0;
            }
        }
        
        // Update display
        display_update();
        
        // Sleep a bit to avoid using 100% CPU
        nanosleep(&sleep_time, NULL);
    }
    
    // Clean up
    close(sock_fd);
    logger_cleanup();
    display_cleanup();
    
    printf("\nCapture complete. Processed %lu packets.\n", packet_count);
    
    return 0;
}