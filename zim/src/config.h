#ifndef ZIM_CONFIG_H
#define ZIM_CONFIG_H

// Maximum string lengths
#define MAX_INTERFACE_LEN 32
#define MAX_FILTER_LEN 256
#define MAX_FILENAME_LEN 256
#define MAX_PACKET_SIZE 65536
#define MAX_ADDR_STR_LEN 46 // IPv6 string length
#define MAX_PAYLOAD_SIZE 1500

// Configuration structure
typedef struct {
    char interface[MAX_INTERFACE_LEN];
    char filter[MAX_FILTER_LEN];
    char log_file[MAX_FILENAME_LEN];
    unsigned long packet_count;
    int promiscuous;
} ZimConfig;

// Packet protocols
#define PROTO_UNKNOWN 0
#define PROTO_ICMP    1
#define PROTO_TCP     6
#define PROTO_UDP     17

// Colors for terminal output
#define COLOR_RESET   "\x1b[0m"
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_WHITE   "\x1b[37m"
#define COLOR_BOLD    "\x1b[1m"

#endif // ZIM_CONFIG_H