#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "logger.h"

static FILE *log_file = NULL;

int logger_init(const char *filename) {
    log_file = fopen(filename, "w");
    if (log_file == NULL) {
        perror("fopen");
        return -1;
    }
    
    // Write CSV header
    fprintf(log_file, "Timestamp,Protocol,Source IP,Source Port,Destination IP,Destination Port,Size\n");
    
    return 0;
}

void logger_cleanup(void) {
    if (log_file != NULL) {
        fclose(log_file);
        log_file = NULL;
    }
}

void logger_log_packet(Packet *packet) {
    if (log_file == NULL) {
        return;
    }
    
    // Format timestamp
    char timestamp[32];
    struct tm *tm_info = localtime(&packet->timestamp.tv_sec);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Get protocol name
    const char *proto_str;
    switch (packet->protocol) {
        case PROTO_TCP:
            proto_str = "TCP";
            break;
        case PROTO_UDP:
            proto_str = "UDP";
            break;
        case PROTO_ICMP:
            proto_str = "ICMP";
            break;
        default:
            proto_str = "UNKNOWN";
            break;
    }
    
    // Write packet info to log file in CSV format
    fprintf(log_file, "%s.%06ld,%s,%s,%u,%s,%u,%u\n",
            timestamp, packet->timestamp.tv_usec,
            proto_str,
            packet->src_ip, packet->src_port,
            packet->dst_ip, packet->dst_port,
            packet->size);
    
    // Flush to ensure data is written immediately
    fflush(log_file);
}