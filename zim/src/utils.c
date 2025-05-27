#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "utils.h"

void print_hex_dump(const unsigned char *data, int size) {
    int i, j;
    
    for (i = 0; i < size; i += 16) {
        // Print offset
        printf("%04x: ", i);
        
        // Print hex values
        for (j = 0; j < 16; j++) {
            if (i + j < size) {
                printf("%02x ", data[i + j]);
            } else {
                printf("   ");
            }
            
            // Extra space after 8 bytes
            if (j == 7) {
                printf(" ");
            }
        }
        
        // Print ASCII representation
        printf(" |");
        for (j = 0; j < 16; j++) {
            if (i + j < size) {
                unsigned char c = data[i + j];
                printf("%c", isprint(c) ? c : '.');
            } else {
                printf(" ");
            }
        }
        printf("|\n");
    }
}

void format_bytes(unsigned long bytes, char *buffer, size_t buffer_size) {
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size = bytes;
    
    while (size >= 1024 && unit < 4) {
        size /= 1024;
        unit++;
    }
    
    snprintf(buffer, buffer_size, "%.2f %s", size, units[unit]);
}