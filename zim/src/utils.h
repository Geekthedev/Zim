#ifndef ZIM_UTILS_H
#define ZIM_UTILS_H

#include <sys/time.h>

// Utility function prototypes
void print_hex_dump(const unsigned char *data, int size);
void format_bytes(unsigned long bytes, char *buffer, size_t buffer_size);

#endif // ZIM_UTILS_H