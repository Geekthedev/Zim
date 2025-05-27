#ifndef ZIM_LOGGER_H
#define ZIM_LOGGER_H

#include "network.h"

// Function prototypes
int logger_init(const char *filename);
void logger_cleanup(void);
void logger_log_packet(Packet *packet);

#endif // ZIM_LOGGER_H