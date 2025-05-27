#ifndef ZIM_DISPLAY_H
#define ZIM_DISPLAY_H

#include "network.h"

// Function prototypes
void display_init(void);
void display_cleanup(void);
int display_check_input(void);
void display_update(void);
void display_packet(Packet *packet);
void display_help(void);

#endif // ZIM_DISPLAY_H