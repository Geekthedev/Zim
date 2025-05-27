# Zim - Network Packet Sniffer and Analyzer
# Makefile

CC = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c11 -O2
LDFLAGS = 

# Source files
SRC = $(wildcard src/*.c)
OBJ = $(SRC:.c=.o)

# Output binary
BIN = zim

# Default target
all: $(BIN)

# Linking
$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Compilation
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up
clean:
	rm -f $(OBJ) $(BIN)

# Install (requires root privileges)
install: $(BIN)
	install -m 755 $(BIN) /usr/local/bin/

# Run (requires root privileges)
run: $(BIN)
	sudo ./$(BIN)

.PHONY: all clean install run