# Zim - Network Packet Sniffer and Analyzer

Zim is a lightweight, terminal-based network packet sniffer and analyzer tool written in C. It captures and analyzes network traffic in real-time, providing insights into packet details, protocol distribution, and traffic patterns.

## Features

- Raw socket implementation for capturing network packets
- TCP/IP header parsing and analysis
- Connection metadata logging to CSV file
- Real-time packet statistics display
- Terminal-based graph visualization of traffic sources
- Multiple display modes (packet list, statistics, graph)
- Filtering capabilities by protocol, port, and IP address
- Interactive terminal UI with keyboard shortcuts

## Requirements

- Linux operating system
- GCC compiler
- Root privileges (for raw socket access)

## Building

To build Zim, simply run:

```bash
make
```

This will compile the source code and create the `zim` executable.

## Usage

Since Zim uses raw sockets to capture packets, it requires root privileges to run:

```bash
sudo ./zim
```

### Command Line Options

```
Usage: zim [options]
Options:
  -i <interface>  Specify network interface (default: first available)
  -f <filter>     Specify BPF filter string
  -l <file>       Log packets to specified file
  -c <count>      Capture only <count> packets
  -p              Promiscuous mode (capture all packets)
  -h              Show this help message
```

### Keyboard Controls

While Zim is running, you can use the following keyboard commands:

- `q` - Quit the application
- `h` - Show help screen
- `m` - Cycle through display modes (packet list, statistics, graph)
- `s` - Toggle auto-scroll in packet list mode
- `d` - Toggle detailed packet view

## Display Modes

Zim offers three different display modes:

1. **Packet List** - Shows captured packets in real-time
2. **Statistics** - Shows packet count and protocol breakdown
3. **Graph** - Shows graph of top source IP addresses

## Logging

When used with the `-l` option, Zim logs all captured packets to a CSV file. The log includes timestamp, protocol, source/destination addresses and ports, and packet size.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Security Considerations

Zim is a packet capture tool that requires raw socket access. This is a privileged operation that should only be performed by authorized users on networks they have permission to monitor.

## Disclaimer

This tool is provided for educational and network troubleshooting purposes only. Only use it on networks you own or have explicit permission to monitor. Unauthorized network monitoring may violate privacy laws and regulations.