# Go Packet Sniffer [An experiment in vibe coding]

A terminal-based packet sniffer written in Go. It captures live network packets from a specified interface, displays them in a real-time terminal dashboard, and can optionally save them to a `.pcap` file for later analysis.

## Features
- Live capture of packets from any network interface
- Scrollable terminal dashboard (using [rivo/tview](https://github.com/rivo/tview))
- Displays source/destination IPs, ports, protocol, and basic info (DNS/HTTP)
- Optional BPF filter support (e.g., `tcp and port 80`)
- Save captured packets to a `.pcap` file for use with Wireshark or tcpdump

## Requirements
- Go 1.18 or newer
- Sufficient privileges to capture packets (may require `sudo`)

## Installation
Clone the repository and install dependencies:
```sh
git clone <repo-url>
cd packet_sniffer
go mod tidy
```

## Usage
Build and run the sniffer:
```sh
go run main.go -i <interface> [options]
```
Or build a binary:
```sh
go build -o sniffer
./sniffer -i <interface> [options]
```

### Options
- `-i <interface>`: **(Required)** Network interface to capture from (e.g., `en0`, `eth0`)
- `-f <bpf filter>`: Optional BPF filter string (e.g., `'tcp and port 80'`)
- `-o <file.pcap>`: Optional output file to save captured packets in pcap format

### Example
List available interfaces:
```sh
go run main.go
```

Capture HTTP traffic on interface `en0` and save to `capture.pcap`:
```sh
go run main.go -i en0 -f "tcp port 80" -o capture.pcap
```

## How It Works (High Level)
1. **CLI Flags:** The program uses Go's `flag` package to parse command-line options for interface, BPF filter, and output file.
2. **Interface Selection:** If no interface is specified, it lists all available interfaces and exits.
3. **Packet Capture:** Uses `gopacket/pcap` to open the interface and apply an optional BPF filter for efficient kernel-level filtering.
4. **Packet Processing:** A background goroutine reads packets, extracts key info (IP addresses, ports, protocol, DNS/HTTP details), and sends them to the UI.
5. **Terminal Dashboard:** Uses `rivo/tview` to display a scrollable, real-time table of recent packets.
6. **Saving to PCAP:** If an output file is specified, all captured packets are written to a `.pcap` file using `gopacket/pcapgo`.

## Notes
- You may need to run as root/admin to capture packets on some interfaces.
- The sniffer is cross-platform but some features (like loopback capture) may be limited on macOS.
- The `.pcap` file can be opened in Wireshark or tcpdump for further analysis.

## License
MIT 