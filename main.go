package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/rivo/tview"
)

func main() {
	// Define CLI flags
	iface := flag.String("i", "", "Network interface to capture from (required)")
	bpf := flag.String("f", "", "Optional BPF filter (e.g., 'tcp and port 80')")
	pcapOut := flag.String("o", "", "Optional output .pcap file path to save captured packets")
	flag.Parse()

	if *iface == "" {
		// List all available interfaces and exit
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatalf("Error finding devices: %v", err)
		}
		fmt.Println("No interface specified. Available network interfaces:")
		for _, device := range devices {
			fmt.Printf("- %s: %s\n", device.Name, device.Description)
		}
		fmt.Println("\nUse -i <interface> to specify one.")
		return
	}

	fmt.Printf("Packet Sniffer CLI - Live Capture on %s\n", *iface)

	// Open the device for capturing
	handle, err := pcap.OpenLive(
		*iface,            // interface name
		1600,              // snapshotLen: max bytes per packet (typical Ethernet MTU + some extra)
		true,              // promiscuous: capture all traffic
		pcap.BlockForever, // timeout: wait indefinitely for packets
	)
	if err != nil {
		log.Fatalf("Error opening device %s: %v", *iface, err)
	}
	defer handle.Close()

	// Set BPF filter if provided
	if *bpf != "" {
		if err := handle.SetBPFFilter(*bpf); err != nil {
			log.Fatalf("Error setting BPF filter: %v", err)
		}
		fmt.Printf("BPF filter applied: %s\n", *bpf)
	}

	// Set up pcap file writer if output path is provided
	var pcapWriter *pcapgo.Writer
	if *pcapOut != "" {
		f, err := os.Create(*pcapOut)
		if err != nil {
			log.Fatalf("Error creating pcap file: %v", err)
		}
		pcapWriter = pcapgo.NewWriter(f)
		if err := pcapWriter.WriteFileHeader(1600, handle.LinkType()); err != nil {
			log.Fatalf("Error writing pcap file header: %v", err)
		}
		fmt.Printf("Saving captured packets to: %s\n", *pcapOut)
		defer f.Close()
	}

	// Set up tview UI
	app := tview.NewApplication()
	table := tview.NewTable().SetBorders(false).SetFixed(1, 0)
	table.SetTitle("Recent Packets").SetBorder(true)

	// Table headers
	headers := []string{"No.", "Time", "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol", "Info"}
	for i, h := range headers {
		table.SetCell(0, i, tview.NewTableCell(h).SetSelectable(false).SetAttributes(1))
	}

	// Channel and goroutine for packet capture
	type PacketRow struct {
		No      int
		Time    string
		SrcIP   string
		DstIP   string
		SrcPort string
		DstPort string
		Proto   string
		Info    string
	}
	packetCh := make(chan PacketRow, 100)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		count := 1
		for packet := range packetSource.Packets() {
			// Save packet to pcap file if enabled
			if pcapWriter != nil {
				ci := packet.Metadata().CaptureInfo
				pcapWriter.WritePacket(ci, packet.Data())
			}
			var srcIP, dstIP, srcPort, dstPort, proto, info string
			timestamp := packet.Metadata().Timestamp.Format("15:04:05.000")
			// Network layer
			if netLayer := packet.NetworkLayer(); netLayer != nil {
				endSrc, endDst := netLayer.NetworkFlow().Endpoints()
				srcIP, dstIP = endSrc.String(), endDst.String()
			}
			// Transport layer
			if transLayer := packet.TransportLayer(); transLayer != nil {
				endSrc, endDst := transLayer.TransportFlow().Endpoints()
				srcPort, dstPort = endSrc.String(), endDst.String()
				proto = transLayer.LayerType().String()
			}
			// Application layer info
			if appLayer := packet.ApplicationLayer(); appLayer != nil {
				payload := appLayer.Payload()
				if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
					dns, _ := dnsLayer.(*layers.DNS)
					if !dns.QR && len(dns.Questions) > 0 {
						info = "DNS: " + string(dns.Questions[0].Name)
					}
				}
				if len(payload) > 0 && info == "" {
					if isHTTP := (len(payload) > 4 && (string(payload[:4]) == "GET " || string(payload[:5]) == "POST " || string(payload[:4]) == "PUT " || string(payload[:7]) == "DELETE " || string(payload[:4]) == "HTTP")); isHTTP {
						lineEnd := 0
						for i, b := range payload {
							if b == '\n' {
								lineEnd = i
								break
							}
						}
						if lineEnd > 0 {
							info = "HTTP: " + string(payload[:lineEnd])
						}
					}
				}
			}
			if info == "" {
				info = "-"
			}
			packetCh <- PacketRow{count, timestamp, srcIP, dstIP, srcPort, dstPort, proto, info}
			count++
		}
		close(packetCh)
	}()

	// UI update loop
	go func() {
		maxRows := 100
		var rows []PacketRow
		for pkt := range packetCh {
			rows = append(rows, pkt)
			if len(rows) > maxRows {
				rows = rows[1:]
			}
			table.Clear().SetFixed(1, 0)
			for i, h := range headers {
				table.SetCell(0, i, tview.NewTableCell(h).SetSelectable(false).SetAttributes(1))
			}
			for i, p := range rows {
				table.SetCell(i+1, 0, tview.NewTableCell(fmt.Sprintf("%d", p.No)))
				table.SetCell(i+1, 1, tview.NewTableCell(p.Time))
				table.SetCell(i+1, 2, tview.NewTableCell(p.SrcIP))
				table.SetCell(i+1, 3, tview.NewTableCell(p.DstIP))
				table.SetCell(i+1, 4, tview.NewTableCell(p.SrcPort))
				table.SetCell(i+1, 5, tview.NewTableCell(p.DstPort))
				table.SetCell(i+1, 6, tview.NewTableCell(p.Proto))
				table.SetCell(i+1, 7, tview.NewTableCell(p.Info))
			}
			app.Draw()
		}
	}()

	if err := app.SetRoot(table, true).EnableMouse(true).Run(); err != nil {
		log.Fatalf("Error running UI: %v", err)
	}
	wg.Wait()
}
