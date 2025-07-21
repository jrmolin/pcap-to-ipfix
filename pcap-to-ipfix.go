package main

import (
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <input.pcap> [output_dir]\n", os.Args[0])
		os.Exit(1)
	}
	pcapFile := os.Args[1]
	outputDir := "."
	if len(os.Args) > 2 {
		outputDir = os.Args[2]
	}

	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatalf("Failed to open pcap file: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	count_packets := 0

	fixer := NewFixer(outputDir)
	for packet := range packetSource.Packets() {

		if err := fixer.OnPacket(packet); err != nil {
			fmt.Printf("Failed to ingest packet with err %v\n", err)
			break
		}
		count_packets += 1

	}

	fixer.dump_to_directory()
	fmt.Printf("Done. Wrote %d packets.\n", count_packets)
}
