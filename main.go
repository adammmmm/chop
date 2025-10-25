package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	minChopSize = 14
	maxChopSize = 128
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: chop <pcap_file>")
		os.Exit(1)
	}
	pcapFile := filepath.Clean(os.Args[1])
	result := findValidChopSize(pcapFile)
	if result != "" {
		fmt.Println(result)
	}
}

// findValidChopSize takes a pcap file and iterates downwards from maxChopSize to minChopSize
// until it finds one that results in valid packets.
func findValidChopSize(pcapFile string) string {
	for chopSize := maxChopSize; chopSize > minChopSize; chopSize-- {
		handler, err := pcap.OpenOffline(pcapFile)
		if err != nil {
			return fmt.Sprintf("error opening file: %v", err)
		}
		defer handler.Close()

		packetSource := gopacket.NewPacketSource(handler, handler.LinkType())
		if isValidChopSize(packetSource.Packets(), chopSize, layers.LinkTypeEthernet) {
			return fmt.Sprintf("Found valid chop size: %d, run editcap -C %d <inputfilename> <outputfilename>", chopSize, chopSize)
		}
		if isValidChopSize(packetSource.Packets(), chopSize, layers.LinkTypeRaw) {
			return fmt.Sprintf("Found valid chop size: %d, run editcap -C %d -T rawip <inputfilename> <outputfilename>", chopSize, chopSize)
		}
	}
	return "coludn't find valid chop size, most likely not encapsulated"
}

// isValidChopSize goes through all packets in a packets channel and slices them by chopSize,
// It returns true if all packets are valid post slicing, and false if any are invalid.
func isValidChopSize(packets <-chan gopacket.Packet, chopSize int, linkType layers.LinkType) bool {
	for packet := range packets {
		if len(packet.Data()) < chopSize {
			// skip packets that are too small to chop
			continue
		}
		packetData := packet.Data()[chopSize:]
		newPacket := gopacket.NewPacket(packetData, linkType, gopacket.Default)
		if err := newPacket.ErrorLayer(); err != nil {
			return false
		}
	}
	return true
}
