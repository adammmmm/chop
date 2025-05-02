package main

import (
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	var size int
	if len(os.Args) != 2 {
		log.Fatal("Usage: chop <pcap_file>")
	}
	pcapFile := os.Args[1]

	for i := 128; i > 14; i-- {
		handler, err := pcap.OpenOffline(pcapFile)
		if err != nil {
			log.Fatalf("error opening file: %v", err)
		}
		defer handler.Close()

		packetSource := gopacket.NewPacketSource(handler, handler.LinkType())
		if checkChopSize(packetSource.Packets(), i) {
			size = i
			log.Printf("Found valid chop size: %d, run editcap -C %d -T rawip on this type of traffic\n", size, size)
			break
		}
	}
	if size == 0 {
		log.Fatal("could not find valid chop size, most likely not encapsulated")
	}
}

func checkChopSize(packets <-chan gopacket.Packet, chopSize int) bool {
	for packet := range packets {
		if len(packet.Data()) < chopSize {
			continue
		}
		packetData := packet.Data()[chopSize:]
		newPacket := gopacket.NewPacket(packetData, layers.LinkTypeRaw, gopacket.Default)
		if err := newPacket.ErrorLayer(); err != nil {
			return false
		}
	}
	return true
}
