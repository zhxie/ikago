package pcap

import (
	"fmt"
	"github.com/google/gopacket"
	"net"
)

// Quintuple describes a tuple with source and destination IP and port and protocol in a packet
type Quintuple struct {
	SrcIP    string
	SrcPort  uint16
	DstIP    string
	DstPort  uint16
	Protocol gopacket.LayerType
}

// SendTCPPacket implements a method sends a TCP packet
func SendTCPPacket(addr string, data []byte) error {
	// Create connection
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("send tcp packet: %w", err)
	}
	defer conn.Close()

	// Write data
	_, err = conn.Write(data)
	if err != nil {
		return fmt.Errorf("send tcp packet: %w", err)
	}
	return nil
}

// SendUDPPacket implements a method sends a UDP packet
func SendUDPPacket(addr string, data []byte) error {
	// Create connection
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return fmt.Errorf("send udp packet: %w", err)
	}
	defer conn.Close()

	// Write data
	_, err = conn.Write(data)
	if err != nil {
		return fmt.Errorf("send udp packet: %w", err)
	}
	return nil
}
