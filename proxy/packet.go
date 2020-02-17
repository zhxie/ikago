package proxy

import (
	"fmt"
	"net"
)

// SendTCPPacket implements a method sends a TCP packet
func SendTCPPacket(addr string, data []byte) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("send tcp packet: %w", err)
	}
	defer conn.Close()
	_, err = conn.Write(data)
	if err != nil {
		return fmt.Errorf("send tcp packet: %w", err)
	}
	return nil
}

// SendUDPPacket implements a method sends a UDP packet
func SendUDPPacket(addr string, data []byte) error {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return fmt.Errorf("send udp packet: %w", err)
	}
	defer conn.Close()
	_, err = conn.Write(data)
	if err != nil {
		return fmt.Errorf("send udp packet: %w", err)
	}
	return nil
}
