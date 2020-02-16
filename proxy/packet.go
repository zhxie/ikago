package proxy

import "net"

// SendTCPPacket implements a method sends a TCP packet
func SendTCPPacket(addr string, data []byte) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(data)
	return err
}

// SendUDPPacket implements a method sends a UDP packet
func SendUDPPacket(addr string, data []byte) error {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(data)
	return err
}
