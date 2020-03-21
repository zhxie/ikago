package addr

import (
	"fmt"
	"net"
	"strconv"
)

// ICMPQueryAddr represents the address of a ICMP query end point.
type ICMPQueryAddr struct {
	IP net.IP
	Id uint16
}

func (i ICMPQueryAddr) String() string {
	return fmt.Sprintf("%s@%d", formatIP(i.IP), i.Id)
}

func (i ICMPQueryAddr) Network() string {
	return "icmp query"
}

// ParseTCPAddr returns an TCPAddr by the given string of address
func ParseTCPAddr(s string) (*net.TCPAddr, error) {
	ipStr, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return nil, fmt.Errorf("split host port: %w", err)
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid ip %s", ipStr)
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("parse port %s: %w", portStr, err)
	}

	return &net.TCPAddr{IP: ip, Port: int(port)}, nil
}

func formatIP(ip net.IP) string {
	if ip == nil {
		return ""
	}

	if ip.To4() != nil {
		return ip.String()
	} else {
		return fmt.Sprintf("[%s]", ip)
	}
}
