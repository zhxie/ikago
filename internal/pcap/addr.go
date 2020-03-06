package pcap

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// IPVersionOption describes the preference of IP version
type IPVersionOption int

const (
	// IPv4AndIPv6 describes IPv4 or IPv6 are both accepted
	IPv4AndIPv6 IPVersionOption = iota
	// IPv4Only describes only IPv4 is accepted
	IPv4Only
	// IPv6Only describes only IPv6 is accepted
	IPv6Only
)

// IPPort describes a network endpoint with an IP and a port
type IPPort struct {
	IP   net.IP
	Port uint16
}

func (i IPPort) String() string {
	var ip string
	if i.IP.To4() != nil {
		ip = i.IP.String()
	} else {
		ip = fmt.Sprintf("[%s]", i.IP)
	}
	return fmt.Sprintf("%s:%d", ip, i.Port)
}

// ParseIPPort returns an IPPort by the given string of address
func ParseIPPort(s string) (*IPPort, error) {
	if s[0] == '[' {
		// IPv6
		strs := strings.Split(s[1:], "]:")
		if len(strs) != 2 {
			return nil, fmt.Errorf("parse ip port: %w", fmt.Errorf("invalid ipv6 address %s", s))
		}
		ip := net.ParseIP(strs[0])
		if ip == nil {
			return nil, fmt.Errorf("parse ip port: %w", fmt.Errorf("invalid ipv6 ip %s", strs[0]))
		}
		port, err := strconv.ParseUint(strs[1], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("parse ip port: %w", fmt.Errorf("invalid port %s", strs[1]))
		}
		return &IPPort{
			IP:   ip,
			Port: uint16(port),
		}, nil
	}
	// IPv4
	strs := strings.Split(s, ":")
	if len(strs) != 2 {
		return nil, fmt.Errorf("parse ip port: %w", fmt.Errorf("invalid ipv4 address %s", s))
	}
	ip := net.ParseIP(strs[0])
	if ip == nil {
		return nil, fmt.Errorf("parse ip port: %w", fmt.Errorf("invalid ipv4 ip %s", strs[0]))
	}
	port, err := strconv.ParseUint(strs[1], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("parse ip port: %w", fmt.Errorf("invalid port %s", strs[1]))
	}
	return &IPPort{
		IP:   ip,
		Port: uint16(port),
	}, nil
}
