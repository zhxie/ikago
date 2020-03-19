package filter

import (
	"encoding/hex"
	"errors"
	"fmt"
	"ikago/internal/addr"
	"net"
	"strconv"
)

// FilterType describes the type of filters
type Type int

const (
	// IP describes the filter contains an IP only
	IP Type = iota
	// IPPort describes the filter contains an IP and a port
	IPPort
	// Port describes the filter contains a port only
	Port
)

// Filter describes the BPF filter
type Filter interface {
	// FilterType returns the type of the filter
	FilterType() Type
	// SrcBPFFilter returns a string describes the BPF filter on the source side
	SrcBPFFilter() string
	// DstBPFFilter returns a string describes the BPF filter on the destination side
	DstBPFFilter() string
}

// IPFilter describes a filter of IP
type IPFilter struct {
	IP net.IP
}

func (filter IPFilter) FilterType() Type {
	return IP
}

func (filter IPFilter) SrcBPFFilter() string {
	return fmt.Sprintf("(src host %s)", fullString(filter.IP))
}

func (filter IPFilter) DstBPFFilter() string {
	return fmt.Sprintf("(dst host %s)", fullString(filter.IP))
}

func (filter IPFilter) String() string {
	return filter.IP.String()
}

// IPPortFilter describes a filter with an IP and a port
type IPPortFilter struct {
	IP   net.IP
	Port uint16
}

func (filter IPPortFilter) FilterType() Type {
	return IPPort
}

func (filter IPPortFilter) SrcBPFFilter() string {
	return fmt.Sprintf("(src host %s && src port %d)", fullString(filter.IP), filter.Port)
}

func (filter IPPortFilter) DstBPFFilter() string {
	return fmt.Sprintf("(dst host %s && dst port %d)", fullString(filter.IP), filter.Port)
}

func (filter IPPortFilter) String() string {
	return addr.IPPort{MemberIP: filter.IP, Port: filter.Port}.String()
}

// PortFilter describes a filter of port
type PortFilter struct {
	Port uint16
}

func (filter PortFilter) FilterType() Type {
	return Port
}

func (filter PortFilter) SrcBPFFilter() string {
	return fmt.Sprintf("(src port %d)", filter.Port)
}

func (filter PortFilter) DstBPFFilter() string {
	return fmt.Sprintf("(dst port %d)", filter.Port)
}

func (filter PortFilter) String() string {
	return fmt.Sprintf(":%d", filter.Port)
}

// ParseFilter returns a Filter by the given string of filter
func ParseFilter(s string) (Filter, error) {
	// Guess port
	if s[0] == ':' {
		port, err := strconv.ParseUint(s[1:], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("parse port %s: %w", s[1:], err)
		}
		return &PortFilter{Port: uint16(port)}, nil
	}
	// Guess IP and port
	ipPort, err := addr.ParseIPPort(s)
	if err != nil {
		// IP
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("parse ip %s: %w", s, errors.New("invalid"))
		}
		return &IPFilter{IP: ip}, nil
	}
	// IPPort
	return &IPPortFilter{IP: ipPort.MemberIP, Port: ipPort.Port}, nil
}

func fullString(ip net.IP) string {
	if ip.To4() != nil {
		return ip.String()
	}
	dst := make([]byte, hex.EncodedLen(len(ip)))
	_ = hex.Encode(dst, ip)
	return string(dst[0:4]) + ":" +
		string(dst[4:8]) + ":" +
		string(dst[8:12]) + ":" +
		string(dst[12:16]) + ":" +
		string(dst[16:20]) + ":" +
		string(dst[20:24]) + ":" +
		string(dst[24:28]) + ":" +
		string(dst[28:])
}
