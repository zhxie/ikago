package addr

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type IPEndpoint interface {
	// IP returns the IP of IP endpoint
	IP() net.IP
	String() string
}

// IP describes a network endpoint with an IP only
type IP struct {
	MemberIP net.IP
}

func (i *IP) IP() net.IP {
	return i.MemberIP
}

func (i IP) String() string {
	return formatIP(i.MemberIP)
}

// IPPort describes a network endpoint with an IP and a port
type IPPort struct {
	MemberIP net.IP
	Port     uint16
}

func (i *IPPort) IP() net.IP {
	return i.MemberIP
}

func (i IPPort) String() string {
	return fmt.Sprintf("%s:%d", formatIP(i.MemberIP), i.Port)
}

// ParseIPPort returns an IPPort by the given string of address
func ParseIPPort(s string) (*IPPort, error) {
	if s[0] == '[' {
		// IPv6
		strs := strings.Split(s[1:], "]:")
		if len(strs) != 2 {
			return nil, fmt.Errorf("parse address: %w", errors.New("invalid"))
		}
		ip := net.ParseIP(strs[0])
		if ip == nil {
			return nil, fmt.Errorf("parse ip %s: %w", strs[0], errors.New("invalid"))
		}
		port, err := strconv.ParseUint(strs[1], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("parse port %s: %w", strs[1], errors.New("invalid"))
		}
		return &IPPort{
			MemberIP: ip,
			Port:     uint16(port),
		}, nil
	}
	// IPv4
	strs := strings.Split(s, ":")
	if len(strs) != 2 {
		return nil, fmt.Errorf("parse address: %w", errors.New("invalid"))
	}
	ip := net.ParseIP(strs[0])
	if ip == nil {
		return nil, fmt.Errorf("parse ip %s: %w", strs[0], errors.New("invalid"))
	}
	port, err := strconv.ParseUint(strs[1], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("parse port %s: %w", strs[1], errors.New("invalid"))
	}
	return &IPPort{
		MemberIP: ip,
		Port:     uint16(port),
	}, nil
}

// IPId describes a network endpoint with at an IP and an Id
type IPId struct {
	MemberIP net.IP
	Id       uint16
}

func (i *IPId) IP() net.IP {
	return i.MemberIP
}

func (i IPId) String() string {
	return fmt.Sprintf("%s@%d", formatIP(i.MemberIP), i.Id)
}

func formatIP(ip net.IP) string {
	if ip.To4() != nil {
		return ip.String()
	} else {
		return fmt.Sprintf("[%s]", ip)
	}
}
