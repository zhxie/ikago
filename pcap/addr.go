package pcap

import (
	"fmt"
	"net"
)

type IPVersionOption int

const IPv4AndIPv6 IPVersionOption = 0
const IPv4Only IPVersionOption = 1
const IPv6Only IPVersionOption = 2

type IPPort struct {
	IP              net.IP
	Port            uint16
	IsPortUndefined bool
}

func (i IPPort) String() string {
	if i.IsPortUndefined {
		return i.IP.String()
	}
	return fmt.Sprintf("%s:%d", i.IP, i.Port)
}
