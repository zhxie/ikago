package exec

import (
	"fmt"
	"net"
	"runtime"
)

// AddGlobalFirewallRule adds a rule for firewall blocking certain traffic in all incoming and outgoing packets.
func AddGlobalFirewallRule() error {
	var err error

	switch t := runtime.GOOS; t {
	case "linux":
		err = addGlobalFirewallRule()
	default:
		return fmt.Errorf("os %s not support", t)
	}
	if err != nil {
		return err
	}

	return nil
}

// AddSpecificFirewallRule adds a rule for firewall blocking certain traffic in packets transmission with specific host.
func AddSpecificFirewallRule(ip net.IP, port uint16) error {
	var err error

	switch t := runtime.GOOS; t {
	case "darwin", "freebsd":
		err = addSpecificFirewallRule(ip, port)
	case "linux":
		err = addSpecificFirewallRule(ip, port)
	default:
		return fmt.Errorf("os %s not support", t)
	}
	if err != nil {
		return err
	}

	return nil
}
