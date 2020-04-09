// +build !darwin,!linux,!freebsd

package exec

import "net"

func addGlobalFirewallRule() error {
	return nil
}

func addSpecificFirewallRule(ip net.IP, port uint16) error {
	return nil
}
