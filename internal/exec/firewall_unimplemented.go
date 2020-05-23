// +build !darwin,!linux,!freebsd

package exec

import "net"

func addGlobalFirewallRule() error {
	return nil
}

func addSpecificFirewallRule(_ net.IP, _ uint16) error {
	return nil
}
