// +build darwin freebsd

package exec

import (
	"fmt"
	"net"
	"os"
	"os/exec"
)

func addGlobalFirewallRule() error {
	return addFirewallRule("block drop proto tcp from any to any flags R/R")
}

func addSpecificFirewallRule(ip net.IP, port uint16) error {
	return addFirewallRule(fmt.Sprintf("block drop proto tcp from any to %s flags R/R port %d", ip, port))
}

func addFirewallRule(rule string) error {
	file, err := os.OpenFile("/etc/pf-ikago.conf", os.O_WRONLY | os.O_CREATE | os.O_TRUNC, 755)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}

	file.WriteString(rule)

	err = file.Close()
	if err != nil {
		return fmt.Errorf("close: %w", err)
	}

	routeCmd := exec.Command("pfctl", "-f", "/etc/pf-ikago.conf")
	_, err = routeCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}

	return nil
}
