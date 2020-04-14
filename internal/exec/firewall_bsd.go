// +build darwin freebsd

package exec

import (
	"fmt"
	"net"
	"os"
	"os/exec"
)

func addGlobalFirewallRule() error {
	return nil
}

func addSpecificFirewallRule(ip net.IP, port uint16) error {
	file, err := os.OpenFile("./pf.conf", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 755)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}

	_, err = file.WriteString(fmt.Sprintf("block drop proto tcp from any to %s port %d\n", ip, port))
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	err = file.Close()
	if err != nil {
		return fmt.Errorf("close: %w", err)
	}

	routeCmd := exec.Command("pfctl", "-f", "./pf.conf")
	_, err = routeCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}

	routeCmd = exec.Command("pfctl", "-d")
	_, _ = routeCmd.CombinedOutput()

	routeCmd = exec.Command("pfctl", "-e")
	_, err = routeCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}

	return nil
}
