package exec

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
)

func addGlobalFirewallRule() error {
	routeCmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=0")
	_, err := routeCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("exec sysctl: %w", err)
	}

	routeCmd = exec.Command("iptables", "-A", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP")
	_, err = routeCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("exec iptables: %w", err)
	}

	return nil
}

func addSpecificFirewallRule(ip net.IP, port uint16) error {
	routeCmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=0")
	_, err := routeCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("exec sysctl: %w", err)
	}

	routeCmd = exec.Command("iptables", "-A", "OUTPUT", "-s", ip.String(), "-p", "tcp", "--dport", strconv.Itoa(int(port)), "-j", "DROP")
	_, err = routeCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("exec iptables: %w", err)
	}

	return nil
}
