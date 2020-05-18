package exec

import (
	"fmt"
	"os/exec"
)

func disableIPForwarding() error {
	routeCmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=0")
	_, err := routeCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("exec sysctl: %w", err)
	}

	return nil
}
