package exec

import (
	"fmt"
	"os/exec"
)

func disableGRO(inter string) error {
	routeCmd := exec.Command("ethtool", "--offload", inter, "gro", "off")
	_, err := routeCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("exec ethtool: %w", err)
	}

	return nil
}
