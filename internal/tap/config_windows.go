package tap

import (
	"fmt"
	"github.com/songgao/water"
	"net"
	"os/exec"
	"syscall"
)

func createConfig(name string) water.Config {
	config := water.Config{DeviceType: water.TAP}

	if name != "" {
		config.PlatformSpecificParams = water.PlatformSpecificParams{
			ComponentID:   "tap0901",
			InterfaceName: name,
		}
	}

	return config
}

func bringUp(name string, ip net.IP) error {
	cmd := exec.Command("netsh",
		"interface", "ip", "set", "address", fmt.Sprintf("name=\"%s\"", name), "source=static", fmt.Sprintf("addr=%s", ip.String()), "mask=255.255.255.0", "gateway=none")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_, err := cmd.CombinedOutput()
	return err
}
