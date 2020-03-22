package tap

import (
	"fmt"
	"github.com/songgao/water"
	"net"
	"os/exec"
)

func createConfig(name string) water.Config {
	config := water.Config{DeviceType: water.TAP}
	config.Name = name

	return config
}

func bringUp(name string, ip net.IP) error {
	cmd := exec.Command("ip", "addr", "add", fmt.Sprintf("%s/24", ip.String()), "dev", name)
	cmd2 := exec.Command("ip", "link", "set", "dev", name, "up")
	_, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}
	_, err = cmd2.CombinedOutput()
	return err
}
