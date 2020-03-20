package tap

import (
	"fmt"
	"github.com/songgao/water"
	"os/exec"
	"runtime"
	"syscall"
)

type TAP struct {
	inter *water.Interface
}

// New returns a new TAP
func New() (*TAP, error) {
	var err error

	// Config
	config := water.Config{
		DeviceType: water.TAP,
	}

	// Decide OS
	switch runtime.GOOS {
	case "linux":
		config.InterfaceName = "ikgtap"
	case "windows":
		break
	default:
		return nil, fmt.Errorf("os %s not support", runtime.GOOS)
	}

	// Create TAP
	inter, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("create tap: %w", err)
	}
	tap := &TAP{inter: inter}

	// Bring TAP up
	switch runtime.GOOS {
	case "linux":
		cmd := exec.Command("ip", "addr", "add", "10.1.0.10/24", "dev", "ikgtap")
		cmd2 := exec.Command("ip", "link", "set", "dev", "ikgtap", "up")
		_, err := cmd.CombinedOutput()
		if err != nil {
			tap.Close()
			return nil, fmt.Errorf("bring tap up: %w", err)
		}
		_, err = cmd2.CombinedOutput()
		if err != nil {
			tap.Close()
			return nil, fmt.Errorf("bring tap up: %w", err)
		}
	case "windows":
		cmd := exec.Command("netsh",
			"interface", "ip", "set", "address", fmt.Sprintf("name=\"%s\"", tap.Name()), "source=static", "addr=10.1.0.10", "mask=255.255.255.0", "gateway=none")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_, err := cmd.CombinedOutput()
		if err != nil {
			tap.Close()
			return nil, fmt.Errorf("bring tap up: %w", err)
		}
	default:
		tap.Close()
		return nil, fmt.Errorf("bring tap up: %w", fmt.Errorf("os %s not support", runtime.GOOS))
	}

	return tap, nil
}

func (t *TAP) Close() {
	t.inter.Close()
}

func (t *TAP) Name() string {
	return t.inter.Name()
}
