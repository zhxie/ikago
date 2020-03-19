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

func (t *TAP) Open() error {
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
		return fmt.Errorf("create tap: %w", fmt.Errorf("os %s not support", runtime.GOOS))
	}

	// Create TAP
	t.inter, err = water.New(config)
	if err != nil {
		return fmt.Errorf("create tap: %w", err)
	}

	// Bring TAP up
	switch runtime.GOOS {
	case "linux":
		cmd := exec.Command("ip", "addr", "add", "10.1.0.10/24", "dev", "ikgtap")
		cmd2 := exec.Command("ip", "link", "set", "dev", "ikgtap", "up")
		_, err := cmd.CombinedOutput()
		if err != nil {
			t.Close()
			return fmt.Errorf("bring tap up: %w", err)
		}
		_, err = cmd2.CombinedOutput()
		if err != nil {
			t.Close()
			return fmt.Errorf("bring tap up: %w", err)
		}
	case "windows":
		cmd := exec.Command("netsh",
			"interface", "ip", "set", "address", fmt.Sprintf("name=\"%s\"", t.inter.Name()), "source=static", "addr=10.1.0.10", "mask=255.255.255.0", "gateway=none")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_, err := cmd.CombinedOutput()
		if err != nil {
			t.Close()
			return fmt.Errorf("bring tap up: %w", err)
		}
	default:
		t.Close()
		return fmt.Errorf("bring tap up: %w", fmt.Errorf("os %s not support", runtime.GOOS))
	}

	return nil
}

func (t *TAP) Close() {
	t.inter.Close()
}

func (t *TAP) Name() string {
	return t.inter.Name()
}
