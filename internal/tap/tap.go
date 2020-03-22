package tap

import (
	"fmt"
	"github.com/songgao/water"
	"net"
	"runtime"
)

type TAP struct {
	inter *water.Interface
}

// Create returns a TAP with given name
func Create(name string, ip net.IP) (*TAP, error) {
	var err error

	// Config
	var config water.Config

	// Decide OS
	switch runtime.GOOS {
	case "linux", "windows":
		config = createConfig(name)
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
	case "linux", "windows":
		err := bringUp(tap.Name(), ip)
		if err != nil {
			tap.Close()
			return nil, fmt.Errorf("bring up: %w", err)
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
