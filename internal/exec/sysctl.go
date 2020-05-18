package exec

import (
	"fmt"
	"runtime"
)

// DisableIPForwarding disables IP forwarding.
func DisableIPForwarding() error {
	var err error

	switch t := runtime.GOOS; t {
	case "darwin", "freebsd":
		err = disableIPForwarding()
	case "linux":
		err = disableIPForwarding()
	default:
		return fmt.Errorf("os %s not support", t)
	}
	if err != nil {
		return err
	}

	return nil
}
