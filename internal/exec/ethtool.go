package exec

import (
	"fmt"
	"runtime"
)

// DisableGRO disables generic receive offload
func DisableGRO(inter string) error {
	var err error

	switch t := runtime.GOOS; t {
	case "linux":
		err = disableGRO(inter)
	default:
		return fmt.Errorf("os %s not support", t)
	}
	if err != nil {
		return err
	}

	return nil
}
