// +build !linux,!windows

package tap

import (
	"fmt"
	"github.com/songgao/water"
	"runtime"
)

func createConfig(name string) water.Config {
	panic(fmt.Errorf("os %s not support", runtime.GOOS))
}

func bringUp(name string, ip net.IP) error {
	panic(fmt.Errorf("os %s not support", runtime.GOOS))
}
