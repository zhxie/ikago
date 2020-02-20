package proxy

import (
	"fmt"
	"io"
	"net"
)

// Bypass implements a method bypasses all traffic between connections
func Bypass(from, to net.Conn) error {
	chanErr := make(chan error, 1)

	// Copy from local to remote
	go func() {
		_, err := io.Copy(from, to)
		chanErr <- fmt.Errorf("bypass from: %w", err)
	}()
	// Copy from remote to local
	go func() {
		_, err := io.Copy(to, from)
		chanErr <- fmt.Errorf("bypass to: %w", err)
	}()

	err := <-chanErr
	return err
}
