package proxy

import (
	"io"
	"net"
)

// Bypass implements a method bypasses all traffic between connections
func Bypass(from, to net.Conn) error {
	chanErr := make(chan error, 1)

	go func() {
		_, err := io.Copy(from, to)
		chanErr <- err
	}()
	go func() {
		_, err := io.Copy(to, from)
		chanErr <- err
	}()

	err := <-chanErr
	return err
}
