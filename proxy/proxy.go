package proxy

import (
	"fmt"
	"net"
)

// Proxy describes a proxy
type Proxy struct {
	LocalPort  uint16
	RemoteAddr string
	tcpListener	net.Listener
}

// Open implements a method opens the proxy
func (p *Proxy) Open() error {
	var err error

	// Concurrency TCP proxy
	p.tcpListener, err = net.Listen("tcp", fmt.Sprintf(":%d", p.LocalPort))
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}

	go func() {
		for {
			conn, err := p.tcpListener.Accept()
			if err != nil {
				fmt.Println(fmt.Errorf("open: %w", err))
				continue
			}
			fmt.Printf("TCP Proxy connect from %s\n", conn.RemoteAddr())

			// Handle connection
			go func() {
				err := p.handleTcpConnection(conn)
				if err != nil {
					fmt.Println(fmt.Errorf("open: %w", err))
				}
			}()
		}
	}()

	select {}
}

// Close implements a method closes the proxy
func (p *Proxy) Close() {
	p.tcpListener.Close()
}

func (p *Proxy) handleTcpConnection(conn net.Conn) error {
	defer conn.Close()

	// Create new remote connection
	remoteConn, err := net.Dial("tcp", p.RemoteAddr)
	if err != nil {
		return fmt.Errorf("handle tcp connection: %w", err)
	}
	fmt.Printf("TCP connect from %s to %s\n", remoteConn.RemoteAddr(), conn.RemoteAddr())
	defer remoteConn.Close()

	// Bypass all traffic
	err = Bypass(conn, remoteConn)
	if err != nil {
		return fmt.Errorf("handle tcp connection: %w", err)
	}
	return nil
}
