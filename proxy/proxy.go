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

	p.tcpListener, err = net.Listen("tcp", fmt.Sprintf(":%d", p.LocalPort))
	if err != nil {
		return err
	}

	go func() {
		for {
			conn, err := p.tcpListener.Accept()
			if err != nil {
				fmt.Println(err)
				continue
			}
			fmt.Printf("tcp connect from %s\n", conn.RemoteAddr())
			go func() {
				err := p.handleTcpConnection(conn)
				if err != nil {
					fmt.Println(err)
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

	remoteConn, err := net.Dial("tcp", p.RemoteAddr)
	if err != nil {
		return err
	}
	fmt.Printf("tcp connect to %s from %s\n", remoteConn.RemoteAddr(), conn.RemoteAddr())
	defer remoteConn.Close()

	err = Bypass(conn, remoteConn)
	if err != nil {
		return err
	}
	return nil
}
