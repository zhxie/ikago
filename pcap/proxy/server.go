package proxy

import (
	"fmt"
	"net"
)

// ConnData describes data from a connection
type ConnData struct {
	Data []byte
	Conn net.Conn
}

// Server describes a server of a TCP proxy
type Server struct {
	Port     uint16
	listener net.Listener
	c        chan ConnData
}

// Open opens a listener for clients' connection
func (p *Server) Open() error {
	var err error
	p.c = make(chan ConnData, 1000)

	// Concurrency TCP proxy
	p.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", p.Port))
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}

	go func() {
		for {
			conn, err := p.listener.Accept()
			if err != nil {
				fmt.Println(fmt.Errorf("open: %w", err))
				return
			}
			fmt.Printf("Connect from client %s\n", conn.RemoteAddr())

			// Handle connection
			go func() {
				p.handle(conn)
			}()
		}
	}()

	return nil
}

// Close closes the listener
func (p *Server) Close() {
	p.listener.Close()
}

// Read reads data from connections
func (p *Server) Read() chan ConnData {
	return p.c
}

func (p *Server) handle(conn net.Conn) {
	defer conn.Close()

	for {
		d := make([]byte, 1600)
		_, err := conn.Read(d)
		if err != nil {
			fmt.Println(fmt.Errorf("handle: %w", fmt.Errorf("conn %s: %w", conn.RemoteAddr(), err)))
			return
		}
		p.c <- ConnData{Data: d, Conn: conn}
	}
}
