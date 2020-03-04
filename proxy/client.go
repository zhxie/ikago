package proxy

import (
	"../log"
	"fmt"
	"net"
)

// Client describes a client of a TCP proxy
type Client struct {
	LocalPort uint16
	Server    string
	conn      net.Conn
	c         chan []byte
}

// Open opens the connection to the server
func (p *Client) Open() error {
	var err error
	p.c = make(chan []byte, 1000)

	// Create new connection
	p.conn, err = net.Dial("tcp", p.Server)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}

	// Handle data
	go p.handle()

	return nil
}

// Close closes the connection
func (p *Client) Close() {
	p.conn.Close()
}

// Write writes data to the connection
func (p *Client) Write(data []byte) error {
	_, err := p.conn.Write(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// Read reads data from the connection
func (p *Client) Read() chan []byte {
	return p.c
}

func (p *Client) handle() {
	defer p.Close()
	for {
		d := make([]byte, 1600)
		n, err := p.conn.Read(d)
		if err != nil {
			log.Errorln(fmt.Errorf("handle: %w", err))
			return
		}
		p.c <- d[:n]
	}
}
