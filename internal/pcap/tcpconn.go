package pcap

import (
	"fmt"
	"ikago/internal/crypto"
	"ikago/internal/log"
	"net"
	"time"
)

type TCPConn struct {
	conn  *net.TCPConn
	crypt crypto.Crypt
}

// DialTCP acts like DialTCP for pcap networks.
func DialTCP(dev *Device, srcPort uint16, dstAddr *net.TCPAddr, crypt crypto.Crypt) (*TCPConn, error) {
	srcAddr := &net.TCPAddr{
		IP:   dev.IPAddr().IP,
		Port: int(srcPort),
	}

	log.Infof("Connect to server %s\n", dstAddr.String())

	t := time.Now()

	conn, err := net.DialTCP("tcp4", srcAddr, dstAddr)
	if err != nil {
		return nil, &net.OpError{
			Op:     "dial",
			Net:    "pcap",
			Source: srcAddr,
			Addr:   dstAddr,
			Err:    err,
		}
	}

	duration := time.Now().Sub(t)

	log.Infof("Connected to server %s in %.3f ms (RTT)\n", dstAddr.String(), float64(duration.Microseconds())/1000)

	return &TCPConn{
		conn:  conn,
		crypt: crypt,
	}, nil
}

func (c *TCPConn) Read(b []byte) (n int, err error) {
	p := make([]byte, 65535)
	n, err = c.conn.Read(p)
	if err != nil {
		return 0, err
	}

	dp, err := c.crypt.Decrypt(p[:n])
	if err != nil {
		return 0, &net.OpError{
			Op:     "read",
			Net:    "pcap",
			Source: c.LocalAddr(),
			Addr:   c.RemoteAddr(),
			Err:    fmt.Errorf("decrypt: %w", err),
		}
	}

	copy(b, dp)

	return n, nil
}

func (c *TCPConn) Write(b []byte) (n int, err error) {
	// Encrypt
	contents, err := c.crypt.Encrypt(b)
	if err != nil {
		return 0, &net.OpError{
			Op:     "write",
			Net:    "pcap",
			Source: c.LocalAddr(),
			Addr:   c.RemoteAddr(),
			Err:    fmt.Errorf("encrypt: %w", err),
		}
	}

	return c.conn.Write(contents)
}

func (c *TCPConn) Close() error {
	return c.conn.Close()
}

func (c *TCPConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *TCPConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *TCPConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *TCPConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *TCPConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

type TCPListener struct {
	listener *net.TCPListener
	crypt    crypto.Crypt
}

// ListenTCP acts like ListenTCP for pcap networks.
func ListenTCP(dev *Device, srcPort uint16, crypt crypto.Crypt) (*TCPListener, error) {
	srcAddr := &net.TCPAddr{
		IP:   dev.IPAddr().IP,
		Port: int(srcPort),
	}

	listener, err := net.ListenTCP("tcp4", srcAddr)
	if err != nil {
		return nil, &net.OpError{
			Op:     "listen",
			Net:    "pcap",
			Source: srcAddr,
			Err:    err,
		}
	}

	return &TCPListener{
		listener: listener,
		crypt:    crypt,
	}, nil
}

func (l *TCPListener) Accept() (net.Conn, error) {
	conn, err := l.listener.AcceptTCP()
	if err != nil {
		return nil, err
	}

	return &TCPConn{
		conn:  conn,
		crypt: l.crypt,
	}, nil
}

func (l *TCPListener) Close() error {
	return l.listener.Close()
}

func (l *TCPListener) Addr() net.Addr {
	return l.listener.Addr()
}
