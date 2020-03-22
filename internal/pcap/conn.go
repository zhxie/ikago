package pcap

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"ikago/internal/addr"
	"net"
	"time"
)

type timeoutError struct {
	Err string
}

func (err *timeoutError) Error() string {
	return err.Err
}

func (err *timeoutError) Timeout() bool {
	return true
}

// Conn describes a pcap connection
type Conn struct {
	SrcDev        *Device
	DstDev        *Device
	handle        *pcap.Handle
	readDeadline  time.Time
	writeDeadline time.Time
}

// Dial acts like Dial for pcap networks
func Dial(srcDev *Device, dstDev *Device, filter string) (*Conn, error) {
	handle, err := pcap.OpenLive(srcDev.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, &net.OpError{
			Op:     "dial",
			Net:    "pcap",
			Source: srcDev.IPAddr(),
			Addr:   dstDev.IPAddr(),
			Err:    err,
		}
	}

	err = handle.SetBPFFilter(filter)
	if err != nil {
		return nil, &net.OpError{
			Op:     "dial",
			Net:    "pcap",
			Source: srcDev.IPAddr(),
			Addr:   dstDev.IPAddr(),
			Err:    err,
		}
	}

	return &Conn{
		SrcDev: srcDev,
		DstDev: dstDev,
		handle: handle,
	}, nil
}

func (c *Conn) Read(b []byte) (n int, err error) {
	type tuple struct {
		data []byte
		err  error
	}

	ch := make(chan tuple, 1)

	go func() {
		d, _, err := c.handle.ReadPacketData()
		if err != nil {
			ch <- tuple{err: &net.OpError{
				Op:     "read",
				Net:    "pcap",
				Source: c.LocalAddr(),
				Addr:   c.RemoteAddr(),
				Err:    err,
			}}
		}

		ch <- tuple{data: d}
	}()
	// Timeout
	if !c.readDeadline.IsZero() {
		go func() {
			duration := c.readDeadline.Sub(time.Now())
			if duration > 0 {
				time.Sleep(duration)
			}
			ch <- tuple{err: &net.OpError{
				Op:     "read",
				Net:    "pcap",
				Source: c.LocalAddr(),
				Addr:   c.RemoteAddr(),
				Err:    &timeoutError{Err: "timeout"},
			}}
		}()
	}

	t := <-ch
	if t.err != nil {
		return 0, t.err
	}

	copy(b, t.data)

	return len(b), nil
}

// ReadPacket reads packet from the connection
func (c *Conn) ReadPacket() (packet gopacket.Packet, err error) {
	b := make([]byte, 1600)

	_, err = c.Read(b)
	if err != nil {
		return nil, err
	}

	packet = gopacket.NewPacket(b, c.handle.LinkType(), gopacket.Default)

	return packet, nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	ch := make(chan error, 1)

	go func() {
		err = c.handle.WritePacketData(b)
		if err != nil {
			ch <- &net.OpError{
				Op:     "write",
				Net:    "pcap",
				Source: c.LocalAddr(),
				Addr:   c.RemoteAddr(),
				Err:    err,
			}
		}

		ch <- nil
	}()
	// Timeout
	if !c.writeDeadline.IsZero() {
		go func() {
			duration := c.writeDeadline.Sub(time.Now())
			if duration > 0 {
				time.Sleep(duration)
			}
			ch <- &net.OpError{
				Op:     "write",
				Net:    "pcap",
				Source: c.LocalAddr(),
				Addr:   c.RemoteAddr(),
				Err:    &timeoutError{Err: "timeout"},
			}
		}()
	}

	err = <-ch
	if err != nil {
		return 0, err
	}

	return len(b), nil
}

func (c *Conn) Close() error {
	c.handle.Close()

	return nil
}

func (c *Conn) LocalAddr() net.Addr {
	ips := make([]net.IP, 0)

	for _, ip := range c.SrcDev.IPAddrs {
		ips = append(ips, ip.IP)
	}

	return &addr.MultiIPAddr{IPs: ips}
}

func (c *Conn) RemoteAddr() net.Addr {
	ips := make([]net.IP, 0)

	for _, ip := range c.DstDev.IPAddrs {
		ips = append(ips, ip.IP)
	}

	return &addr.MultiIPAddr{IPs: ips}
}

// IsLoop returns if the connection is to a loopback device
func (c *Conn) IsLoop() bool {
	return c.DstDev.IsLoop
}

func (c *Conn) SetDeadline(t time.Time) error {
	readDeadline := c.readDeadline

	err := c.SetReadDeadline(t)
	if err != nil {
		return err
	}

	err = c.SetWriteDeadline(t)
	if err != nil {
		_ = c.SetReadDeadline(readDeadline)
		return err
	}

	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t

	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t

	return nil
}
