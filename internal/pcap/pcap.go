package pcap

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"net"
	"time"
)

type TimeoutError struct {
	Err string
}

func (err *TimeoutError) Error() string {
	return err.Err
}

func (err *TimeoutError) Timeout() bool {
	return true
}

type Conn struct {
	SrcDev        *Device
	DstDev        *Device
	handle        *pcap.Handle
	readDeadline  time.Time
	writeDeadline time.Time
}

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
				Err:    &TimeoutError{Err: "timeout"},
			}}
		}()
	}

	t := <-ch
	if t.err != nil {
		return 0, err
	}

	copy(b, t.data)

	return len(b), nil
}

// ReadPacket reads packet from the connection.
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
				Err:    &TimeoutError{Err: "timeout"},
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
	return c.SrcDev.IPAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.DstDev.IPAddr()
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
