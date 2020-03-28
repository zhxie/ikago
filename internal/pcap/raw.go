package pcap

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
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

// RawConn is a raw network connection.
type RawConn struct {
	srcDev *Device
	dstDev *Device
	handle *pcap.Handle
}

// CreateRawConn creates a raw connection between devices with BPF filter.
func CreateRawConn(srcDev, dstDev *Device, filter string) (*RawConn, error) {
	handle, err := pcap.OpenLive(srcDev.name, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	err = handle.SetBPFFilter(filter)
	if err != nil {
		return nil, err
	}

	return &RawConn{
		srcDev: srcDev,
		dstDev: dstDev,
		handle: handle,
	}, nil
}

func (c *RawConn) Read(b []byte) (n int, err error) {
	d, _, err := c.handle.ReadPacketData()
	if err != nil {
		return 0, err
	}

	copy(b, d)

	return len(d), nil
}

// ReadPacket reads packet from the connection.
func (c *RawConn) ReadPacket() (packet gopacket.Packet, err error) {
	b := make([]byte, 1600)

	_, err = c.Read(b)
	if err != nil {
		return nil, err
	}

	packet = gopacket.NewPacket(b, c.handle.LinkType(), gopacket.Default)

	return packet, nil
}

func (c *RawConn) Write(b []byte) (n int, err error) {
	err = c.handle.WritePacketData(b)
	if err != nil {
		return 0, err
	}

	return len(b), nil
}

func (c *RawConn) Close() error {
	c.handle.Close()

	return nil
}

// LocalDev returns the local device.
func (c *RawConn) LocalDev() *Device {
	return c.srcDev
}

// RemoteDev returns the remote device.
func (c *RawConn) RemoteDev() *Device {
	return c.dstDev
}

// IsLoop returns if the connection is to a loopback device.
func (c *RawConn) IsLoop() bool {
	return c.dstDev.isLoop
}
