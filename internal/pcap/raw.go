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

// MaxMTU is the max transmission and receive unit in pcap raw conn.
const MaxMTU = 1600

// RawConn is a raw network connection.
type RawConn struct {
	srcDev *Device
	dstDev *Device
	handle *pcap.Handle
}

func createPureRawConn(dev, filter string) (*RawConn, error) {
	handle, err := pcap.OpenLive(dev, MaxMTU, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	err = handle.SetBPFFilter(filter)
	if err != nil {
		return nil, err
	}

	return &RawConn{
		handle: handle,
	}, nil
}

// CreateRawConn creates a raw connection between devices with BPF filter.
func CreateRawConn(srcDev, dstDev *Device, filter string) (*RawConn, error) {
	conn, err := createPureRawConn(srcDev.Name(), filter)
	if err != nil {
		return nil, err
	}

	conn.srcDev = srcDev
	conn.dstDev = dstDev

	return conn, nil
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
func (c *RawConn) ReadPacket() (gopacket.Packet, error) {
	b := make([]byte, MaxMTU)

	_, err := c.Read(b)
	if err != nil {
		return nil, err
	}

	packet := gopacket.NewPacket(b, c.handle.LinkType(), gopacket.NoCopy)

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
	return c.dstDev.IsLoop()
}

// Reader is a reader reads packets from a pcap file.
type Reader struct {
	handle *pcap.Handle
	ps     *gopacket.PacketSource
}

// CreateReader creates a reader reading a pcap file.
func CreateReader(file string) (*Reader, error) {
	handle, err := pcap.OpenOffline(file)
	if err != nil {
		return nil, err
	}

	ps := gopacket.NewPacketSource(handle, handle.LinkType())

	return &Reader{
		handle: handle,
		ps:     ps,
	}, nil
}

func (r *Reader) Read(b []byte) (n int, err error) {
	packet, err := r.ReadPacket()
	if err != nil {
		return 0, err
	}

	copy(b, packet.Data())

	return len(packet.Data()), nil
}

func (r *Reader) ReadPacket() (gopacket.Packet, error) {
	packet, err := r.ps.NextPacket()
	if err != nil {
		return nil, err
	}

	return packet, nil
}

func (r *Reader) Close() error {
	r.handle.Close()

	return nil
}
