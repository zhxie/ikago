package pcap

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"ikago/internal/crypto"
	"net"
	"time"
)

// KCPBackConn is a generic packet-oriented pcap network connection
type KCPBackConn struct {
	rawConn       *RawConn
	srcAddr       *net.TCPAddr
	crypt         crypto.Crypt
	seq           uint32
	ack           uint32
	id            uint16
	readDeadline  time.Time
	writeDeadline time.Time
}

// ListenPacket announces on the local network address
func ListenPacket(srcDev, dstDev *Device, srcAddr *net.TCPAddr, crypt crypto.Crypt) (*KCPBackConn, error) {
	rawConn, err := CreateRawConn(srcDev, dstDev, fmt.Sprintf("tcp && dst port %d", srcAddr.Port))
	if err != nil {
		return nil, &net.OpError{
			Op:     "dial",
			Net:    "pcap",
			Source: srcAddr,
			Err:    fmt.Errorf("create raw connection: %w", err),
		}
	}

	return &KCPBackConn{
		rawConn: rawConn,
		srcAddr: srcAddr,
		crypt:   crypt,
	}, nil
}

func (c *KCPBackConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	packet, addr, err := c.readPacketFrom()
	if err != nil {
		return 0, addr, err
	}

	if packet.ApplicationLayer() == nil {
		return 0, addr, err
	}

	contents, err := c.crypt.Decrypt(packet.ApplicationLayer().LayerContents())
	if err != nil {
		return 0, addr, fmt.Errorf("decrypt: %w", err)
	}

	copy(p, contents)

	return len(contents), addr, err
}

func (c *KCPBackConn) readPacketFrom() (packet gopacket.Packet, addr net.Addr, err error) {
	type tuple struct {
		packet gopacket.Packet
		err    error
	}

	ch := make(chan tuple)
	go func() {
		packet, err := c.rawConn.ReadPacket()
		if err != nil {
			ch <- tuple{err: &net.OpError{
				Op:     "read",
				Net:    "pcap",
				Source: c.LocalAddr(),
				Err:    err,
			}}
		}

		ch <- tuple{packet: packet}
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
				Err:    &timeoutError{Err: "timeout"},
			}}
		}()
	}

	t := <-ch
	if t.err != nil {
		return nil, nil, t.err
	}

	// Parse packet
	indicator, err := ParsePacket(t.packet)
	if err != nil {
		return nil, nil, &net.OpError{
			Op:     "read",
			Net:    "pcap",
			Source: c.LocalAddr(),
			Err:    fmt.Errorf("parse: %w", err),
		}
	}

	transportLayerType := indicator.TransportLayerType()
	switch transportLayerType {
	case layers.LayerTypeTCP:
		return t.packet, &net.UDPAddr{
			IP:   indicator.SrcIP(),
			Port: int(indicator.SrcPort()),
		}, nil
	case layers.LayerTypeUDP:
		return t.packet, indicator.Src(), nil
	default:
		return nil, nil, &net.OpError{
			Op:     "read",
			Net:    "pcap",
			Source: c.LocalAddr(),
			Addr:   indicator.Src(),
			Err:    fmt.Errorf("transport layer type %s not support", transportLayerType),
		}
	}
}

func (c *KCPBackConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	var (
		dstIP   net.IP
		dstPort uint16
	)

	ch := make(chan error)

	switch t := addr.(type) {
	case *net.TCPAddr:
		dstIP = addr.(*net.TCPAddr).IP
		dstPort = uint16(addr.(*net.TCPAddr).Port)
	case *net.UDPAddr:
		dstIP = addr.(*net.UDPAddr).IP
		dstPort = uint16(addr.(*net.UDPAddr).Port)
	default:
		return 0, &net.OpError{
			Op:     "write",
			Net:    "pcap",
			Source: c.LocalAddr(),
			Addr:   addr,
			Err:    fmt.Errorf("type %T not support", t),
		}
	}

	go func() {
		var (
			transportLayer   gopacket.SerializableLayer
			networkLayer     gopacket.SerializableLayer
			linkLayer        gopacket.SerializableLayer
		)

		// Create layers
		transportLayer, networkLayer, linkLayer, err := CreateLayers(uint16(c.srcAddr.Port), dstPort, c.seq, c.ack, c.rawConn, dstIP, c.id, 128, c.rawConn.dstDev.HardwareAddr)
		if err != nil {
			ch <- fmt.Errorf("create layers: %w", err)
		}

		// Encrypt
		contents, err := c.crypt.Encrypt(p)
		if err != nil {
			ch <- fmt.Errorf("encrypt: %w", err)
		}

		// Serialize layers
		data, err := Serialize(linkLayer, networkLayer, transportLayer, gopacket.Payload(contents))
		if err != nil {
			ch <- fmt.Errorf("serialize: %w", err)
			return
		}

		// Write packet data
		_, err = c.rawConn.Write(data)
		if err != nil {
			ch <- fmt.Errorf("write: %w", err)
			return
		}

		// TCP Seq
		c.seq = c.seq + uint32(len(contents))

		// IPv4 Id
		if networkLayer.LayerType() == layers.LayerTypeIPv4 {
			c.id++
		}

		ch <- nil
		return
	}()
	// Timeout
	if !c.writeDeadline.IsZero() {
		go func() {
			duration := c.readDeadline.Sub(time.Now())
			if duration > 0 {
				time.Sleep(duration)
			}
			ch <- &net.OpError{
				Op:     "write",
				Net:    "pcap",
				Source: c.LocalAddr(),
				Addr:   addr,
				Err:    &timeoutError{Err: "timeout"},
			}
		}()
	}

	err = <-ch
	if err != nil {
		return 0, err
	}

	return len(p), nil
}

func (c *KCPBackConn) Close() error {
	return c.rawConn.Close()
}

func (c *KCPBackConn) LocalDev() *Device {
	return c.rawConn.LocalDev()
}

func (c *KCPBackConn) LocalAddr() net.Addr {
	return c.srcAddr
}

func (c *KCPBackConn) SetDeadline(t time.Time) error {
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

func (c *KCPBackConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t

	return nil
}

func (c *KCPBackConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t

	return nil
}
