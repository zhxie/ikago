package pcap

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/xtaci/kcp-go"
	"ikago/internal/addr"
	"ikago/internal/crypto"
	"ikago/internal/log"
	"net"
	"sync"
	"time"
)

type clientIndicator struct {
	crypt crypto.Crypt
	seq   uint32
	ack   uint32
}

// Conn is a packet pcap network connection add fake TCP header to all traffic
type Conn struct {
	handshakeConn *RawConn
	conn          *RawConn
	srcPort       uint16
	dstAddr       *net.TCPAddr
	crypt         crypto.Crypt
	isClosed      bool
	clientsLock   sync.RWMutex
	clients       map[string]*clientIndicator
	id            uint16
	readDeadline  time.Time
	writeDeadline time.Time
}

func New() *Conn {
	return &Conn{
		clients: make(map[string]*clientIndicator),
	}
}

// Dial acts like Dial for pcap networks
func Dial(srcDev, dstDev *Device, srcPort uint16, dstAddr *net.TCPAddr, crypt crypto.Crypt) (*Conn, error) {
	var srcAddr *net.TCPAddr

	// Decide IPv4 or IPv6
	if dstAddr.IP.To4() != nil {
		srcAddr = &net.TCPAddr{
			IP:   srcDev.IPv4Addr().IP,
			Port: int(srcPort),
		}
	} else {
		srcAddr = &net.TCPAddr{
			IP:   srcDev.IPv6Addr().IP,
			Port: int(srcPort),
		}
	}

	conn := New()
	conn.srcPort = srcPort
	conn.dstAddr = dstAddr
	conn.crypt = crypt

	// Handshake
	err := conn.handshake(srcDev, dstDev, srcPort, dstAddr)
	if err != nil {
		return nil, &net.OpError{
			Op:     "dial",
			Net:    "pcap",
			Source: srcAddr,
			Addr:   dstAddr,
			Err:    fmt.Errorf("handshake: %w", err),
		}
	}

	rawConn, err := CreateRawConn(srcDev, dstDev, fmt.Sprintf("(tcp && dst port %d && (src host %s && src port %d))", srcAddr.Port, dstAddr.IP, dstAddr.Port))
	if err != nil {
		return nil, &net.OpError{
			Op:     "dial",
			Net:    "pcap",
			Source: srcAddr,
			Addr:   dstAddr,
			Err:    fmt.Errorf("create raw connection: %w", err),
		}
	}

	conn.conn = rawConn

	return conn, nil
}

func (c *Conn) handshake(srcDev, dstDev *Device, srcPort uint16, dstAddr *net.TCPAddr) error {
	handshakeConn, err := CreateRawConn(srcDev, dstDev, fmt.Sprintf("tcp && tcp[tcpflags] & tcp-ack != 0 && dst port %d && (src host %s && src port %d)",
		srcPort, dstAddr.IP.String(), dstAddr.Port))
	if err != nil {
		return fmt.Errorf("create raw connection: %w", err)
	}
	defer handshakeConn.Close()

	// Handshaking with server (SYN)
	err = c.handshakeSYN(handshakeConn)
	if err != nil {
		return fmt.Errorf("synchronize: %w", err)
	}

	log.Infof("Connect to server %s\n", dstAddr.String())

	// Latency test
	start := time.Now()

	type tuple struct {
		packet gopacket.Packet
		err    error
	}
	ct := make(chan tuple)

	go func() {
		packet, err := handshakeConn.ReadPacket()
		if err != nil {
			ct <- tuple{err: fmt.Errorf("read device %s: %w", handshakeConn.LocalDev().Alias, err)}
		}

		ct <- tuple{packet: packet}
	}()
	go func() {
		time.Sleep(3 * time.Second)
		ct <- tuple{err: errors.New("timeout")}
	}()

	t := <-ct
	if t.err != nil {
		return t.err
	}

	transportLayer := t.packet.TransportLayer()
	if transportLayer == nil {
		return errors.New("missing transport layer")
	}
	transportLayerType := transportLayer.LayerType()
	switch transportLayerType {
	case layers.LayerTypeTCP:
		tcpLayer := transportLayer.(*layers.TCP)
		if tcpLayer.RST {
			return errors.New("connection reset")
		}
		if !tcpLayer.SYN {
			return errors.New("invalid packet")
		}
	default:
		return fmt.Errorf("transport layer type %s not support", transportLayerType)
	}

	// Latency test
	duration := time.Now().Sub(start)

	// Handshaking with server (ACK)
	err = c.handshakeACK(t.packet, handshakeConn)
	if err != nil {
		return fmt.Errorf("acknowledge: %w", err)
	}

	log.Infof("Connected to server %s in %.3f ms (two-way)\n", dstAddr.String(), float64(duration.Microseconds())/1000)

	return nil
}

// Listen acts like ListenPacket for pcap networks
func Listen(srcDev, dstDev *Device, srcPort uint16, crypt crypto.Crypt) (*Conn, error) {
	addrs := make([]*net.TCPAddr, 0)
	for _, ip := range srcDev.IPAddrs {
		addrs = append(addrs, &net.TCPAddr{IP: ip.IP, Port: int(srcPort)})
	}
	srcAddrs := addr.MultiTCPAddr{Addrs: addrs}

	handshakeConn, err := CreateRawConn(srcDev, dstDev, fmt.Sprintf("tcp && tcp[tcpflags] & tcp-syn != 0 && dst port %d", srcPort))
	if err != nil {
		return nil, &net.OpError{
			Op:     "dial",
			Net:    "pcap",
			Source: srcAddrs,
			Err:    fmt.Errorf("create handshake connection: %w", err),
		}
	}

	rawConn, err := CreateRawConn(srcDev, dstDev, fmt.Sprintf("tcp && tcp[tcpflags] & tcp-syn == 0 && dst port %d", srcPort))
	if err != nil {
		return nil, &net.OpError{
			Op:     "dial",
			Net:    "pcap",
			Source: srcAddrs,
			Err:    fmt.Errorf("create connection: %w", err),
		}
	}

	conn := New()
	conn.handshakeConn = handshakeConn
	conn.conn = rawConn
	conn.srcPort = srcPort
	conn.crypt = crypt

	// Handle handshaking
	go func() {
		for {
			packet, err := conn.handshakeConn.ReadPacket()
			if err != nil {
				if conn.isClosed {
					return
				}
				log.Errorln(&net.OpError{
					Op:     "listen",
					Net:    "pcap",
					Source: srcAddrs,
					Err:    fmt.Errorf("read device %s: %w", conn.handshakeConn.LocalDev().Alias, err),
				})
				continue
			}

			// Parse packet
			indicator, err := ParsePacket(packet)
			if err != nil {
				log.Errorln(&net.OpError{
					Op:     "handshake",
					Net:    "pcap",
					Source: srcAddrs,
					Err:    fmt.Errorf("parse packet: %w", err),
				})
				continue
			}

			// Handshaking with client (SYN+ACK)
			if indicator.TCPLayer().SYN {
				err := conn.handshakeSYNACK(indicator)
				if err != nil {
					log.Errorln(&net.OpError{
						Op:     "listen",
						Net:    "pcap",
						Source: conn.corLocalAddr(indicator.Src()),
						Addr:   indicator.Src(),
						Err:    fmt.Errorf("handshake: %w", err),
					})
					continue
				}

				log.Infof("Connect from client %s\n", indicator.Src().String())
			}
		}
	}()

	return conn, nil
}

func (c *Conn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)

	return n, err
}

func (c *Conn) handshakeSYN(conn *RawConn) error {
	var (
		transportLayer gopacket.SerializableLayer
		networkLayer   gopacket.SerializableLayer
		linkLayer      gopacket.SerializableLayer
	)

	// Initial client
	client := &clientIndicator{crypt: c.crypt}

	// Create layers
	transportLayer, networkLayer, linkLayer, err := CreateLayers(c.srcPort, uint16(c.dstAddr.Port), client.seq, 0, conn, c.dstAddr.IP, c.id, 128, conn.RemoteDev().HardwareAddr)
	if err != nil {
		return err
	}

	// Make TCP layer SYN
	FlagTCPLayer(transportLayer.(*layers.TCP), true, false, false)

	// Serialize layers
	data, err := Serialize(linkLayer, networkLayer, transportLayer)
	if err != nil {
		return fmt.Errorf("serialize: %w", err)
	}

	// Write packet data
	_, err = conn.Write(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	// TCP Seq
	client.seq++

	// Map client
	c.clientsLock.Lock()
	c.clients[c.dstAddr.String()] = client
	c.clientsLock.Unlock()

	// IPv4 Id
	if networkLayer.LayerType() == layers.LayerTypeIPv4 {
		c.id++
	}

	return nil
}

func (c *Conn) handshakeSYNACK(indicator *PacketIndicator) error {
	var (
		transportLayerType gopacket.LayerType
		newTransportLayer  gopacket.SerializableLayer
		newNetworkLayer    gopacket.SerializableLayer
		newLinkLayer       gopacket.SerializableLayer
	)

	transportLayerType = indicator.TransportLayerType()
	if transportLayerType != layers.LayerTypeTCP {
		return fmt.Errorf("transport layer type %s not support", transportLayerType)
	}

	// Initial TCP Seq
	src := indicator.Src()
	client := &clientIndicator{
		crypt: c.crypt,
		seq:   0,
		ack:   indicator.TCPLayer().Seq + 1,
	}

	// Create layers
	newTransportLayer, newNetworkLayer, newLinkLayer, err := CreateLayers(indicator.DstPort(), indicator.SrcPort(), client.seq, client.ack, c.handshakeConn, indicator.SrcIP(), c.id, 64, indicator.SrcHardwareAddr())
	if err != nil {
		return fmt.Errorf("create layers: %w", err)
	}

	// Make TCP layer SYN & ACK
	FlagTCPLayer(newTransportLayer.(*layers.TCP), true, false, true)

	// Serialize layers
	data, err := Serialize(newLinkLayer, newNetworkLayer, newTransportLayer)
	if err != nil {
		return fmt.Errorf("serialize: %w", err)
	}

	// Write packet data
	_, err = c.handshakeConn.Write(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	// TCP Seq
	client.seq++

	// Map client
	c.clientsLock.Lock()
	c.clients[src.String()] = client
	c.clientsLock.Unlock()

	// IPv4 Id
	if newNetworkLayer.LayerType() == layers.LayerTypeIPv4 {
		c.id++
	}

	return nil
}

func (c *Conn) handshakeACK(packet gopacket.Packet, conn *RawConn) error {
	var (
		indicator          *PacketIndicator
		transportLayerType gopacket.LayerType
		newTransportLayer  gopacket.SerializableLayer
		newNetworkLayer    gopacket.SerializableLayer
		newLinkLayer       gopacket.SerializableLayer
	)

	// Parse packet
	indicator, err := ParsePacket(packet)
	if err != nil {
		return fmt.Errorf("parse packet: %w", err)
	}

	transportLayerType = indicator.TransportLayerType()
	if transportLayerType != layers.LayerTypeTCP {
		return fmt.Errorf("transport layer type %s not support", transportLayerType)
	}

	// Client
	c.clientsLock.RLock()
	client := c.clients[indicator.Src().String()]
	c.clientsLock.RUnlock()

	// TCP Ack
	client.ack = indicator.TCPLayer().Seq + 1

	// Create layers
	newTransportLayer, newNetworkLayer, newLinkLayer, err = CreateLayers(indicator.DstPort(), indicator.SrcPort(), client.seq, client.ack, conn, indicator.SrcIP(), c.id, 128, indicator.SrcHardwareAddr())
	if err != nil {
		return fmt.Errorf("create layers: %w", err)
	}

	// Make TCP layer ACK
	FlagTCPLayer(newTransportLayer.(*layers.TCP), false, false, true)

	// Serialize layers
	data, err := Serialize(newLinkLayer, newNetworkLayer, newTransportLayer)
	if err != nil {
		return fmt.Errorf("serialize: %w", err)
	}

	// Write packet data
	_, err = conn.Write(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	// IPv4 Id
	if newNetworkLayer.LayerType() == layers.LayerTypeIPv4 {
		c.id++
	}

	return nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.dstAddr)
}

func (c *Conn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	packet, addr, err := c.readPacketFrom()
	if err != nil {
		return 0, addr, &net.OpError{
			Op:     "read",
			Net:    "pcap",
			Source: c.corLocalAddr(addr),
			Addr:   addr,
			Err:    err,
		}
	}

	if packet.ApplicationLayer() == nil {
		return 0, addr, nil
	}

	// Client
	c.clientsLock.RLock()
	client, ok := c.clients[addr.String()]
	c.clientsLock.RUnlock()
	if !ok {
		return 0, addr, &net.OpError{
			Op:     "read",
			Net:    "pcap",
			Source: c.corLocalAddr(addr),
			Addr:   addr,
			Err:    fmt.Errorf("client %s unauthorized", addr.String()),
		}
	}

	// TCP Ack
	client.ack = client.ack + uint32(len(packet.ApplicationLayer().LayerContents()))

	// Decrypt
	contents, err := client.crypt.Decrypt(packet.ApplicationLayer().LayerContents())
	if err != nil {
		return 0, addr, &net.OpError{
			Op:     "read",
			Net:    "pcap",
			Source: c.corLocalAddr(addr),
			Addr:   addr,
			Err:    fmt.Errorf("decrypt: %w", err),
		}
	}

	copy(p, contents)

	return len(contents), addr, err
}

func (c *Conn) readPacketFrom() (packet gopacket.Packet, addr net.Addr, err error) {
	type tuple struct {
		packet gopacket.Packet
		err    error
	}

	ch := make(chan tuple)
	go func() {
		packet, err := c.conn.ReadPacket()
		if err != nil {
			ch <- tuple{err: err}
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
			ch <- tuple{err: &timeoutError{Err: "timeout"}}
		}()
	}

	t := <-ch
	if t.err != nil {
		return nil, nil, t.err
	}

	// Parse packet
	indicator, err := ParsePacket(t.packet)
	if err != nil {
		return nil, nil, fmt.Errorf("parse: %w", err)
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
		return nil, indicator.Src(), fmt.Errorf("transport layer type %s not support", transportLayerType)
	}
}

func (c *Conn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
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
			Source: c.corLocalAddr(addr),
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

		// Client
		c.clientsLock.RLock()
		client, ok := c.clients[addr.String()]
		c.clientsLock.RUnlock()
		if !ok {
			ch <- fmt.Errorf("client %s unrecognized", addr.String())
			return
		}

		// Create layers
		transportLayer, networkLayer, linkLayer, err := CreateLayers(c.srcPort, dstPort, client.seq, client.ack, c.conn, dstIP, c.id, 128, c.conn.dstDev.HardwareAddr)
		if err != nil {
			ch <- fmt.Errorf("create layers: %w", err)
			return
		}

		// Encrypt
		contents, err := client.crypt.Encrypt(p)
		if err != nil {
			ch <- fmt.Errorf("encrypt: %w", err)
			return
		}

		// Serialize layers
		data, err := Serialize(linkLayer, networkLayer, transportLayer, gopacket.Payload(contents))
		if err != nil {
			ch <- fmt.Errorf("serialize: %w", err)
			return
		}

		// Write packet data
		_, err = c.conn.Write(data)
		if err != nil {
			ch <- fmt.Errorf("write: %w", err)
			return
		}

		// TCP Seq
		client.seq = client.seq + uint32(len(contents))

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
			ch <- &timeoutError{Err: "timeout"}
		}()
	}

	err = <-ch
	if err != nil {
		return 0, &net.OpError{
			Op:     "write",
			Net:    "pcap",
			Source: c.corLocalAddr(addr),
			Addr:   addr,
			Err:    err,
		}
	}

	return len(p), nil
}

func (c *Conn) Close() error {
	c.isClosed = true

	err := c.conn.Close()
	if err != nil {
		return &net.OpError{
			Op:     "close",
			Net:    "pcap",
			Source: c.corLocalAddr(c.dstAddr),
			Addr:   c.dstAddr,
			Err:    err,
		}
	}

	return nil
}

// LocalDev returns the local device
func (c *Conn) LocalDev() *Device {
	return c.conn.LocalDev()
}

func (c *Conn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: c.LocalDev().IPAddr().IP, Port: int(c.srcPort)}
}

func (c *Conn) corLocalAddr(dstAddr net.Addr) net.Addr {
	if dstAddr == nil {
		addrs := make([]*net.TCPAddr, 0)

		for _, ip := range c.LocalDev().IPAddrs {
			addrs = append(addrs, &net.TCPAddr{
				IP:   ip.IP,
				Port: int(c.srcPort),
			})
		}

		return &addr.MultiTCPAddr{Addrs: addrs}
	}

	var (
		ip   net.IP
		port uint16
	)

	switch t := dstAddr.(type) {
	case *net.TCPAddr:
		ip = dstAddr.(*net.TCPAddr).IP
		port = uint16(dstAddr.(*net.TCPAddr).Port)
	case *net.UDPAddr:
		ip = dstAddr.(*net.UDPAddr).IP
		port = uint16(dstAddr.(*net.UDPAddr).Port)
	default:
		panic(fmt.Errorf("type %T not support", t))
	}

	if ip.To4() != nil {
		return &net.TCPAddr{
			IP:   c.LocalDev().IPv4Addr().IP,
			Port: int(port),
		}
	}

	return &net.TCPAddr{
		IP:   c.LocalDev().IPv6Addr().IP,
		Port: int(port),
	}
}

// RemoteDev returns the remote device
func (c *Conn) RemoteDev() *Device {
	return c.conn.RemoteDev()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.dstAddr
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

// DialWithKCP connects to the remote address in the pcap connection with KCP support
func DialWithKCP(srcDev, dstDev *Device, srcPort uint16, dstAddr *net.TCPAddr, crypt crypto.Crypt) (*kcp.UDPSession, error) {
	conn, err := Dial(srcDev, dstDev, srcPort, dstAddr, crypt)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	block, err := kcp.NewNoneBlockCrypt(nil)
	if err != nil {
		return nil, fmt.Errorf("crypt: %w", err)
	}

	session, err := kcp.NewConn(dstAddr.String(), block, 10, 3, conn)
	if err != nil {
		return nil, fmt.Errorf("new: %w", err)
	}

	return session, nil
}

// ListenWithKCP listens for incoming packets addressed to the local address in the pcap connection with KCP support
func ListenWithKCP(srcDev, dstDev *Device, srcPort uint16, crypt crypto.Crypt) (*kcp.Listener, error) {
	conn, err := Listen(srcDev, dstDev, srcPort, crypt)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	block, err := kcp.NewNoneBlockCrypt(nil)
	if err != nil {
		return nil, fmt.Errorf("crypt: %w", err)
	}

	listener, err := kcp.ServeConn(block, 10, 3, conn)
	if err != nil {
		return nil, fmt.Errorf("serve: %w", err)
	}

	return listener, err
}
