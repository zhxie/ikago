package pcap

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/xtaci/kcp-go"
	"ikago/internal/addr"
	"ikago/internal/config"
	"ikago/internal/crypto"
	"ikago/internal/log"
	"math"
	"net"
	"sync"
	"time"
)

type clientIndicator struct {
	crypt crypto.Crypt
	seq   uint32
	ack   uint32
}

const establishDeadline = 3 * time.Second
const keepFragments = 30 * time.Second

// FakeTCPConn is a packet pcap network connection add fake TCP header to all traffic.
type FakeTCPConn struct {
	lock          sync.Mutex
	conn          *RawConn
	defrag        Defragmenter
	srcPort       uint16
	dstAddr       *net.TCPAddr
	crypt         crypto.Crypt
	mtu           int
	appear        time.Time
	isConnected   bool
	isReconnected bool
	isClosed      bool
	clientsLock   sync.RWMutex
	clients       map[string]*clientIndicator
	id            uint16
	readDeadline  time.Time
	writeDeadline time.Time
}

func newConn() *FakeTCPConn {
	conn := &FakeTCPConn{
		defrag:  NewEasyDefragmenter(),
		mtu:     MaxEthernetMTU,
		clients: make(map[string]*clientIndicator),
	}
	conn.defrag.SetDeadline(keepFragments)
	return conn
}

// DialFakeTCP establishes FakeTCP connection for pcap networks.
func DialFakeTCP(srcDev, dstDev *Device, srcPort uint16, dstAddr *net.TCPAddr, crypt crypto.Crypt, mtu int) (*FakeTCPConn, error) {
	srcAddr := &net.TCPAddr{
		IP:   srcDev.IPAddr().IP,
		Port: int(srcPort),
	}

	conn, err := dialFakeTCPPassive(srcDev, dstDev, srcPort, dstAddr, crypt, mtu)
	if err != nil {
		return nil, &net.OpError{
			Op:     "dial",
			Net:    "pcap",
			Source: srcAddr,
			Addr:   dstAddr,
			Err:    err,
		}
	}

	log.Infof("Connect to server %s\n", dstAddr.String())

	// Handshake
	err = conn.handshakeSYN()
	if err != nil {
		return nil, &net.OpError{
			Op:     "dial",
			Net:    "pcap",
			Source: srcAddr,
			Addr:   dstAddr,
			Err:    fmt.Errorf("handshake: %w", err),
		}
	}

	conn.appear = time.Now()

	go func() {
		time.Sleep(establishDeadline)

		if !conn.isConnected {
			log.Errorf("Cannot receive response from server %s, is your network down?\n", dstAddr.String())
		}
	}()

	return conn, nil
}

func dialFakeTCPPassive(srcDev, dstDev *Device, srcPort uint16, dstAddr *net.TCPAddr, crypt crypto.Crypt, mtu int) (*FakeTCPConn, error) {
	srcAddr := &net.TCPAddr{
		IP:   srcDev.IPAddr().IP,
		Port: int(srcPort),
	}

	filter, err := addr.SrcBPFFilter(dstAddr)
	if err != nil {
		return nil, fmt.Errorf("parse filter %s: %w", dstAddr, err)
	}
	dstIP := &net.IPAddr{IP: dstAddr.IP}
	filter2, err := addr.SrcBPFFilter(dstIP)
	if err != nil {
		return nil, fmt.Errorf("parse filter %s: %w", dstIP, err)
	}

	rawConn, err := CreateRawConn(srcDev, dstDev, fmt.Sprintf("ip && ((tcp && dst port %d && %s) || ((ip[6:2] & 0x1fff) != 0 && %s))", srcAddr.Port, filter, filter2))
	if err != nil {
		return nil, fmt.Errorf("create raw connection: %w", err)
	}

	conn := newConn()
	conn.srcPort = srcPort
	conn.dstAddr = dstAddr
	conn.crypt = crypt
	conn.mtu = mtu
	conn.conn = rawConn

	return conn, nil
}

func listenFakeTCPMulticast(srcDev, dstDev *Device, srcPort uint16, crypt crypto.Crypt, mtu int) (*FakeTCPConn, error) {
	addrs := make([]*net.TCPAddr, 0)
	for _, ip := range srcDev.IPAddrs() {
		addrs = append(addrs, &net.TCPAddr{IP: ip.IP, Port: int(srcPort)})
	}
	srcAddrs := addr.MultiTCPAddr{Addrs: addrs}

	rawConn, err := CreateRawConn(srcDev, dstDev, fmt.Sprintf("tcp && dst port %d", srcPort))
	if err != nil {
		return nil, &net.OpError{
			Op:     "dial",
			Net:    "pcap",
			Source: srcAddrs,
			Err:    fmt.Errorf("create connection: %w", err),
		}
	}

	conn := newConn()
	conn.srcPort = srcPort
	conn.crypt = crypt
	conn.mtu = mtu
	conn.conn = rawConn

	return conn, nil
}

func (c *FakeTCPConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)

	return n, err
}

func (c *FakeTCPConn) handshakeSYN() error {
	var (
		transportLayer gopacket.SerializableLayer
		networkLayer   gopacket.SerializableLayer
		linkLayer      gopacket.SerializableLayer
	)

	c.lock.Lock()
	defer c.lock.Unlock()

	// Client
	c.clientsLock.RLock()
	client, ok := c.clients[c.RemoteAddr().String()]
	c.clientsLock.RUnlock()
	if !ok {
		// Initial TCP Seq
		client = &clientIndicator{
			crypt: c.crypt,
			seq:   0,
		}

		// Map client
		c.clientsLock.Lock()
		c.clients[c.RemoteAddr().String()] = client
		c.clientsLock.Unlock()
	}

	// Create layers
	transportLayer, networkLayer, linkLayer, err := CreateLayers(c.srcPort, uint16(c.dstAddr.Port), client.seq, client.ack, c.conn, c.dstAddr.IP, c.id, 128, c.RemoteDev().HardwareAddr())
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
	_, err = c.conn.Write(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	// TCP Seq
	client.seq++

	// IPv4 Id
	if networkLayer.LayerType() == layers.LayerTypeIPv4 {
		c.id++
	}

	srcAddr := &net.TCPAddr{
		IP:   c.LocalDev().IPAddr().IP,
		Port: int(c.srcPort),
	}
	log.Verbosef("Send TCP SYN: %s -> %s\n", srcAddr.String(), c.RemoteAddr().String())

	return nil
}

func (c *FakeTCPConn) handshakeSYNACK(indicator *PacketIndicator) error {
	var (
		err               error
		newTransportLayer gopacket.SerializableLayer
		newNetworkLayer   gopacket.SerializableLayer
		newLinkLayer      gopacket.SerializableLayer
	)

	c.lock.Lock()
	defer c.lock.Unlock()

	// Client
	c.clientsLock.RLock()
	client, ok := c.clients[indicator.Src().String()]
	c.clientsLock.RUnlock()
	if !ok {
		// Initial TCP Seq
		client = &clientIndicator{
			crypt: c.crypt,
			seq:   0,
		}

		// Map client
		c.clientsLock.Lock()
		c.clients[indicator.Src().String()] = client
		c.clientsLock.Unlock()
	}
	client.ack = indicator.TCPLayer().Seq + 1

	// Create layers
	newTransportLayer, newNetworkLayer, newLinkLayer, err = CreateLayers(indicator.DstPort(), indicator.SrcPort(), client.seq, client.ack, c.conn, indicator.SrcIP(), c.id, 64, indicator.SrcHardwareAddr())
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
	_, err = c.conn.Write(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	// TCP Seq
	client.seq++

	// IPv4 Id
	if newNetworkLayer.LayerType() == layers.LayerTypeIPv4 {
		c.id++
	}

	srcAddr := &net.TCPAddr{
		IP:   c.LocalDev().IPAddr().IP,
		Port: int(indicator.DstPort()),
	}
	log.Verbosef("Send TCP SYN+ACK: %s <- %s\n", indicator.Src().String(), srcAddr.String())

	return nil
}

func (c *FakeTCPConn) handshakeACK(indicator *PacketIndicator) error {
	var (
		err               error
		newTransportLayer gopacket.SerializableLayer
		newNetworkLayer   gopacket.SerializableLayer
		newLinkLayer      gopacket.SerializableLayer
	)

	c.lock.Lock()
	defer c.lock.Unlock()

	// Client
	c.clientsLock.RLock()
	client, ok := c.clients[indicator.Src().String()]
	c.clientsLock.RUnlock()
	if !ok {
		return fmt.Errorf("client %s unauthorized", indicator.Src().String())
	}

	// TCP Ack
	client.ack = indicator.TCPLayer().Seq + 1

	// Create layers
	newTransportLayer, newNetworkLayer, newLinkLayer, err = CreateLayers(indicator.DstPort(), indicator.SrcPort(), client.seq, client.ack, c.conn, indicator.SrcIP(), c.id, 128, indicator.SrcHardwareAddr())
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
	_, err = c.conn.Write(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	// IPv4 Id
	if newNetworkLayer.LayerType() == layers.LayerTypeIPv4 {
		c.id++
	}

	srcAddr := &net.TCPAddr{
		IP:   c.LocalDev().IPAddr().IP,
		Port: int(indicator.DstPort()),
	}
	log.Verbosef("Send TCP ACK: %s -> %s\n", srcAddr.String(), indicator.Src().String())

	return nil
}

func (c *FakeTCPConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.RemoteAddr())
}

func (c *FakeTCPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	type tuple struct {
		indicator *PacketIndicator
		err       error
	}

	ch := make(chan tuple)
	go func() {
		for {
			packet, err := c.conn.ReadPacket()
			if err != nil {
				ch <- tuple{err: err}
				return
			}

			// Parse packet
			indicator, err := ParsePacket(packet)
			if err != nil {
				ch <- tuple{err: fmt.Errorf("parse packet: %w", err)}
				return
			}

			// Handle fragments
			indicator, err = c.defrag.Append(indicator)
			if err != nil {
				ch <- tuple{err: fmt.Errorf("defrag: %w", err)}
				return
			}
			if indicator != nil {
				ch <- tuple{indicator: indicator}
				return
			}
		}
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

	tu := <-ch
	if tu.err != nil {
		return 0, nil, &net.OpError{
			Op:     "read",
			Net:    "pcap",
			Source: c.LocalAddr(),
			Err:    err,
		}
	}

	indicator := tu.indicator
	if indicator.TransportLayer() == nil {
		addr = &net.IPAddr{IP: indicator.SrcIP()}
	} else {
		switch t := indicator.TransportLayer().LayerType(); t {
		case layers.LayerTypeTCP:
			addr = &net.UDPAddr{
				IP:   indicator.SrcIP(),
				Port: int(indicator.SrcPort()),
			}
		case layers.LayerTypeUDP:
			addr = indicator.Src()
		default:
			return 0, nil, &net.OpError{
				Op:     "read",
				Net:    "pcap",
				Source: c.LocalAddr(),
				Err:    fmt.Errorf("transport layer type %s not support", t),
			}
		}
	}

	// Check TCP flags
	if indicator.TransportLayer() != nil && indicator.TransportLayer().LayerType() == layers.LayerTypeTCP {
		if indicator.IsRST() {
			log.Errorf("Receive TCP RST: %s <- %s\n", indicator.Dst().String(), addr.String())

			// Re-establish connection
			err := c.Reconnect()
			if err != nil {
				return 0, addr, &net.OpError{
					Op:     "read",
					Net:    "pcap",
					Source: c.LocalAddr(),
					Addr:   addr,
					Err:    fmt.Errorf("reconnect: %w", err),
				}
			}
		}
		if indicator.IsFIN() {
			log.Infof("Receive TCP FIN: %s <- %s\n", indicator.Dst().String(), addr.String())
		}
	}

	// Reply TCP SYN
	if indicator.TransportLayer() != nil && indicator.TransportLayer().LayerType() == layers.LayerTypeTCP {
		if indicator.IsSYN() {
			// SYN+ACK
			if indicator.IsACK() {
				log.Verbosef("Receive TCP SYN+ACK: %s <- %s\n", indicator.Dst().String(), addr.String())

				if !c.isConnected {
					t := time.Now()
					duration := t.Sub(c.appear)

					log.Infof("Connected to server %s in %.3f ms (RTT)\n", addr.String(), float64(duration.Microseconds())/1000)

					c.isConnected = true
				}
				c.isReconnected = true

				err = c.handshakeACK(indicator)
			} else {
				log.Verbosef("Receive TCP SYN: %s -> %s\n", addr.String(), indicator.Dst().String())

				err = c.handshakeSYNACK(indicator)
			}
			if err != nil {
				return 0, addr, &net.OpError{
					Op:     "read",
					Net:    "pcap",
					Source: c.LocalAddr(),
					Addr:   addr,
					Err:    fmt.Errorf("handshake: %w", err),
				}
			}

			return 0, addr, nil
		}
	}

	if indicator.Payload() == nil {
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
			Source: c.LocalAddr(),
			Addr:   addr,
			Err:    fmt.Errorf("client %s unauthorized", addr.String()),
		}
	}

	// TCP Ack, always use the expected one
	if indicator.TransportLayer() != nil && indicator.TransportLayer().LayerType() == layers.LayerTypeTCP {
		expectedAck := indicator.TCPLayer().Seq + uint32(len(indicator.Payload()))
		if expectedAck > client.ack || (math.MaxUint32-indicator.TCPLayer().Seq < uint32(len(indicator.Payload()))) {
			client.ack = expectedAck
		}
	}

	// Decrypt
	contents, err := client.crypt.Decrypt(indicator.Payload())
	if err != nil {
		return 0, addr, &net.OpError{
			Op:     "read",
			Net:    "pcap",
			Source: c.LocalAddr(),
			Addr:   addr,
			Err:    fmt.Errorf("decrypt: %w", err),
		}
	}

	copy(p, contents)

	return len(contents), addr, err
}

func (c *FakeTCPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
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
			transportLayer gopacket.SerializableLayer
			networkLayer   gopacket.SerializableLayer
			linkLayer      gopacket.SerializableLayer
			fragments      [][]byte
		)

		c.lock.Lock()
		defer c.lock.Unlock()

		// Client
		c.clientsLock.RLock()
		client, ok := c.clients[addr.String()]
		c.clientsLock.RUnlock()
		if !ok {
			ch <- fmt.Errorf("client %s unrecognized", addr.String())
			return
		}

		// Create layers
		transportLayer, networkLayer, linkLayer, err := CreateLayers(c.srcPort, dstPort, client.seq, client.ack, c.conn, dstIP, c.id, 128, c.conn.RemoteDev().HardwareAddr())
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

		// Fragment
		fragments, err = CreateFragmentPackets(linkLayer.(gopacket.Layer), networkLayer.(gopacket.Layer), transportLayer.(gopacket.Layer), gopacket.Payload(contents), c.mtu)
		if err != nil {
			ch <- fmt.Errorf("fragment: %w", err)
			return
		}

		// Write packet data
		for _, frag := range fragments {
			_, err := c.conn.Write(frag)
			if err != nil {
				ch <- fmt.Errorf("write: %w", err)
				return
			}
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
			Source: c.LocalAddr(),
			Addr:   addr,
			Err:    err,
		}
	}

	return len(p), nil
}

func (c *FakeTCPConn) Close() error {
	c.isClosed = true

	err := c.conn.Close()
	if err != nil {
		return &net.OpError{
			Op:   "close",
			Net:  "pcap",
			Addr: c.LocalAddr(),
			Err:  err,
		}
	}

	return nil
}

// LocalDev returns the local device.
func (c *FakeTCPConn) LocalDev() *Device {
	return c.conn.LocalDev()
}

func (c *FakeTCPConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: c.LocalDev().IPAddr().IP, Port: int(c.srcPort)}
}

// RemoteDev returns the remote device.
func (c *FakeTCPConn) RemoteDev() *Device {
	return c.conn.RemoteDev()
}

func (c *FakeTCPConn) RemoteAddr() net.Addr {
	return c.dstAddr
}

func (c *FakeTCPConn) SetDeadline(t time.Time) error {
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

func (c *FakeTCPConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t

	return nil
}

func (c *FakeTCPConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t

	return nil
}

// Reconnect reconnects the connection by sending TCP SYN.
func (c *FakeTCPConn) Reconnect() error {
	c.isReconnected = false

	err := c.handshakeSYN()
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	go func() {
		time.Sleep(establishDeadline)

		if !c.isReconnected {
			log.Errorf("Cannot receive response from server %s, is it down?\n", c.RemoteAddr().String())
		}
	}()

	return nil
}

// FakeTCPListener is a pcap network listener in FakeTCP network.
type FakeTCPListener struct {
	conn    *RawConn
	srcPort uint16
	crypt   crypto.Crypt
	mtu     int
	clients map[string]net.Conn
}

// ListenFakeTCP announces on the local network address in FakeTCP network.
func ListenFakeTCP(srcDev, dstDev *Device, srcPort uint16, crypt crypto.Crypt, mtu int) (*FakeTCPListener, error) {
	addrs := make([]*net.TCPAddr, 0)
	for _, ip := range srcDev.IPAddrs() {
		addrs = append(addrs, &net.TCPAddr{IP: ip.IP, Port: int(srcPort)})
	}
	srcAddrs := addr.MultiTCPAddr{Addrs: addrs}

	conn, err := CreateRawConn(srcDev, dstDev, fmt.Sprintf("tcp && tcp[tcpflags] & tcp-syn != 0 && dst port %d", srcPort))
	if err != nil {
		return nil, &net.OpError{
			Op:     "dial",
			Net:    "pcap",
			Source: srcAddrs,
			Err:    fmt.Errorf("create handshake connection: %w", err),
		}
	}

	listener := &FakeTCPListener{
		conn:    conn,
		srcPort: srcPort,
		crypt:   crypt,
		mtu:     mtu,
		clients: make(map[string]net.Conn),
	}

	return listener, nil
}

func (l *FakeTCPListener) Accept() (net.Conn, error) {
	packet, err := l.conn.ReadPacket()
	if err != nil {
		return nil, &net.OpError{
			Op:   "accept",
			Net:  "pcap",
			Addr: l.Addr(),
			Err:  fmt.Errorf("read device %s: %w", l.Dev().Alias(), err),
		}
	}

	// Parse packet
	indicator, err := ParsePacket(packet)
	if err != nil {
		return nil, &net.OpError{
			Op:   "accept",
			Net:  "pcap",
			Addr: l.Addr(),
			Err:  fmt.Errorf("parse packet: %w", err),
		}
	}

	_, ok := l.clients[indicator.Src().String()]
	if ok {
		// Duplicate
		return nil, nil
	}

	conn, err := dialFakeTCPPassive(l.Dev(), l.conn.RemoteDev(), l.srcPort, indicator.Src().(*net.TCPAddr), l.crypt, l.mtu)
	if err != nil {
		return nil, &net.OpError{
			Op:     "dial",
			Net:    "pcap",
			Source: l.Addr(),
			Addr:   indicator.Src(),
			Err:    err,
		}
	}

	conn.clients[indicator.Src().String()] = &clientIndicator{
		crypt: l.crypt,
		seq:   0,
		ack:   0,
	}

	// Handshaking with client (SYN+ACK)
	err = conn.handshakeSYNACK(indicator)
	if err != nil {
		return nil, &net.OpError{
			Op:     "handshake",
			Net:    "pcap",
			Source: l.Addr(),
			Addr:   indicator.Src(),
			Err:    err,
		}
	}

	// Map client
	l.clients[indicator.Src().String()] = conn

	return conn, nil
}

func (l *FakeTCPListener) Close() error {
	err := l.conn.Close()
	if err != nil {
		return &net.OpError{
			Op:   "close",
			Net:  "pcap",
			Addr: l.Addr(),
			Err:  err,
		}
	}

	return nil
}

// Dev returns the device.
func (l *FakeTCPListener) Dev() *Device {
	return l.conn.LocalDev()
}

func (l *FakeTCPListener) Addr() net.Addr {
	return &net.TCPAddr{
		IP:   l.Dev().IPAddr().IP,
		Port: int(l.srcPort),
	}
}

// DialFakeTCPWithKCP connects to the remote address in the FakeTCP network with KCP support.
func DialFakeTCPWithKCP(srcDev, dstDev *Device, srcPort uint16, dstAddr *net.TCPAddr, crypt crypto.Crypt, mtu int, config *config.KCPConfig) (*kcp.UDPSession, error) {
	conn, err := DialFakeTCP(srcDev, dstDev, srcPort, dstAddr, crypt, mtu)
	if err != nil {
		return nil, err
	}

	sess, err := kcp.NewConn(dstAddr.String(), nil, config.DataShard, config.ParityShard, conn)
	if err != nil {
		return nil, &net.OpError{
			Op:     "dial",
			Net:    "pcap",
			Source: conn.LocalAddr(),
			Addr:   conn.RemoteAddr(),
			Err:    fmt.Errorf("kcp: %w", err),
		}
	}

	// Tuning
	err = tuneKCP(sess, config)
	if err != nil {
		sess.Close()
		return nil, &net.OpError{
			Op:     "dial",
			Net:    "pcap",
			Source: conn.LocalAddr(),
			Addr:   conn.RemoteAddr(),
			Err:    fmt.Errorf("tune: %w", err),
		}
	}

	return sess, nil
}

// ListenFakeTCPWithKCP listens for incoming packets addressed to the local address in the FakeTCP network with KCP support.
func ListenFakeTCPWithKCP(srcDev, dstDev *Device, srcPort uint16, crypt crypto.Crypt, mtu int, config *config.KCPConfig) (*kcp.Listener, error) {
	conn, err := listenFakeTCPMulticast(srcDev, dstDev, srcPort, crypt, mtu)
	if err != nil {
		return nil, err
	}

	listener, err := kcp.ServeConn(nil, config.DataShard, config.ParityShard, conn)
	if err != nil {
		return nil, &net.OpError{
			Op:     "listen",
			Net:    "pcap",
			Source: conn.LocalAddr(),
			Err:    fmt.Errorf("kcp: %w", err),
		}
	}

	return listener, err
}

func tuneKCP(sess *kcp.UDPSession, config *config.KCPConfig) error {
	ok := sess.SetMtu(config.MTU)
	if !ok {
		return fmt.Errorf("cannot set mtu")
	}

	sess.SetWindowSize(config.SendWindow, config.RecvWindow)

	sess.SetACKNoDelay(config.ACKNoDelay)

	sess.SetNoDelay(btoi(config.NoDelay), config.Interval, config.Resend, config.NC)

	return nil
}

// TuneKCP tunes a KCP connection.
func TuneKCP(sess *kcp.UDPSession, config *config.KCPConfig) error {
	err := tuneKCP(sess, config)
	if err != nil {
		return &net.OpError{
			Op:     "tune",
			Net:    "pcap",
			Source: sess.LocalAddr(),
			Addr:   sess.RemoteAddr(),
			Err:    err,
		}
	}

	return nil
}

func btoi(b bool) int {
	if b {
		return 1
	}

	return 0
}
