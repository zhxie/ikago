package pcap

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"ikago/internal/addr"
	"ikago/internal/crypto"
	"ikago/internal/log"
	"net"
	"strings"
	"sync"
	"time"
)

// Client describes the packet capture on the client side
type Client struct {
	Filters        []net.Addr
	UpPort         uint16
	ServerIP       net.IP
	ServerPort     uint16
	ListenDevs     []*Device
	UpDev          *Device
	GatewayDev     *Device
	Crypt          crypto.Crypt
	isClosed       bool
	listenConns    []*Conn
	upConn         *Conn
	cListenPackets chan ConnPacket
	seq            uint32
	ack            uint32
	id             uint16
	connMapLock    sync.RWMutex
	connMap        map[NATGuide]*Conn
}

// NewClient returns a new pcap client
func NewClient() *Client {
	return &Client{
		listenConns:    make([]*Conn, 0),
		cListenPackets: make(chan ConnPacket, 1000),
		seq:            0,
		ack:            0,
		id:             0,
		connMap:        make(map[NATGuide]*Conn),
	}
}

// Open implements a method opens the pcap
func (p *Client) Open() error {
	var err error

	// Verify
	if len(p.Filters) <= 0 {
		return errors.New("missing filter")
	}
	if p.UpPort <= 0 || p.UpPort > 65535 {
		return fmt.Errorf("upstream port %d out of range", p.UpPort)
	}
	if p.ServerIP == nil {
		return errors.New("missing server ip")
	}
	if p.ServerPort <= 0 || p.ServerPort > 65535 {
		return fmt.Errorf("server port %d out of range", p.ServerPort)
	}
	if len(p.ListenDevs) <= 0 {
		return errors.New("missing listen device")
	}
	if p.UpDev == nil {
		return errors.New("missing upstream device")
	}
	if p.GatewayDev == nil {
		return errors.New("missing gateway device")
	}

	if len(p.ListenDevs) == 1 {
		log.Infof("Listen on %s\n", p.ListenDevs[0])
	} else {
		log.Infoln("Listen on:")
		for _, dev := range p.ListenDevs {
			log.Infof("  %s\n", dev)
		}
	}
	if !p.GatewayDev.IsLoop {
		log.Infof("Route upstream from %s to %s\n", p.UpDev, p.GatewayDev)
	} else {
		log.Infof("Route upstream in %s\n", p.UpDev)
	}

	// Handshake
	err = p.handshake()
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	// Filters for listening
	fs := make([]string, 0)
	for _, f := range p.Filters {
		s, err := addr.SrcBPFFilter(f)
		if err != nil {
			return fmt.Errorf("parse filter %s: %w", f, err)
		}

		fs = append(fs, s)
	}
	f := strings.Join(fs, " || ")

	// Handles for listening
	for _, dev := range p.ListenDevs {
		var err error
		var conn *Conn

		if dev.IsLoop {
			conn, err = Dial(dev, dev, fmt.Sprintf("((tcp || udp) && (%s) && not (src host %s && src port %d)) || (icmp && (%s) && not src host %s)",
				f, p.ServerIP, p.ServerPort, f, p.ServerIP))
		} else {
			conn, err = Dial(dev, p.GatewayDev, fmt.Sprintf("((tcp || udp) && (%s) && not (src host %s && src port %d)) || (icmp && (%s) && not src host %s)",
				f, p.ServerIP, p.ServerPort, f, p.ServerIP))
		}
		if err != nil {
			return fmt.Errorf("open listen device %s: %w", dev.Name, err)
		}

		p.listenConns = append(p.listenConns, conn)
	}

	// Handle for routing upstream
	p.upConn, err = Dial(p.UpDev, p.GatewayDev, fmt.Sprintf("(tcp && dst port %d && (src host %s && src port %d))", p.UpPort, p.ServerIP, p.ServerPort))
	if err != nil {
		return fmt.Errorf("open upstream device %s: %w", p.UpDev.Name, err)
	}

	// Start handling
	for i := 0; i < len(p.listenConns); i++ {
		conn := p.listenConns[i]

		go func() {
			for {
				packet, err := conn.ReadPacket()
				if err != nil {
					if p.isClosed {
						return
					}
					log.Errorln(fmt.Errorf("read listen in %s: %w", conn.SrcDev.Alias, err))
					continue
				}

				// Avoid conflict
				p.cListenPackets <- ConnPacket{packet: packet, conn: conn}
			}
		}()
	}
	go func() {
		for connPacket := range p.cListenPackets {
			err := p.handleListen(connPacket.packet, connPacket.conn)
			if err != nil {
				log.Errorln(fmt.Errorf("handle listen in %s: %w", connPacket.conn.SrcDev.Alias, err))
				log.Verboseln(connPacket.packet)
				continue
			}
		}
	}()
	for {
		packet, err := p.upConn.ReadPacket()
		if err != nil {
			if p.isClosed {
				return nil
			}
			log.Errorln(fmt.Errorf("read upstream: %w", err))
			continue
		}

		err = p.handleUpstream(packet)
		if err != nil {
			log.Errorln(fmt.Errorf("handle upstream: %w", err))
			log.Verboseln(packet)
			continue
		}
	}
}

// Close implements a method closes the pcap
func (p *Client) Close() {
	p.isClosed = true
	for _, handle := range p.listenConns {
		if handle != nil {
			handle.Close()
		}
	}
	if p.upConn != nil {
		p.upConn.Close()
	}
}

func (p *Client) handshake() error {
	// Handle for handshaking
	conn, err := Dial(p.UpDev, p.GatewayDev, fmt.Sprintf("tcp && tcp[tcpflags] & tcp-ack != 0 && dst port %d && (src host %s && src port %d)",
		p.UpPort, p.ServerIP, p.ServerPort))
	if err != nil {
		return fmt.Errorf("open device %s: %w", p.UpDev.Name, err)
	}
	defer conn.Close()

	// Handshaking with server (SYN)
	err = p.handshakeSYN(conn)
	if err != nil {
		return fmt.Errorf("synchronize: %w", err)
	}
	serverAddr := net.TCPAddr{IP: p.ServerIP, Port: int(p.ServerPort)}
	serverAddrStr := serverAddr.String()

	log.Infof("Connect to server %s\n", serverAddrStr)

	// Latency test
	t := time.Now()

	err = conn.SetReadDeadline(t.Add(3 * time.Second))
	if err != nil {
		return err
	}

	packet, err := conn.ReadPacket()
	if err != nil {
		return err
	}

	transportLayer := packet.TransportLayer()
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
	d := time.Now().Sub(t)

	// Handshaking with server (ACK)
	err = p.handshakeACK(packet, conn)
	if err != nil {
		return fmt.Errorf("acknowledge: %w", err)
	}

	log.Infof("Connected to server %s in %.3f ms (two-way)\n", serverAddrStr, float64(d.Microseconds())/1000)

	return nil
}

// handshakeSYN sends TCP SYN to the server in handshaking
func (p *Client) handshakeSYN(conn *Conn) error {
	var (
		transportLayer gopacket.SerializableLayer
		networkLayer   gopacket.SerializableLayer
		linkLayer      gopacket.SerializableLayer
	)

	// Create layers
	transportLayer, networkLayer, linkLayer, err := CreateLayers(p.UpPort, p.ServerPort, p.seq, 0, conn, p.ServerIP, p.id, 128)
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
	p.seq++

	// IPv4 Id
	if networkLayer.LayerType() == layers.LayerTypeIPv4 {
		p.id++
	}

	return nil
}

// handshakeACK sends TCP ACK to the server in handshaking
func (p *Client) handshakeACK(packet gopacket.Packet, conn *Conn) error {
	var (
		indicator         *PacketIndicator
		newTransportLayer gopacket.SerializableLayer
		newNetworkLayer   gopacket.SerializableLayer
		newLinkLayer      gopacket.SerializableLayer
	)

	// Parse packet
	indicator, err := ParsePacket(packet)
	if err != nil {
		return fmt.Errorf("parse packet: %w", err)
	}

	if indicator.transportLayerType != layers.LayerTypeTCP {
		return fmt.Errorf("transport layer type %s not support", indicator.transportLayerType)
	}

	// TCP Ack
	p.ack = indicator.TCPLayer().Seq + 1

	// Create layers
	newTransportLayer, newNetworkLayer, newLinkLayer, err = CreateLayers(indicator.DstPort(), indicator.SrcPort(), p.seq, p.ack, conn, indicator.SrcIP(), p.id, 128)
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
		p.id++
	}

	return nil
}

// handleListen handles TCP and UDP packets from sources
func (p *Client) handleListen(packet gopacket.Packet, conn *Conn) error {
	var (
		indicator         *PacketIndicator
		newTransportLayer gopacket.SerializableLayer
		newNetworkLayer   gopacket.SerializableLayer
		newLinkLayer      gopacket.SerializableLayer
	)

	// Parse packet
	indicator, err := ParsePacket(packet)
	if err != nil {
		return fmt.Errorf("parse packet: %w", err)
	}

	// Construct contents of new application layer
	contents, err := SerializeRaw(indicator.networkLayer.(gopacket.SerializableLayer),
		indicator.transportLayer.(gopacket.SerializableLayer),
		gopacket.Payload(indicator.Payload()))
	if err != nil {
		return fmt.Errorf("serialize embedded: %w", err)
	}

	// Wrap
	newTransportLayer, newNetworkLayer, newLinkLayer, err = CreateLayers(p.UpPort, p.ServerPort, p.seq, p.ack, conn, p.ServerIP, p.id, indicator.Hop()-1)
	if err != nil {
		return fmt.Errorf("wrap: %w", err)
	}

	// Encrypt
	contents, err = p.Crypt.Encrypt(contents)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	// Serialize layers
	data, err := Serialize(newLinkLayer, newNetworkLayer, newTransportLayer, gopacket.Payload(contents))
	if err != nil {
		return fmt.Errorf("serialize: %w", err)
	}

	// Write packet data
	n, err := conn.Write(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	// Record the connection of the packet
	p.connMapLock.Lock()
	p.connMap[NATGuide{src: indicator.NATSrc().String(), proto: indicator.NATProto()}] = conn
	p.connMapLock.Unlock()

	// TCP Seq
	p.seq = p.seq + uint32(len(contents))

	// IPv4 Id
	if newNetworkLayer.LayerType() == layers.LayerTypeIPv4 {
		p.id++
	}

	log.Verbosef("Redirect an outbound %s packet: %s -> %s (%d Bytes)\n", indicator.transportLayerType, indicator.Src(), indicator.Dst(), n)

	return nil
}

// handleUpstream handles TCP packets from the server
func (p *Client) handleUpstream(packet gopacket.Packet) error {
	var (
		embIndicator     *PacketIndicator
		newLinkLayer     gopacket.Layer
		newLinkLayerType gopacket.LayerType
	)

	// Parse packet
	applicationLayer := packet.ApplicationLayer()

	// Empty payload
	if applicationLayer == nil {
		return errors.New("empty payload")
	}

	// TCP Ack
	p.ack = p.ack + uint32(len(applicationLayer.LayerContents()))

	// Decrypt
	contents, err := p.Crypt.Decrypt(applicationLayer.LayerContents())
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	// Parse embedded packet
	embIndicator, err = ParseEmbPacket(contents)
	if err != nil {
		return fmt.Errorf("parse embedded packet: %w", err)
	}

	// Check map
	p.connMapLock.RLock()
	conn, ok := p.connMap[NATGuide{src: embIndicator.NATDst().String(), proto: embIndicator.NATProto()}]
	p.connMapLock.RUnlock()
	if !ok {
		return fmt.Errorf("missing %s nat to %s", embIndicator.NATProto(), embIndicator.NATDst())
	}

	// Decide Loopback or Ethernet
	if conn.IsLoop() {
		newLinkLayerType = layers.LayerTypeLoopback
	} else {
		newLinkLayerType = layers.LayerTypeEthernet
	}

	// Create new link layer
	switch newLinkLayerType {
	case layers.LayerTypeLoopback:
		newLinkLayer = CreateLoopbackLayer()
	case layers.LayerTypeEthernet:
		newLinkLayer, err = CreateEthernetLayer(conn.SrcDev.HardwareAddr, conn.DstDev.HardwareAddr, embIndicator.networkLayer)
	default:
		return fmt.Errorf("link layer type %s not support", newLinkLayerType)
	}
	if err != nil {
		return fmt.Errorf("create link layer: %w", err)
	}

	// Serialize layers
	data, err := SerializeRaw(newLinkLayer.(gopacket.SerializableLayer),
		embIndicator.networkLayer.(gopacket.SerializableLayer),
		embIndicator.transportLayer.(gopacket.SerializableLayer),
		gopacket.Payload(embIndicator.Payload()))
	if err != nil {
		return fmt.Errorf("serialize: %w", err)
	}

	// Write packet data
	n, err := conn.Write(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	log.Verbosef("Redirect an inbound %s packet: %s <- %s (%d Bytes)\n", embIndicator.transportLayerType, embIndicator.Dst(), embIndicator.Src(), n)

	return nil
}
