package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"ikago/internal/addr"
	"ikago/internal/config"
	"ikago/internal/crypto"
	"ikago/internal/log"
	"ikago/internal/pcap"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

type hardwareConn struct {
	conn         *pcap.Conn
	hardwareAddr net.HardwareAddr
}

var (
	argListDevs   = flag.Bool("list-devices", false, "List all valid devices in current computer.")
	argConfig     = flag.String("c", "", "Configuration file.")
	argListenDevs = flag.String("listen-devices", "", "Devices for listening.")
	argUpDev      = flag.String("upstream-device", "", "Device for routing upstream to.")
	argGateway    = flag.String("gateway", "", "Gateway address.")
	argMethod     = flag.String("method", "plain", "Method of encryption.")
	argPassword   = flag.String("password", "", "Password of encryption.")
	argVerbose    = flag.Bool("v", false, "Print verbose messages.")
	argPretend    = flag.String("pretend", "", "Address pretended to be.")
	argUpPort     = flag.Int("p", 0, "Port for routing upstream.")
	argFilters    = flag.String("f", "", "Filters.")
	argServer     = flag.String("s", "", "Server.")
)

var (
	pretendIP  net.IP
	filters    []net.Addr
	upPort     uint16
	serverIP   net.IP
	serverPort uint16
	listenDevs []*pcap.Device
	upDev      *pcap.Device
	gatewayDev *pcap.Device
	crypt      crypto.Crypt
)

var (
	isClosed    bool
	listenConns []*pcap.Conn
	upConn      *pcap.Conn
	c           chan pcap.ConnPacket
	seq         uint32
	ack         uint32
	id          uint16
	natLock     sync.RWMutex
	nat         map[pcap.NATGuide]*hardwareConn
)

func init() {
	filters = make([]net.Addr, 0)
	listenDevs = make([]*pcap.Device, 0)

	listenConns = make([]*pcap.Conn, 0)
	c = make(chan pcap.ConnPacket, 1000)
	seq = 0
	ack = 0
	id = 0
	nat = make(map[pcap.NATGuide]*hardwareConn)

	// Parse arguments
	flag.Parse()
}

func main() {
	var (
		err     error
		cfg     *config.Config
		gateway net.IP
	)

	// Configuration
	if *argConfig != "" {
		cfg, err = config.ParseFile(*argConfig)
		if err != nil {
			log.Fatalln(fmt.Errorf("parse config file %s: %w", *argConfig, err))
		}
	} else {
		cfg = &config.Config{
			ListenDevs: splitArg(*argListenDevs),
			UpDev:      *argUpDev,
			Gateway:    *argGateway,
			Method:     *argMethod,
			Password:   *argPassword,
			Verbose:    *argVerbose,
			Pretend:    *argPretend,
			UpPort:     *argUpPort,
			Filters:    splitArg(*argFilters),
			Server:     *argServer,
		}
	}

	// Log
	log.SetVerbose(cfg.Verbose)

	// Exclusive commands
	if *argListDevs {
		log.Infoln("Available devices are listed below, use -listen-devices [devices] or -upstream-device [device] to designate device:")
		devs, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatalln(fmt.Errorf("list devices: %w", err))
		}
		for _, dev := range devs {
			log.Infof("  %s\n", dev)
		}
		os.Exit(0)
	}

	// Verify parameters
	if len(cfg.Filters) <= 0 {
		log.Fatalln("Please provide filters by -f filters.")
	}
	if cfg.Server == "" {
		log.Fatalln("Please provide server by -s ip:port.")
	}
	if cfg.Gateway != "" {
		gateway = net.ParseIP(cfg.Gateway)
		if gateway == nil {
			log.Fatalln(fmt.Errorf("invalid gateway %s", cfg.Gateway))
		}
	}
	if cfg.UpPort < 0 || cfg.UpPort > 65535 {
		log.Fatalln(fmt.Errorf("upstream port %d out of range", cfg.UpPort))
	}

	// Pretend
	if cfg.Pretend != "" {
		pretendIP = net.ParseIP(cfg.Pretend)
		if pretendIP == nil {
			log.Fatalln(fmt.Errorf("invalid pretend %s", cfg.Pretend))
		}
	}

	// Filters
	for _, strFilter := range cfg.Filters {
		f, err := addr.ParseAddr(strFilter)
		if err != nil {
			log.Fatalln(fmt.Errorf("parse filter %s: %w", strFilter, err))
		}
		filters = append(filters, f)
	}

	// Randomize upstream port
	if cfg.UpPort == 0 {
		s := rand.NewSource(time.Now().UnixNano())
		r := rand.New(s)
		// Select an upstream port which is different from any port in filters
		for {
			cfg.UpPort = 49152 + r.Intn(16384)
			var exist bool
			for _, f := range filters {
				switch t := f.(type) {
				case *net.IPAddr:
					break
				case *net.TCPAddr:
					if f.(*net.TCPAddr).Port == cfg.UpPort {
						exist = true
					}
				default:
					panic(fmt.Errorf("type %T not support", t))
				}
				if exist {
					break
				}
			}
			if !exist {
				break
			}
		}
	}
	upPort = uint16(cfg.UpPort)

	serverAddr, err := addr.ParseTCPAddr(cfg.Server)
	if err != nil {
		log.Fatalln(fmt.Errorf("parse server %s: %w", cfg.Server, err))
	}
	serverIP = serverAddr.IP
	serverPort = uint16(serverAddr.Port)

	// Crypt
	crypt, err = crypto.ParseCrypt(cfg.Method, cfg.Password)
	if err != nil {
		log.Fatalln(fmt.Errorf("parse crypt: %w", err))
	}

	if len(filters) == 1 {
		log.Infof("Proxy from %s through :%d to %s\n", filters[0], cfg.UpPort, serverAddr)
	} else {
		log.Info("Proxy:")
		for _, f := range filters {
			log.Infof("\n  %s", f)
		}
		log.Infof(" through :%d to %s\n", cfg.UpPort, serverAddr)
	}

	// Find devices
	listenDevs, err = pcap.FindListenDevs(cfg.ListenDevs)
	if err != nil {
		log.Fatalln(fmt.Errorf("find listen devices: %w", err))
	}
	if len(cfg.ListenDevs) <= 0 {
		// Remove loopback devices by default
		result := make([]*pcap.Device, 0)

		for _, dev := range listenDevs {
			if dev.IsLoop {
				continue
			}
			result = append(result, dev)
		}

		listenDevs = result
	}
	if len(listenDevs) <= 0 {
		log.Fatalln(errors.New("cannot determine listen device"))
	}

	upDev, gatewayDev, err = pcap.FindUpstreamDevAndGatewayDev(cfg.UpDev, gateway)
	if err != nil {
		log.Fatalln(fmt.Errorf("find upstream device and gateway device: %w", err))
	}
	if upDev == nil && gatewayDev == nil {
		log.Fatalln(errors.New("cannot determine upstream device and gateway device"))
	}
	if upDev == nil {
		log.Fatalln(errors.New("cannot determine upstream device"))
	}
	if gatewayDev == nil {
		log.Fatalln(errors.New("cannot determine gateway device"))
	}

	// Wait signals
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		closeAll()
		os.Exit(0)
	}()

	// Open pcap
	err = open()
	if err != nil {
		log.Fatalln(fmt.Errorf("open pcap: %w", err))
	}
}

func open() error {
	var err error

	if len(listenDevs) == 1 {
		log.Infof("Listen on %s\n", listenDevs[0])
	} else {
		log.Infoln("Listen on:")
		for _, dev := range listenDevs {
			log.Infof("  %s\n", dev)
		}
	}
	if !gatewayDev.IsLoop {
		log.Infof("Route upstream from %s to %s\n", upDev, gatewayDev)
	} else {
		log.Infof("Route upstream in %s\n", upDev)
	}
	if pretendIP != nil {
		log.Infof("Pretend to be %s\n", pretendIP)
	}

	// Handshake
	err = handshake()
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	// Filters for listening
	fs := make([]string, 0)
	for _, f := range filters {
		s, err := addr.SrcBPFFilter(f)
		if err != nil {
			return fmt.Errorf("parse filter %s: %w", f, err)
		}

		fs = append(fs, s)
	}
	f := strings.Join(fs, " || ")
	filter := fmt.Sprintf("((tcp || udp) && (%s) && not (src host %s && src port %d)) || (icmp && (%s) && not src host %s)",
		f, serverIP, serverPort, f, serverIP)
	if pretendIP != nil {
		filter = filter + fmt.Sprintf(" || ((arp[6:2] = 1) && dst host %s)", pretendIP)
	}

	// Handles for listening
	for _, dev := range listenDevs {
		var (
			err  error
			conn *pcap.Conn
		)

		if dev.IsLoop {
			conn, err = pcap.Dial(dev, dev, filter)
		} else {
			conn, err = pcap.Dial(dev, gatewayDev, filter)
		}
		if err != nil {
			return fmt.Errorf("open listen device %s: %w", dev.Alias, err)
		}

		listenConns = append(listenConns, conn)
	}

	// Handle for routing upstream
	upConn, err = pcap.Dial(upDev, gatewayDev, fmt.Sprintf("(tcp && dst port %d && (src host %s && src port %d))",
		upPort, serverIP, serverPort))
	if err != nil {
		return fmt.Errorf("open upstream device %s: %w", upDev.Alias, err)
	}

	for i := 0; i < len(listenConns); i++ {
		conn := listenConns[i]

		go func() {
			for {
				packet, err := conn.ReadPacket()
				if err != nil {
					if isClosed {
						return
					}
					log.Errorln(fmt.Errorf("read listen device %s: %w", conn.SrcDev.Alias, err))
					continue
				}

				c <- pcap.ConnPacket{Packet: packet, Conn: conn}
			}
		}()
	}

	go func() {
		for cp := range c {
			err := handleListen(cp.Packet, cp.Conn)
			if err != nil {
				log.Errorln(fmt.Errorf("handle listen in device %s: %w", cp.Conn.SrcDev.Alias, err))
				log.Verboseln(cp.Packet)
				continue
			}
		}
	}()

	for {
		packet, err := upConn.ReadPacket()
		if err != nil {
			if isClosed {
				return nil
			}
			log.Errorln("read upstream device %s: %w", upConn.SrcDev.Alias, err)
			continue
		}

		err = handleUpstream(packet)
		if err != nil {
			log.Errorln(fmt.Errorf("handle upstream: %w", err))
			log.Verboseln(packet)
			continue
		}
	}
}

func closeAll() {
	isClosed = true
	for _, handle := range listenConns {
		if handle != nil {
			handle.Close()
		}
	}
	if upConn != nil {
		upConn.Close()
	}
}

func handshake() error {
	// Handle for handshaking
	conn, err := pcap.Dial(upDev, gatewayDev, fmt.Sprintf("tcp && tcp[tcpflags] & tcp-ack != 0 && dst port %d && (src host %s && src port %d)",
		upPort, serverIP, serverPort))
	if err != nil {
		return fmt.Errorf("open device %s: %w", upDev.Name, err)
	}
	defer conn.Close()

	// Handshaking with server (SYN)
	err = handshakeSYN(conn)
	if err != nil {
		return fmt.Errorf("synchronize: %w", err)
	}
	serverAddr := net.TCPAddr{IP: serverIP, Port: int(serverPort)}
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
	err = handshakeACK(packet, conn)
	if err != nil {
		return fmt.Errorf("acknowledge: %w", err)
	}

	log.Infof("Connected to server %s in %.3f ms (two-way)\n", serverAddrStr, float64(d.Microseconds())/1000)

	return nil
}

func handshakeSYN(conn *pcap.Conn) error {
	var (
		transportLayer gopacket.SerializableLayer
		networkLayer   gopacket.SerializableLayer
		linkLayer      gopacket.SerializableLayer
	)

	// Create layers
	transportLayer, networkLayer, linkLayer, err := pcap.CreateLayers(upPort, serverPort, seq, 0, conn, serverIP, id, 128, conn.DstDev.HardwareAddr)
	if err != nil {
		return err
	}

	// Make TCP layer SYN
	pcap.FlagTCPLayer(transportLayer.(*layers.TCP), true, false, false)

	// Serialize layers
	data, err := pcap.Serialize(linkLayer, networkLayer, transportLayer)
	if err != nil {
		return fmt.Errorf("serialize: %w", err)
	}

	// Write packet data
	_, err = conn.Write(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	// TCP Seq
	seq++

	// IPv4 Id
	if networkLayer.LayerType() == layers.LayerTypeIPv4 {
		id++
	}

	return nil
}

func handshakeACK(packet gopacket.Packet, conn *pcap.Conn) error {
	var (
		indicator          *pcap.PacketIndicator
		transportLayerType gopacket.LayerType
		newTransportLayer  gopacket.SerializableLayer
		newNetworkLayer    gopacket.SerializableLayer
		newLinkLayer       gopacket.SerializableLayer
	)

	// Parse packet
	indicator, err := pcap.ParsePacket(packet)
	if err != nil {
		return fmt.Errorf("parse packet: %w", err)
	}

	transportLayerType = indicator.TransportLayerType()
	if transportLayerType != layers.LayerTypeTCP {
		return fmt.Errorf("transport layer type %s not support", transportLayerType)
	}

	// TCP Ack
	ack = indicator.TCPLayer().Seq + 1

	// Create layers
	newTransportLayer, newNetworkLayer, newLinkLayer, err = pcap.CreateLayers(indicator.DstPort(), indicator.SrcPort(), seq, ack, conn, indicator.SrcIP(), id, 128, indicator.SrcHardwareAddr())
	if err != nil {
		return fmt.Errorf("create layers: %w", err)
	}

	// Make TCP layer ACK
	pcap.FlagTCPLayer(newTransportLayer.(*layers.TCP), false, false, true)

	// Serialize layers
	data, err := pcap.Serialize(newLinkLayer, newNetworkLayer, newTransportLayer)
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
		id++
	}

	return nil
}

func pretend(packet gopacket.Packet, conn *pcap.Conn) error {
	var (
		indicator     *pcap.PacketIndicator
		arpLayer      *layers.ARP
		newARPLayer   *layers.ARP
		linkLayer     gopacket.Layer
		linkLayerType gopacket.LayerType
		newLinkLayer  *layers.Ethernet
	)

	// Parse packet
	indicator, err := pcap.ParsePacket(packet)
	if err != nil {
		return fmt.Errorf("parse packet: %w", err)
	}

	t := indicator.NetworkLayerType()
	if t != layers.LayerTypeARP {
		return fmt.Errorf("network layer type %s not support", t)
	}

	// Create new ARP layer
	arpLayer = indicator.NetworkLayer().(*layers.ARP)
	newARPLayer = &layers.ARP{
		AddrType:          arpLayer.AddrType,
		Protocol:          arpLayer.Protocol,
		HwAddressSize:     arpLayer.HwAddressSize,
		ProtAddressSize:   arpLayer.ProtAddressSize,
		Operation:         layers.ARPReply,
		SourceHwAddress:   conn.SrcDev.HardwareAddr,
		SourceProtAddress: arpLayer.DstProtAddress,
		DstHwAddress:      arpLayer.SourceHwAddress,
		DstProtAddress:    arpLayer.SourceProtAddress,
	}

	// Create new link layer
	linkLayer = packet.LinkLayer()
	linkLayerType = linkLayer.LayerType()
	switch linkLayerType {
	case layers.LayerTypeEthernet:
		newLinkLayer = &layers.Ethernet{
			SrcMAC:       conn.SrcDev.HardwareAddr,
			DstMAC:       linkLayer.(*layers.Ethernet).SrcMAC,
			EthernetType: linkLayer.(*layers.Ethernet).EthernetType,
		}
	default:
		return fmt.Errorf("link layer type %s not support", linkLayerType)
	}

	// Serialize layers
	data, err := pcap.Serialize(newLinkLayer, newARPLayer)
	if err != nil {
		return fmt.Errorf("serialize: %w", err)
	}

	// Write packet data
	n, err := conn.Write(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	log.Verbosef("Reply an %s request: %s -> %s (%d Bytes)\n", indicator.NetworkLayerType(), indicator.SrcIP(), indicator.DstIP(), n)

	return nil
}

func handleListen(packet gopacket.Packet, conn *pcap.Conn) error {
	var (
		indicator         *pcap.PacketIndicator
		newTransportLayer gopacket.SerializableLayer
		newNetworkLayer   gopacket.SerializableLayer
		newLinkLayer      gopacket.SerializableLayer
	)

	// Parse packet
	indicator, err := pcap.ParsePacket(packet)
	if err != nil {
		return fmt.Errorf("parse packet: %w", err)
	}

	// ARP
	if indicator.NetworkLayerType() == layers.LayerTypeARP {
		err := pretend(packet, conn)
		if err != nil {
			return fmt.Errorf("pretend: %w", err)
		}

		return nil
	}

	// Construct contents of new application layer
	contents, err := pcap.SerializeRaw(indicator.NetworkLayer().(gopacket.SerializableLayer),
		indicator.TransportLayer().(gopacket.SerializableLayer),
		gopacket.Payload(indicator.Payload()))
	if err != nil {
		return fmt.Errorf("serialize embedded: %w", err)
	}

	// Wrap
	newTransportLayer, newNetworkLayer, newLinkLayer, err = pcap.CreateLayers(upPort, serverPort, seq, ack, conn, serverIP, id, indicator.Hop()-1, conn.DstDev.HardwareAddr)
	if err != nil {
		return fmt.Errorf("wrap: %w", err)
	}

	// Encrypt
	contents, err = crypt.Encrypt(contents)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	// Serialize layers
	data, err := pcap.Serialize(newLinkLayer, newNetworkLayer, newTransportLayer, gopacket.Payload(contents))
	if err != nil {
		return fmt.Errorf("serialize: %w", err)
	}

	// Write packet data
	n, err := conn.Write(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	// Record the connection of the packet
	natLock.Lock()
	nat[pcap.NATGuide{Src: indicator.NATSrc().String(), Proto: indicator.NATProto()}] = &hardwareConn{conn: conn, hardwareAddr: indicator.SrcHardwareAddr()}
	natLock.Unlock()

	// TCP Seq
	seq = seq + uint32(len(contents))

	// IPv4 Id
	if newNetworkLayer.LayerType() == layers.LayerTypeIPv4 {
		id++
	}

	log.Verbosef("Redirect an outbound %s packet: %s -> %s (%d Bytes)\n", indicator.TransportLayerType(), indicator.Src(), indicator.Dst(), n)

	return nil
}

func handleUpstream(packet gopacket.Packet) error {
	var (
		embIndicator     *pcap.PacketIndicator
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
	ack = ack + uint32(len(applicationLayer.LayerContents()))

	// Decrypt
	contents, err := crypt.Decrypt(applicationLayer.LayerContents())
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	// Parse embedded packet
	embIndicator, err = pcap.ParseEmbPacket(contents)
	if err != nil {
		return fmt.Errorf("parse embedded packet: %w", err)
	}

	// Check map
	natLock.RLock()
	hardwareConn, ok := nat[pcap.NATGuide{Src: embIndicator.NATDst().String(), Proto: embIndicator.NATProto()}]
	natLock.RUnlock()
	if !ok {
		return fmt.Errorf("missing %s nat to %s", embIndicator.NATProto(), embIndicator.NATDst())
	}

	// Decide Loopback or Ethernet
	if hardwareConn.conn.IsLoop() {
		newLinkLayerType = layers.LayerTypeLoopback
	} else {
		newLinkLayerType = layers.LayerTypeEthernet
	}

	// Create new link layer
	switch newLinkLayerType {
	case layers.LayerTypeLoopback:
		newLinkLayer = pcap.CreateLoopbackLayer()
	case layers.LayerTypeEthernet:
		newLinkLayer, err = pcap.CreateEthernetLayer(hardwareConn.conn.SrcDev.HardwareAddr, hardwareConn.hardwareAddr, embIndicator.NetworkLayer().(gopacket.NetworkLayer))
	default:
		return fmt.Errorf("link layer type %s not support", newLinkLayerType)
	}
	if err != nil {
		return fmt.Errorf("create link layer: %w", err)
	}

	// Serialize layers
	data, err := pcap.SerializeRaw(newLinkLayer.(gopacket.SerializableLayer),
		embIndicator.NetworkLayer().(gopacket.SerializableLayer),
		embIndicator.TransportLayer().(gopacket.SerializableLayer),
		gopacket.Payload(embIndicator.Payload()))
	if err != nil {
		return fmt.Errorf("serialize: %w", err)
	}

	// Write packet data
	n, err := hardwareConn.conn.Write(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	log.Verbosef("Redirect an inbound %s packet: %s <- %s (%d Bytes)\n", embIndicator.TransportLayerType(), embIndicator.Dst(), embIndicator.Src(), n)

	return nil
}

func splitArg(s string) []string {
	if s == "" {
		return nil
	} else {
		result := make([]string, 0)

		strs := strings.Split(s, ",")

		for _, str := range strs {
			result = append(result, strings.Trim(str, " "))
		}

		return result
	}
}
