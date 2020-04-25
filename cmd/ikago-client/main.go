package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/xtaci/kcp-go"
	"ikago/internal/addr"
	"ikago/internal/config"
	"ikago/internal/crypto"
	"ikago/internal/exec"
	"ikago/internal/log"
	"ikago/internal/pcap"
	"ikago/internal/stat"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

type natIndicator struct {
	srcHardwareAddr net.HardwareAddr
	conn            *pcap.RawConn
}

var (
	version = ""
	build   = ""
)

var (
	argListDevs       = flag.Bool("list-devices", false, "List all valid devices in current computer.")
	argConfig         = flag.String("c", "", "Configuration file.")
	argListenDevs     = flag.String("listen-devices", "", "Devices for listening.")
	argUpDev          = flag.String("upstream-device", "", "Device for routing upstream to.")
	argGateway        = flag.String("gateway", "", "Gateway address.")
	argMethod         = flag.String("method", "plain", "Method of encryption.")
	argPassword       = flag.String("password", "", "Password of encryption.")
	argMTU            = flag.Int("mtu", 0, "MTU.")
	argListenMTU      = flag.Int("listen-mtu", 0, "MTU of devices for listening.")
	argUpMTU          = flag.Int("upstream-mtu", 0, "MTU of device for routing upstream to.")
	argKCP            = flag.Bool("kcp", false, "Enable KCP.")
	argKCPMTU         = flag.Int("kcp-mtu", kcp.IKCP_MTU_DEF, "KCP tuning option mtu.")
	argKCPSendWindow  = flag.Int("kcp-sndwnd", kcp.IKCP_WND_SND, "KCP tuning option sndwnd.")
	argKCPRecvWindow  = flag.Int("kcp-rcvwnd", kcp.IKCP_WND_RCV, "KCP tuning option rcvwnd.")
	argKCPDataShard   = flag.Int("kcp-datashard", 10, "KCP tuning option datashard.")
	argKCPParityShard = flag.Int("kcp-parityshard", 3, "KCP tuning option parityshard.")
	argKCPACKNoDelay  = flag.Bool("kcp-acknodelay", false, "KCP tuning option acknodelay.")
	argKCPNoDelay     = flag.Bool("kcp-nodelay", false, "KCP tuning option nodelay.")
	argKCPInterval    = flag.Int("kcp-interval", kcp.IKCP_INTERVAL, "KCP tuning option interval.")
	argKCPResend      = flag.Int("kcp-resend", 0, "KCP tuning option resend.")
	argKCPNC          = flag.Int("kcp-nc", 0, "KCP tuning option nc.")
	argRule           = flag.Bool("rule", false, "Add firewall rule.")
	argVerbose        = flag.Bool("v", false, "Print verbose messages.")
	argLog            = flag.String("log", "", "Log.")
	argPublish        = flag.String("publish", "", "ARP publishing address.")
	argUpPort         = flag.Int("p", 0, "Port for routing upstream.")
	argSources        = flag.String("r", "", "Sources.")
	argServer         = flag.String("s", "", "Server.")
)

var (
	publishIP     *net.IPAddr
	upPort        uint16
	sources       []*net.IPAddr
	serverIP      net.IP
	serverPort    uint16
	listenDevs    []*pcap.Device
	upDev         *pcap.Device
	gatewayDev    *pcap.Device
	crypt         crypto.Crypt
	listenMTU     int
	upMTU         int
	isKCP         bool
	kcpConfig     *config.KCPConfig
	dummyListener net.Listener
)

var (
	isClosed    bool
	listenConns []*pcap.RawConn
	upConn      net.Conn
	c           chan pcap.ConnPacket
	defrag      *pcap.Defragmenter
	natLock     sync.RWMutex
	nat         map[string]*natIndicator
	listenStats *stat.TrafficManager
	upStats     *stat.TrafficManager
)

func init() {
	if version != "" && build != "" {
		log.Infof("IkaGo-client %s-%s\n\n", version, build)
	} else {
		log.Infof("IkaGo-client %s%s\n\n", version, build)
	}

	// Parse arguments
	flag.Parse()

	// Load config.json by default
	if len(os.Args) <= 1 {
		_, err := os.Stat("config.json")
		if err == nil {
			*argConfig = "config.json"
		}
	}

	sources = make([]*net.IPAddr, 0)
	listenDevs = make([]*pcap.Device, 0)

	listenConns = make([]*pcap.RawConn, 0)
	c = make(chan pcap.ConnPacket, 1000)
	defrag = pcap.NewDefragmenter()
	nat = make(map[string]*natIndicator)
	listenStats = stat.NewTrafficManager()
	upStats = stat.NewTrafficManager()
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
		log.Infof("Load configuration from %s\n", *argConfig)
	} else {
		cfg = &config.Config{
			ListenDevs: splitArg(*argListenDevs),
			UpDev:      *argUpDev,
			Gateway:    *argGateway,
			Method:     *argMethod,
			Password:   *argPassword,
			KCP:        *argKCP,
			KCPConfig: config.KCPConfig{
				MTU:         *argKCPMTU,
				SendWindow:  *argKCPSendWindow,
				RecvWindow:  *argKCPRecvWindow,
				DataShard:   *argKCPDataShard,
				ParityShard: *argKCPParityShard,
				ACKNoDelay:  *argKCPACKNoDelay,
				NoDelay:     *argKCPNoDelay,
				Interval:    *argKCPInterval,
				Resend:      *argKCPResend,
				NC:          *argKCPNC,
			},
			MTU:       *argMTU,
			ListenMTU: *argListenMTU,
			UpMTU:     *argUpMTU,
			Rule:      *argRule,
			Verbose:   *argVerbose,
			Log:       *argLog,
			Publish:   *argPublish,
			Port:      *argUpPort,
			Sources:   splitArg(*argSources),
			Server:    *argServer,
		}
	}

	// Log
	log.SetVerbose(cfg.Verbose)
	err = log.SetLog(cfg.Log)
	if err != nil {
		log.Fatalln(fmt.Errorf("log %s: %w", cfg.Log, err))
	}
	if cfg.Log != "" {
		log.Infof("Save log to file %s\n", cfg.Log)
	}

	// Check permission
	switch runtime.GOOS {
	case "linux":
		if os.Geteuid() != 0 {
			ex, err := os.Executable()
			if err != nil {
				ex = "path_to_ikago"
			}

			log.Infoln("You are running IkaGo as non-root, if IkaGo does not work, run")
			log.Infof("  sudo setcap cap_net_raw+ep \"%s\"\n", ex)
			log.Infoln("  before opening IkaGo, or just run as root with sudo.")
		}
	case "windows":
		break
	default:
		if os.Geteuid() != 0 {
			log.Fatalln("Please run IkaGo as root with sudo.")
		}
	}

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
	if len(cfg.Sources) <= 0 {
		log.Fatalln("Please provide sources by -r addresses.")
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
	if cfg.MTU < 576 || cfg.MTU > pcap.MaxMTU {
		if cfg.MTU == 0 {
			cfg.MTU = pcap.MaxMTU
		} else {
			log.Fatalln(fmt.Errorf("mtu %d out of range", cfg.MTU))
		}
	}
	if cfg.ListenMTU < 576 || cfg.ListenMTU > pcap.MaxMTU {
		if cfg.ListenMTU != 0 {
			log.Fatalln(fmt.Errorf("listen mtu %d out of range", cfg.ListenMTU))
		}
	}
	if cfg.UpMTU < 576 || cfg.UpMTU > pcap.MaxMTU {
		if cfg.UpMTU != 0 {
			log.Fatalln(fmt.Errorf("upstream mtu %d out of range", cfg.UpMTU))
		}
	}
	if cfg.KCPConfig.MTU > 1500 {
		log.Fatalln(fmt.Errorf("kcp mtu %d out of range", cfg.KCPConfig.MTU))
	}
	if cfg.KCPConfig.SendWindow <= 0 || cfg.KCPConfig.SendWindow > 4294967295 {
		log.Fatalln(fmt.Errorf("kcp send window %d out of range", cfg.KCPConfig.SendWindow))
	}
	if cfg.KCPConfig.RecvWindow <= 0 || cfg.KCPConfig.RecvWindow > 4294967295 {
		log.Fatalln(fmt.Errorf("kcp receive window %d out of range", cfg.KCPConfig.RecvWindow))
	}
	if cfg.KCPConfig.DataShard < 0 {
		log.Fatalln(fmt.Errorf("kcp data shard %d out of range", cfg.KCPConfig.DataShard))
	}
	if cfg.KCPConfig.ParityShard < 0 {
		log.Fatalln(fmt.Errorf("kcp parity shard %d out of range", cfg.KCPConfig.ParityShard))
	}
	if cfg.KCPConfig.Interval < 0 {
		log.Fatalln(fmt.Errorf("kcp interval %d out of range", cfg.KCPConfig.Interval))
	}
	if cfg.KCPConfig.Resend < 0 {
		log.Fatalln(fmt.Errorf("kcp resend %d out of range", cfg.KCPConfig.Resend))
	}
	if cfg.KCPConfig.NC < 0 {
		log.Fatalln(fmt.Errorf("kcp nc %d out of range", cfg.KCPConfig.NC))
	}
	if cfg.Port < 0 || cfg.Port > 65535 {
		log.Fatalln(fmt.Errorf("upstream port %d out of range", cfg.Port))
	}

	// Randomize upstream port
	if cfg.Port == 0 {
		s := rand.NewSource(time.Now().UnixNano())
		r := rand.New(s)
		cfg.Port = 49152 + r.Intn(16384)
	}
	upPort = uint16(cfg.Port)

	// Sources
	for _, source := range cfg.Sources {
		ip := net.ParseIP(source)
		if ip == nil {
			log.Fatalln(fmt.Errorf("invalid source %s", source))
		}
		sources = append(sources, &net.IPAddr{IP: ip})
	}

	// Server
	serverAddr, err := addr.ParseTCPAddr(cfg.Server)
	if err != nil {
		log.Fatalln(fmt.Errorf("parse server %s: %w", cfg.Server, err))
	}
	serverIP = serverAddr.IP
	serverPort = uint16(serverAddr.Port)

	// Add firewall rule
	if cfg.Rule {
		err := exec.AddSpecificFirewallRule(serverIP, serverPort)
		if err != nil {
			log.Fatalln(fmt.Errorf("add firewall rule: %w", err))
		}

		log.Infoln("Add firewall rule")
	}

	// Publish
	if cfg.Publish != "" {
		ip := net.ParseIP(cfg.Publish)
		if ip == nil {
			log.Errorln(fmt.Errorf("invalid publish %s", cfg.Publish))
		}
		publishIP = &net.IPAddr{IP: ip}
	}
	if publishIP != nil {
		log.Infof("Publish %s\n", publishIP.IP)
	}

	// Crypt
	crypt, err = crypto.ParseCrypt(cfg.Method, cfg.Password)
	if err != nil {
		log.Fatalln(fmt.Errorf("parse crypt: %w", err))
	}
	method := crypt.Method()
	if method != crypto.MethodPlain {
		log.Infof("Encrypt with %s\n", method)
	}

	// MTU
	listenMTU = cfg.MTU
	upMTU = cfg.MTU
	if cfg.ListenMTU != 0 {
		listenMTU = cfg.ListenMTU
	}
	if cfg.UpMTU != 0 {
		upMTU = cfg.UpMTU
	}
	if listenMTU != pcap.MaxMTU {
		log.Infof("Set listen MTU to %d Bytes\n", listenMTU)
	}
	if upMTU != pcap.MaxMTU {
		log.Infof("Set upstream MTU to %d Bytes\n", listenMTU)
	}

	// KCP
	isKCP = cfg.KCP
	kcpConfig = &cfg.KCPConfig
	if isKCP {
		log.Infoln("Enable KCP")
	}

	if len(sources) == 1 {
		log.Infof("Proxy %s through :%d to %s\n", sources[0], upPort, serverAddr)
	} else {
		log.Info("Proxy:")
		for _, f := range sources {
			log.Infof("\n  %s", f)
		}
		log.Infof(" through :%d to %s\n", upPort, serverAddr)
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
			if dev.IsLoop() {
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
		if dummyListener != nil {
			dummyListener.Close()
		}
		log.Close()
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
		log.Infof("Listen on %s\n", listenDevs[0].String())
	} else {
		log.Infoln("Listen on:")
		for _, dev := range listenDevs {
			log.Infof("  %s\n", dev.String())
		}
	}
	if !gatewayDev.IsLoop() {
		log.Infof("Route upstream from %s to %s\n", upDev, gatewayDev)
	} else {
		log.Infof("Route upstream in %s\n", upDev)
	}

	// Filters for listening
	fs := make([]string, 0)
	for _, f := range sources {
		s, err := addr.SrcBPFFilter(f)
		if err != nil {
			return fmt.Errorf("parse filter %s: %w", f, err)
		}

		fs = append(fs, s)
	}
	f := strings.Join(fs, " || ")
	filter := fmt.Sprintf("ip && (((tcp || udp) && (%s) && not (src host %s && src port %d)) || (icmp && (%s) && not src host %s))",
		f, serverIP, serverPort, f, serverIP)
	if publishIP != nil {
		s, err := addr.DstBPFFilter(publishIP)
		if err != nil {
			return fmt.Errorf("parse filter %s: %w", f, err)
		}
		filter = filter + fmt.Sprintf(" || (arp[6:2] = 1 && %s)", s)
	}

	// Handles for listening
	for _, dev := range listenDevs {
		var (
			err  error
			conn *pcap.RawConn
		)

		if dev.IsLoop() {
			conn, err = pcap.CreateRawConn(dev, dev, filter)
		} else {
			conn, err = pcap.CreateRawConn(dev, gatewayDev, filter)
		}
		if err != nil {
			return fmt.Errorf("open listen device %s: %w", conn.LocalDev().Alias(), err)
		}

		listenConns = append(listenConns, conn)
	}

	// Handle for routing upstream
	if isKCP {
		upConn, err = pcap.DialWithKCP(upDev, gatewayDev, upPort, &net.TCPAddr{IP: serverIP, Port: int(serverPort)}, crypt, upMTU, kcpConfig)
	} else {
		upConn, err = pcap.Dial(upDev, gatewayDev, upPort, &net.TCPAddr{IP: serverIP, Port: int(serverPort)}, crypt, upMTU)
	}
	if err != nil {
		return fmt.Errorf("open upstream: %w", err)
	}

	// Start handling
	for i := 0; i < len(listenConns); i++ {
		conn := listenConns[i]

		go func() {
			for {
				packet, err := conn.ReadPacket()
				if err != nil {
					if isClosed {
						return
					}
					log.Errorln(fmt.Errorf("read listen device %s: %w", conn.LocalDev().Alias(), err))
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
				log.Errorln(fmt.Errorf("handle listen in device %s: %w", cp.Conn.LocalDev().Alias(), err))
				log.Verboseln(cp.Packet)
				continue
			}
		}
	}()

	for {
		b := make([]byte, pcap.MaxMTU)

		n, err := upConn.Read(b)
		if err != nil {
			if isClosed {
				return nil
			}
			log.Errorln(fmt.Errorf("read upstream: %w", err))
			continue
		}

		err = handleUpstream(b[:n])
		if err != nil {
			log.Errorln(fmt.Errorf("handle upstream in address %s: %w", upConn.LocalAddr().String(), err))
			log.Verbosef("Source: %s\nSize: %d Bytes\n\n", upConn.RemoteAddr().String(), n)
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

	// Statistics
	log.Infof("\nOutbound statistics:\n")
	for _, node := range listenStats.Nodes() {
		indicator, err := listenStats.Indicator(node)
		if err != nil {
			log.Errorln(fmt.Errorf("statistics %s: %w", node, err))
		}

		log.Infof("%s: %s\n", node, indicator.String())
	}
	log.Infof("\nInbound statistics:\n")
	for _, node := range upStats.Nodes() {
		indicator, err := upStats.Indicator(node)
		if err != nil {
			log.Errorln(fmt.Errorf("statistics %s: %w", node, err))
		}

		log.Infof("%s: %s\n", node, indicator.String())
	}
}

func publish(packet gopacket.Packet, conn *pcap.RawConn) error {
	var (
		indicator    *pcap.PacketIndicator
		arpLayer     *layers.ARP
		newARPLayer  *layers.ARP
		linkLayer    gopacket.Layer
		newLinkLayer *layers.Ethernet
	)

	// Parse packet
	indicator, err := pcap.ParsePacket(packet)
	if err != nil {
		return fmt.Errorf("parse packet: %w", err)
	}

	if t := indicator.NetworkLayer().LayerType(); t != layers.LayerTypeARP {
		return fmt.Errorf("network layer type %s not support", t)
	}

	// Create new ARP layer
	arpLayer = indicator.ARPLayer()
	newARPLayer = &layers.ARP{
		AddrType:          arpLayer.AddrType,
		Protocol:          arpLayer.Protocol,
		HwAddressSize:     arpLayer.HwAddressSize,
		ProtAddressSize:   arpLayer.ProtAddressSize,
		Operation:         layers.ARPReply,
		SourceHwAddress:   conn.LocalDev().HardwareAddr(),
		SourceProtAddress: arpLayer.DstProtAddress,
		DstHwAddress:      arpLayer.SourceHwAddress,
		DstProtAddress:    arpLayer.SourceProtAddress,
	}

	// Create new link layer
	linkLayer = packet.LinkLayer()

	switch t := linkLayer.LayerType(); t {
	case layers.LayerTypeEthernet:
		newLinkLayer = &layers.Ethernet{
			SrcMAC:       conn.LocalDev().HardwareAddr(),
			DstMAC:       linkLayer.(*layers.Ethernet).SrcMAC,
			EthernetType: linkLayer.(*layers.Ethernet).EthernetType,
		}
	default:
		return fmt.Errorf("link layer type %s not support", t)
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

	log.Infof("Device %s [%s] joined the network\n", indicator.SrcIP(), net.HardwareAddr(arpLayer.SourceHwAddress))
	log.Verbosef("Reply an %s request: %s -> %s (%d Bytes)\n", indicator.NetworkLayer().LayerType(), indicator.SrcIP(), indicator.DstIP(), n)

	return nil
}

func handleListen(packet gopacket.Packet, conn *pcap.RawConn) error {
	var (
		hardwareAddr net.HardwareAddr
		data         []byte
	)

	// Parse packet
	indicator, err := pcap.ParsePacket(packet)
	if err != nil {
		return fmt.Errorf("parse packet: %w", err)
	}

	// ARP
	if indicator.NetworkLayer().LayerType() == layers.LayerTypeARP {
		err := publish(packet, conn)
		if err != nil {
			return fmt.Errorf("publish: %w", err)
		}
		return nil
	}

	// Record source hardware address
	hardwareAddr = indicator.SrcHardwareAddr()

	// Handle fragments
	indicator, err = defrag.Append(indicator)
	if err != nil {
		return fmt.Errorf("defrag: %w", err)
	}
	if indicator == nil {
		return nil
	}

	// Set network layer for transport layer
	if indicator.TransportLayer() != nil {
		switch t := indicator.TransportLayer().LayerType(); t {
		case layers.LayerTypeTCP:
			tcpLayer := indicator.TCPLayer()

			err = tcpLayer.SetNetworkLayerForChecksum(indicator.NetworkLayer().(gopacket.NetworkLayer))
		case layers.LayerTypeUDP:
			udpLayer := indicator.UDPLayer()

			err = udpLayer.SetNetworkLayerForChecksum(indicator.NetworkLayer().(gopacket.NetworkLayer))
		case layers.LayerTypeICMPv4:
			break
		default:
			return fmt.Errorf("transport layer type %s not support", t)
		}
		if err != nil {
			return fmt.Errorf("set network layer for checksum: %w", err)
		}
	}

	// Serialize layers
	data, err = pcap.Serialize(indicator.NetworkLayer().(gopacket.SerializableLayer), indicator.TransportLayer().(gopacket.SerializableLayer), gopacket.Payload(indicator.Payload()))
	if err != nil {
		return fmt.Errorf("serialize: %w", err)
	}

	// Write packet data
	_, err = upConn.Write(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	// Record the connection of the packet
	ni, ok := nat[indicator.SrcIP().String()]
	if !ok || ni.srcHardwareAddr.String() != hardwareAddr.String() {
		natLock.Lock()
		nat[indicator.SrcIP().String()] = &natIndicator{srcHardwareAddr: hardwareAddr, conn: conn}
		natLock.Unlock()
	}

	// Statistics
	size := indicator.MTU()
	listenStats.Add(indicator.SrcIP().String(), uint(size))

	log.Verbosef("Redirect an outbound %s packet: %s -> %s (%d Bytes)\n",
		indicator.TransportProtocol(), indicator.Src().String(), indicator.Dst().String(), size)

	return nil
}

func handleUpstream(contents []byte) error {
	var (
		embIndicator     *pcap.PacketIndicator
		newLinkLayer     gopacket.Layer
		newLinkLayerType gopacket.LayerType
		fragments        [][]byte
	)

	// Empty payload
	if len(contents) <= 0 {
		return errors.New("empty payload")
	}

	// Parse embedded packet
	embIndicator, err := pcap.ParseEmbPacket(contents)
	if err != nil {
		return fmt.Errorf("parse embedded packet: %w", err)
	}

	// Check map
	natLock.RLock()
	ni, ok := nat[embIndicator.DstIP().String()]
	natLock.RUnlock()
	if !ok {
		return fmt.Errorf("missing nat to %s", embIndicator.DstIP())
	}

	// Set network layer for transport layer
	if embIndicator.TransportLayer() != nil {
		switch t := embIndicator.TransportLayer().LayerType(); t {
		case layers.LayerTypeTCP:
			tcpLayer := embIndicator.TCPLayer()

			err = tcpLayer.SetNetworkLayerForChecksum(embIndicator.NetworkLayer().(gopacket.NetworkLayer))
		case layers.LayerTypeUDP:
			udpLayer := embIndicator.UDPLayer()

			err = udpLayer.SetNetworkLayerForChecksum(embIndicator.NetworkLayer().(gopacket.NetworkLayer))
		case layers.LayerTypeICMPv4:
			break
		default:
			return fmt.Errorf("transport layer type %s not support", t)
		}
		if err != nil {
			return fmt.Errorf("set network layer for checksum: %w", err)
		}
	}

	// Decide Loopback or Ethernet
	if ni.conn.IsLoop() {
		newLinkLayerType = layers.LayerTypeLoopback
	} else {
		newLinkLayerType = layers.LayerTypeEthernet
	}

	// Create new link layer
	switch newLinkLayerType {
	case layers.LayerTypeLoopback:
		newLinkLayer = pcap.CreateLoopbackLayer()
	case layers.LayerTypeEthernet:
		newLinkLayer, err = pcap.CreateEthernetLayer(ni.conn.LocalDev().HardwareAddr(), ni.srcHardwareAddr, embIndicator.NetworkLayer().(gopacket.NetworkLayer))
	default:
		return fmt.Errorf("link layer type %s not support", newLinkLayerType)
	}
	if err != nil {
		return fmt.Errorf("create link layer: %w", err)
	}

	// Fragment
	fragments, err = pcap.CreateFragmentPackets(newLinkLayer, embIndicator.NetworkLayer(), embIndicator.TransportLayer(), gopacket.Payload(embIndicator.Payload()), listenMTU)
	if err != nil {
		return fmt.Errorf("fragment: %w", err)
	}

	// Write packet data
	for i, frag := range fragments {
		_, err := ni.conn.Write(frag)
		if err != nil {
			return fmt.Errorf("write: %w", err)
		}

		if i == len(fragments)-1 {
			log.Verbosef("Redirect an inbound %s packet: %s <- %s (%d Bytes)\n",
				embIndicator.TransportProtocol(), embIndicator.Dst().String(), embIndicator.Src().String(), embIndicator.Size())
		} else {
			log.Verbosef("Redirect an inbound %s packet: %s <- %s (...)\n",
				embIndicator.TransportProtocol(), embIndicator.Dst().String(), embIndicator.Src().String())
		}
	}

	// Statistics
	upStats.Add(embIndicator.DstIP().String(), uint(embIndicator.Size()))

	return nil
}

func splitArg(s string) []string {
	if s == "" {
		return nil
	}

	result := make([]string, 0)

	strs := strings.Split(s, ",")

	for _, str := range strs {
		result = append(result, strings.Trim(str, " "))
	}

	return result
}
