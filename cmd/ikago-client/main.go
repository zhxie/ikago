package main

import (
	"errors"
	"flag"
	"fmt"
	"ikago/internal/config"
	"ikago/internal/crypto"
	"ikago/internal/log"
	"ikago/internal/pcap"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var argListDevs = flag.Bool("list-devices", false, "List all valid pcap devices in current computer.")
var argConfig = flag.String("c", "", "Configuration file.")
var argListenDevs = flag.String("listen-devices", "", "pcap devices for listening.")
var argUpDev = flag.String("upstream-device", "", "pcap device for routing upstream to.")
var argUpPort = flag.Int("upstream-port", 0, "Port for routing upstream.")
var argMethod = flag.String("method", "plain", "Method of encryption.")
var argPassword = flag.String("password", "", "Password of the encryption.")
var argVerbose = flag.Bool("v", false, "Print verbose messages.")
var argFilters = flag.String("f", "", "Filters.")
var argServer = flag.String("s", "", "Server.")

func init() {
	// Parse arguments
	flag.Parse()
}

func main() {
	var (
		err        error
		filters    = make([]pcap.Filter, 0)
		serverIP   net.IP
		serverPort uint16
		listenDevs = make([]*pcap.Device, 0)
		upDev      *pcap.Device
		gatewayDev *pcap.Device
		c          crypto.Crypto
	)

	// Configuration file
	if *argConfig != "" {
		cfg, err := config.LoadConfig(*argConfig)
		if err != nil {
			log.Fatalln(fmt.Errorf("parse: %w", err))
		}

		listenDevs := cfg.ListenDevsString()
		argListenDevs = &listenDevs
		argUpDev = &cfg.UpDev
		argUpPort = &cfg.UpPort
		argMethod = &cfg.Method
		argPassword = &cfg.Password
		argVerbose = &cfg.Verbose
		filters := cfg.FiltersString()
		argFilters = &filters
		argServer = &cfg.Server
	}

	// Log
	log.SetVerbose(*argVerbose)

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
	if *argFilters == "" {
		log.Fatalln("Please provide filters by -f [filters].")
	}
	if *argServer == "" {
		log.Fatalln("Please provide server by -s [address:port].")
	}
	strFilters := strings.Split(*argFilters, ",")
	for _, strFilter := range strFilters {
		filter, err := pcap.ParseFilter(strings.Trim(strFilter, " "))
		if err != nil {
			log.Fatalln(fmt.Errorf("parse: %w", err))
		}
		filters = append(filters, filter)
	}
	if *argUpPort < 0 || *argUpPort >= 65536 {
		log.Fatalln(fmt.Errorf("parse: %w", errors.New("upstream port out of range")))
		os.Exit(1)
	}
	// Randomize upstream port
	if *argUpPort == 0 {
		s := rand.NewSource(time.Now().UnixNano())
		r := rand.New(s)
		for {
			randUpPort := 49152 + r.Intn(16384)
			argUpPort = &randUpPort
			var exist bool
			for _, filter := range filters {
				switch filter.FilterType() {
				case pcap.FilterTypeIP, pcap.FilterTypeIPPort:
					break
				case pcap.FilterTypePort:
					if filter.(*pcap.PortFilter).Port == uint16(*argUpPort) {
						exist = true
					}
				default:
					log.Fatalln(fmt.Errorf("parse: %w", fmt.Errorf("filter type %d not support", filter.FilterType())))
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
	for _, filter := range filters {
		switch filter.FilterType() {
		case pcap.FilterTypeIP, pcap.FilterTypeIPPort:
			break
		case pcap.FilterTypePort:
			if filter.(*pcap.PortFilter).Port == uint16(*argUpPort) {
				log.Fatalln(fmt.Errorf("parse: %w", errors.New("same port in filters and port for routing upstream")))
			}
		default:
			break
		}
	}
	serverIPPort, err := pcap.ParseIPPort(*argServer)
	if err != nil {
		log.Fatalln(fmt.Errorf("parse: %w", fmt.Errorf("server: %w", err)))
	}
	serverIP = serverIPPort.IP
	serverPort = serverIPPort.Port
	c, err = crypto.ParseCrypto(*argMethod, *argPassword)
	if err != nil {
		log.Fatalln(fmt.Errorf("parse: %w", err))
	}
	if len(filters) == 1 {
		log.Infof("Proxy from %s through :%d to %s\n", filters[0], *argUpPort, serverIPPort)
	} else {
		log.Info("Proxy:")
		for _, filter := range filters {
			log.Infof("\n  %s", filter)
		}
		log.Infof(" through :%d to %s\n", *argUpPort, serverIPPort)
	}

	// Find devices
	if *argListenDevs == "" {
		listenDevs, err = pcap.FindListenDevs(nil)
	} else {
		listenDevs, err = pcap.FindListenDevs(strings.Split(*argListenDevs, ","))
	}
	if err != nil {
		log.Fatalln(fmt.Errorf("parse: %w", err))
	}
	if len(listenDevs) <= 0 {
		log.Fatalln(fmt.Errorf("parse: %w", errors.New("cannot determine listen device")))
	}
	// Check if listen devices including illegal filter
	addrs := make(map[string]bool)
	for _, dev := range listenDevs {
		for _, addr := range dev.IPAddrs {
			addrs[addr.IP.String()] = true
		}
	}
	for _, filter := range filters {
		switch filter.FilterType() {
		case pcap.FilterTypeIPPort:
			ipPortFilter := filter.(*pcap.IPPortFilter)
			if ipPortFilter.Port == uint16(*argUpPort) {
				_, ok := addrs[ipPortFilter.IP.String()]
				if ok {
					log.Fatalln(fmt.Errorf("parse: %w", errors.New("same port in filters and port for routing upstream")))
				}
			}
		case pcap.FilterTypeIP, pcap.FilterTypePort:
			break
		default:
			break
		}
	}
	upDev, gatewayDev, err = pcap.FindUpstreamDevAndGateway(*argUpDev)
	if err != nil {
		log.Fatalln(fmt.Errorf("parse: %w", err))
	}
	if upDev == nil && gatewayDev == nil {
		log.Fatalln(fmt.Errorf("parse: %w", errors.New("cannot determine upstream device and gateway")))
	}
	if upDev == nil {
		log.Fatalln(fmt.Errorf("parse: %w", errors.New("cannot determine upstream device")))
	}
	if gatewayDev == nil {
		log.Fatalln(fmt.Errorf("parse: %w", errors.New("cannot determine gateway")))
	}

	// Packet capture
	p := pcap.Client{
		Filters:    filters,
		UpPort:     uint16(*argUpPort),
		ServerIP:   serverIP,
		ServerPort: serverPort,
		ListenDevs: listenDevs,
		UpDev:      upDev,
		GatewayDev: gatewayDev,
		Crypto:     c,
	}

	// Wait signals
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		p.Close()
		os.Exit(0)
	}()

	err = p.Open()
	if err != nil {
		log.Fatalln(fmt.Errorf("pcap: %w", err))
	}
}
