package main

import (
	"./pcap"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	var (
		err             error
		filters         = make([]pcap.Filter, 0)
		ipVersionOption = pcap.IPv4AndIPv6
		serverIP        net.IP
		serverPort      uint16
		listenDevs      = make([]*pcap.Device, 0)
		gatewayDev      *pcap.Device
	)

	var argListDevs = flag.Bool("list-devices", false, "List all valid pcap devices in current computer.")
	var argListenLoopDev = flag.Bool("listen-loopback-device", false, "Listen loopback device only.")
	var argListenDevs = flag.String("listen-devices", "", "Designated pcap devices for listening.")
	var argUpLoopDev = flag.Bool("upstream-loopback-device", false, "Route upstream to loopback device only.")
	var argIPv4Dev = flag.Bool("ipv4-device", false, "Use IPv4 device only.")
	var argIPv6Dev = flag.Bool("ipv6-device", false, "Use IPv6 device only.")
	var argFilters = flag.String("f", "", "Filters.")
	var argUpPort = flag.Int("upstream-port", 0, "Port for routing upstream.")
	var argServer = flag.String("s", "", "Server.")

	// Parse arguments
	flag.Parse()
	if *argListDevs {
		fmt.Println("Available devices are listed below, use -listen-device [device] or -upstream-device [device] to designate device:")
		devs, err := pcap.FindAllDevs()
		if err != nil {
			fmt.Fprintln(os.Stderr, fmt.Errorf("list devices: %w", err))
			os.Exit(1)
		}
		for _, dev := range devs {
			fmt.Printf("  %s\n", dev)
		}
		os.Exit(0)
	}
	if *argFilters == "" {
		fmt.Fprintln(os.Stderr, "Please provide filters by -f [filters].")
		os.Exit(1)
	}
	if *argServer == "" {
		fmt.Fprintln(os.Stderr, "Please provide server by -s [address:port].")
		os.Exit(1)
	}

	// Verify parameters
	strFilters := strings.Split(*argFilters, ",")
	for _, strFilter := range strFilters {
		filter, err := pcap.ParseFilter(strFilter)
		if err != nil {
			fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", err))
			os.Exit(1)
		}
		filters = append(filters, filter)
	}
	if *argUpPort < 0 || *argUpPort >= 65536 {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", errors.New("upstream port out of range")))
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
				case pcap.FilterTypeIP:
				case pcap.FilterTypeIPPort:
					break
				case pcap.FilterTypePort:
					if filter.(*pcap.PortFilter).Port == uint16(*argUpPort) {
						exist = true
					}
				default:
					// TODO: escape default
					break
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
		case pcap.FilterTypeIP:
		case pcap.FilterTypeIPPort:
			break
		case pcap.FilterTypePort:
			if filter.(*pcap.PortFilter).Port == uint16(*argUpPort) {
				fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", errors.New("same port in filters and port for routing upstream")))
				os.Exit(1)
			}
		default:
			// TODO: escape default
			break
		}
	}
	serverIPPort, err := pcap.ParseIPPort(*argServer)
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", fmt.Errorf("server: %w", err)))
		os.Exit(1)
	}
	serverIP = serverIPPort.IP
	serverPort = serverIPPort.Port
	if len(filters) == 1 {
		fmt.Printf("Proxy from %s through :%d to %s\n", filters[0], *argUpPort, serverIPPort)
	} else {
		fmt.Println("Proxy:")
		for _, filter := range filters {
			fmt.Printf("  %s\n", filter)
		}
		fmt.Printf("    through :%d to %s\n", *argUpPort, serverIPPort)
	}

	// Find devices
	if *argIPv4Dev && !*argIPv6Dev {
		ipVersionOption = pcap.IPv4Only
	}
	if *argIPv6Dev && !*argIPv4Dev {
		ipVersionOption = pcap.IPv6Only
	}
	if *argListenDevs == "" {
		listenDevs, err = pcap.FindListenDevs(nil, *argListenLoopDev, ipVersionOption)
	} else {
		listenDevs, err = pcap.FindListenDevs(strings.Split(*argListenDevs, ","), *argListenLoopDev, ipVersionOption)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", err))
		os.Exit(1)
	}
	if len(listenDevs) <= 0 {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", errors.New("cannot determine listen device")))
		os.Exit(1)
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
					fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", errors.New("same port in filters and port for routing upstream")))
					os.Exit(1)
				}
			}
		case pcap.FilterTypeIP:
		case pcap.FilterTypePort:
			break
		default:
			break
		}
	}
	_, gatewayDev, err = pcap.FindUpstreamDevAndGateway("", *argUpLoopDev, ipVersionOption)
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", err))
		os.Exit(1)
	}
	if gatewayDev == nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", errors.New("cannot determine gateway")))
		os.Exit(1)
	}

	// Packet capture
	p := pcap.Client{
		Filters:    filters,
		UpPort:     uint16(*argUpPort),
		ServerIP:   serverIP,
		ServerPort: serverPort,
		ListenDevs: listenDevs,
		GatewayDev: gatewayDev,
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
		fmt.Fprintln(os.Stderr, fmt.Errorf("pcap: %w", err))
		os.Exit(1)
	}
}
