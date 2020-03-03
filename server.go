package main

import (
	"./pcap"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	var (
		err             error
		ipVersionOption = pcap.IPv4AndIPv6
		listenDevs      = make([]*pcap.Device, 0)
		upDev           *pcap.Device
		gatewayDev      *pcap.Device
	)

	var argListDevs = flag.Bool("list-devices", false, "List all valid pcap devices in current computer.")
	var argListenLoopDev = flag.Bool("listen-loopback-device", false, "Listen loopback device only.")
	var argListenDevs = flag.String("listen-devices", "", "Designated pcap devices for listening.")
	var argUpLoopDev = flag.Bool("upstream-loopback-device", false, "Route upstream to loopback device only.")
	var argUpDev = flag.String("upstream-device", "", "Designated pcap device for routing upstream to.")
	var argIPv4Dev = flag.Bool("ipv4", false, "Use IPv4 only.")
	var argIPv6Dev = flag.Bool("ipv6", false, "Use IPv6 only.")
	var argListenPort = flag.Int("p", 0, "Port for listening.")

	// Parse arguments
	flag.Parse()
	if *argListDevs {
		fmt.Println("Available devices are listed below, use -listen-devices [devices] or -upstream-device [device] to designate device:")
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
	if *argListenPort == 0 {
		fmt.Fprintln(os.Stderr, "Please provide listen port by -p [port].")
		os.Exit(1)
	}

	// Verify parameters
	if *argListenPort <= 0 || *argListenPort >= 65536 {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", errors.New("listen port out of range")))
		os.Exit(1)
	}
	fmt.Printf("Proxy from :%d\n", *argListenPort)

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
	upDev, gatewayDev, err = pcap.FindUpstreamDevAndGateway(*argUpDev, *argUpLoopDev, ipVersionOption)
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", err))
		os.Exit(1)
	}
	if upDev == nil && gatewayDev == nil {
		fmt.Fprintln(os.Stderr,
			fmt.Errorf("parse: %w", errors.New("cannot determine upstream device and gateway")))
		os.Exit(1)
	}
	if upDev == nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", errors.New("cannot determine upstream device")))
		os.Exit(1)
	}
	if gatewayDev == nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", errors.New("cannot determine gateway")))
		os.Exit(1)
	}

	// Packet capture
	p := pcap.Server{
		ListenPort: uint16(*argListenPort),
		ListenDevs: listenDevs,
		UpDev:      upDev,
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
