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
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	var (
		err        error
		serverIP   net.IP
		serverPort uint64
		listenDevs = make([]*pcap.Device, 0)
		upDev      *pcap.Device
		gatewayDev *pcap.Device
	)

	var argListDevs = flag.Bool("list-devices", false, "List all valid pcap devices in current computer.")
	var argListenLocal = flag.Bool("listen-local", false, "Listen loopback device only.")
	var argListenDevs = flag.String("listen-devices", "", "Designated pcap devices for listening.")
	var argUpLocal = flag.Bool("upstream-local", false, "Route upstream to loopback device only.")
	var argUpDev = flag.String("upstream-device", "", "Designated pcap device for routing upstream to.")
	var argListenPort = flag.Int("p", 0, "Port for listening.")
	var argUpPort = flag.Int("upstream-port", 0, "Port for routing upstream.")
	var argServer = flag.String("s", "", "Server.")

	// Parse arguments
	flag.Parse()
	if *argListDevs {
		fmt.Println("Available devices are listed below, use -listen-device [device] or " +
			"-upstream-device [device] to designate device:")
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
	if *argServer == "" {
		fmt.Fprintln(os.Stderr, "Please provide server by -s [address:port].")
		os.Exit(1)
	}

	// Verify parameters
	if *argListenPort <= 0 || *argListenPort >= 65536 {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", errors.New("listen port out of range")))
		os.Exit(1)
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
			if *argListenPort != *argUpPort {
				break
			}
		}
	}
	if *argListenPort == *argUpPort {
		fmt.Fprintln(os.Stderr,
			fmt.Errorf("parse: %w", errors.New("same port for listening and routing upstream")))
		os.Exit(1)
	}
	serverSplit := strings.Split(*argServer, ":")
	if len(serverSplit) < 2 {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", errors.New("invalid server")))
		os.Exit(1)
	}
	serverIP = net.ParseIP(serverSplit[0])
	if serverIP == nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", errors.New("invalid server ip")))
		os.Exit(1)
	}
	serverPort, err = strconv.ParseUint(serverSplit[len(serverSplit) - 1], 10, 16)
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", errors.New("invalid server port")))
		os.Exit(1)
	}
	if serverPort <= 0 || serverPort >= 65535 {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", errors.New("server port out of range")))
		os.Exit(1)
	}
	fmt.Printf("Starting proxying from :%d through :%d to %s...\n",
		*argListenPort, *argUpPort, *argServer)

	// Find devices
	if *argListenDevs == "" {
		listenDevs, err = pcap.FindListenDevs(nil, *argListenLocal)
	} else {
		listenDevs, err = pcap.FindListenDevs(strings.Split(*argListenDevs, ","), *argListenLocal)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", err))
		os.Exit(1)
	}
	if len(listenDevs) <= 0 {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", errors.New("cannot determine listen device")))
		os.Exit(1)
	}
	upDev, gatewayDev, err = pcap.FindUpstreamDevAndGateway(*argUpDev, *argUpLocal)
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
	p := pcap.Client{
		ListenPort:    uint16(*argListenPort),
		UpPort:        uint16(*argUpPort),
		ServerIP:      serverIP,
		ServerPort:    uint16(serverPort),
		ListenDevs:    listenDevs,
		UpDev:         upDev,
		GatewayDev:    gatewayDev,
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
