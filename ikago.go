package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"./pcap"
	"./proxy"
)

var argListDevs = flag.Bool("list-devices", false, "List all valid pcap devices in current computer.")
var argListenLocal = flag.Bool("listen-local", false, "Listen loopback device only.")
var argListenDevs = flag.String("listen-devices", "", "Designated pcap devices for listening.")
var argUpLocal = flag.Bool("upstream-local", false, "Route upstream to loopback device only.")
var argUpDev = flag.String("upstream-device", "", "Designated pcap device for routing upstream to.")
var argListenPort = flag.Int("p", 0, "Port for listening.")
var argServer = flag.String("s", "", "Server.")

func main() {
	var (
		serverIP   net.IP
		serverPort uint64
		err        error
		listenDevs = make([]*pcap.Device, 0)
		upDev      *pcap.Device
	)

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
	fmt.Printf("Starting proxying from :%d to %s...\n", *argListenPort, *argServer)

	// Packet capture
	if *argListenDevs != "" {
		mapDevs := make(map[string]*pcap.Device)
		devs, err := pcap.FindAllDevs()
		if err != nil {
			fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", fmt.Errorf("listen device: %w", err)))
			os.Exit(1)
		}
		for _, dev := range devs {
			mapDevs[dev.Name] = dev
		}

		listenDevsSplit := strings.Split(*argListenDevs, ",")
		for _, strDev := range listenDevsSplit {
			dev, ok := mapDevs[strDev]
			if ok {
				listenDevs = append(listenDevs, dev)
			} else {
				fmt.Println(fmt.Errorf("parse: %w",
					fmt.Errorf("listen device: %w", fmt.Errorf("unknown device %s", strDev))))
			}
		}
	}
	if *argUpDev != "" {
		devs, err := pcap.FindAllDevs()
		if err != nil {
			fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", fmt.Errorf("upstream device: %w", err)))
			os.Exit(1)
		}
		for _, dev := range devs {
			if dev.Name == *argUpDev {
				upDev = dev
				break
			}
		}
		if upDev == nil {
			fmt.Println(fmt.Errorf("parse: %w",
				fmt.Errorf("upstream device: %w", fmt.Errorf("unknown device %s", *argUpDev))))
		}
	}
	pc := pcap.Pcap{
		ListenPort:    uint16(*argListenPort),
		ServerIP:      serverIP,
		ServerPort:    uint16(serverPort),
		IsListenLocal: *argListenLocal,
		ListenDevs:    listenDevs,
		IsLocal:       *argUpLocal,
		UpDev:         upDev,
	}
	// Proxy, for debug use
	p := proxy.Proxy{
		LocalPort:  uint16(*argListenPort),
		RemoteAddr: *argServer,
	}

	// Wait signals
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		pc.Close()
		p.Close()
		os.Exit(0)
	}()

	go func() {
		err := pc.Open()
		if err != nil {
			fmt.Fprintln(os.Stderr, fmt.Errorf("pcap: %w", err))
			os.Exit(1)
		}
	}()
	go func() {
		err := p.Open()
		if err != nil {
			fmt.Fprintln(os.Stderr, fmt.Errorf("proxy: %w", err))
			os.Exit(1)
		}
	}()

	select {}
}
