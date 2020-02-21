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

var listDevs = flag.Bool("list-devices", false, "List all valid pcap devices in current computer.")
var listenLocal = flag.Bool("listen-local", false, "Listen loopback device only.")
var local = flag.Bool("local", false, "Route upstream to loopback device.")
var upDev = flag.String("d", "", "Route upstream to designated pcap device.")
var listenPort = flag.Int("p", 0, "Port for listening.")
var server = flag.String("s", "", "Server.")

func main() {
	var (
		serverIP   net.IP
		serverPort uint64
		err        error
	)

	// Parse arguments
	flag.Parse()
	if *listDevs {
		fmt.Println("Available devices are listed below, use -d [device] to designate device:")
		devs, err := pcap.FindAllDevs()
		if err != nil {
			fmt.Fprintln(os.Stderr, fmt.Errorf("list devices: %w", err))
			os.Exit(1)
		}
		for _, d := range devs {
			fmt.Println(d)
		}
		os.Exit(0)
	}
	if *listenPort == 0 {
		fmt.Fprintln(os.Stderr, "Please provide listen port by -p [port].")
		os.Exit(1)
	}
	if *server == "" {
		fmt.Fprintln(os.Stderr, "Please provide server by -s [address:port].")
		os.Exit(1)
	}

	// Verify parameters
	if *listenPort <= 0 || *listenPort >= 65536 {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", errors.New("listen port out of range")))
		os.Exit(1)
	}
	serverSplit := strings.Split(*server, ":")
	if len(serverSplit) < 2 {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w",
			fmt.Errorf("server: %w", errors.New("invalid"))))
		os.Exit(1)
	}
	serverIP = net.ParseIP(serverSplit[0])
	if serverIP == nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w",
			fmt.Errorf("server: %w", errors.New("invalid ip"))))
		os.Exit(1)
	}
	serverPort, err = strconv.ParseUint(serverSplit[len(serverSplit) - 1], 10, 16)
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w",
			fmt.Errorf("server: %w", errors.New("invalid port"))))
		os.Exit(1)
	}
	if serverPort <= 0 || serverPort >= 65535 {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w",
			fmt.Errorf("server: %w", errors.New("port out of range"))))
		os.Exit(1)
	}
	fmt.Printf("Starting proxying from :%d to %s...\n", *listenPort, *server)

	// Packet capture
	var d *pcap.Device
	if *upDev != "" {
		devs, err := pcap.FindAllDevs()
		if err != nil {
			fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", err))
			os.Exit(1)
		}
		for _, de := range devs {
			if de.Name == *upDev {
				d = de
				break
			}
		}
	}
	pc := pcap.Pcap{
		ListenPort:    uint16(*listenPort),
		ServerIP:      serverIP,
		ServerPort:    uint16(serverPort),
		IsLocal:       *local,
		UpDev:         d,
		IsListenLocal: *listenLocal,
	}
	// Proxy, for debug use
	p := proxy.Proxy{
		LocalPort:  uint16(*listenPort),
		RemoteAddr: *server,
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
