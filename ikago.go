package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"./pcap"
	"./proxy"
)

var device = flag.String("d", "", "Device")
var localPort = flag.Int("l", 0, "LocalPort LocalPort")
var remoteAddr = flag.String("r", "", "Remote Address")

func main() {
	flag.Parse()

	if *device == "" {
		fmt.Fprintln(os.Stderr, "Please provide device by -d [device].")
		fmt.Println("Available devices are listed below:")
		devs, err := pcap.FindAllDevs()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		for _, dev := range devs {
			fmt.Println(dev)
		}
		os.Exit(1)
	}
	if *localPort == 0 {
		fmt.Fprintln(os.Stderr, "Please provide local port port by -l [port].")
		os.Exit(1)
	}
	if *localPort <= 0 || *localPort >= 65536 {
		fmt.Fprintln(os.Stderr, "Provided local port is out of range [1, 65535].")
		os.Exit(1)
	}
	if *remoteAddr == "" {
		fmt.Fprintln(os.Stderr, "Please provide remote address by -r [address:port].")
		os.Exit(1)
	}
	remoteAddrSplit := strings.Split(*remoteAddr, ":")
	if len(remoteAddrSplit) < 2 {
		fmt.Fprintln(os.Stderr, "Provided remote address is invalid.")
		os.Exit(1)
	}
	remotePort, err := strconv.ParseUint(remoteAddrSplit[len(remoteAddrSplit) - 1], 10, 16)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Provided remote address's port is invalid.")
		os.Exit(1)
	}
	if remotePort <= 0 || remotePort >= 65535 {
		fmt.Fprintln(os.Stderr, "Provided remote address's port is out of range [1, 65535].")
		os.Exit(1)
	}
	fmt.Printf("Starting proxying from :%d to %s...\n", *localPort, *remoteAddr)

	pc := pcap.Pcap{
		Device:     *device,
		LocalPort:  uint16(*localPort),
		RemotePort: uint16(remotePort),
	}
	// This is a tcp proxy for debug
	p := proxy.Proxy{
		LocalPort:  uint16(*localPort),
		RemoteAddr: *remoteAddr,
	}

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
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}()
	go func() {
		err := p.Open()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}()

	select {}
}
