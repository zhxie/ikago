package main

import (
	"errors"
	"flag"
	"fmt"
	"ikago/internal/config"
	"ikago/internal/crypto"
	"ikago/internal/log"
	"ikago/internal/pcap"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

var argListDevs = flag.Bool("list-devices", false, "List all valid pcap devices in current computer.")
var argConfig = flag.String("c", "", "Configuration file.")
var argListenDevs = flag.String("listen-devices", "", "pcap devices for listening.")
var argUpDev = flag.String("upstream-device", "", "pcap device for routing upstream to.")
var argMethod = flag.String("method", "plain", "Method of encryption.")
var argPassword = flag.String("password", "", "Password of the encryption.")
var argVerbose = flag.Bool("v", false, "Print verbose messages.")
var argListenPort = flag.Int("p", 0, "Port for listening.")

func init() {
	// Parse arguments
	flag.Parse()
}

func main() {
	var (
		err        error
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
		argMethod = &cfg.Method
		argPassword = &cfg.Password
		argVerbose = &cfg.Verbose
		argListenPort = &cfg.ListenPort
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
	if *argListenPort == 0 {
		log.Fatalln("Please provide listen port by -p [port].")
	}
	if *argListenPort <= 0 || *argListenPort >= 65536 {
		log.Fatalln(fmt.Errorf("parse: %w", errors.New("listen port out of range")))
	}
	c, err = crypto.ParseCrypto(*argMethod, *argPassword)
	if err != nil {
		log.Fatalln(fmt.Errorf("parse: %w", err))
	}
	log.Infof("Proxy from :%d\n", *argListenPort)

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
	p := pcap.Server{
		ListenPort: uint16(*argListenPort),
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
