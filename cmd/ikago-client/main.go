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
var argMethod = flag.String("method", "plain", "Method of encryption.")
var argPassword = flag.String("password", "", "Password of the encryption.")
var argVerbose = flag.Bool("v", false, "Print verbose messages.")
var argUpPort = flag.Int("upstream-port", 0, "Port for routing upstream.")
var argFilters = flag.String("f", "", "Filters.")
var argServer = flag.String("s", "", "Server.")

func init() {
	// Parse arguments
	flag.Parse()
}

func main() {
	var (
		err        error
		cfg        *config.Config
		filters    = make([]pcap.Filter, 0)
		serverIP   net.IP
		serverPort uint16
		listenDevs = make([]*pcap.Device, 0)
		upDev      *pcap.Device
		gatewayDev *pcap.Device
		c          crypto.Crypto
	)

	// Configuration
	if *argConfig != "" {
		cfg, err = config.Parse(*argConfig)
		if err != nil {
			log.Fatalln(fmt.Errorf("parse: %w", err))
		}
	} else {
		cfg = &config.Config{
			ListenDevs: splitArg(*argListenDevs),
			UpDev:      *argUpDev,
			Method:     *argMethod,
			Password:   *argPassword,
			Verbose:    *argVerbose,
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
		log.Fatalln("Please provide filters by -f [filters].")
	}
	if cfg.Server == "" {
		log.Fatalln("Please provide server by -s [address:port].")
	}
	for _, strFilter := range cfg.Filters {
		filter, err := pcap.ParseFilter(strFilter)
		if err != nil {
			log.Fatalln(fmt.Errorf("parse: %w", err))
		}
		filters = append(filters, filter)
	}
	if cfg.UpPort < 0 || cfg.UpPort >= 65536 {
		log.Fatalln(fmt.Errorf("parse: %w", errors.New("upstream port out of range")))
		os.Exit(1)
	}
	// Randomize upstream port
	if cfg.UpPort == 0 {
		s := rand.NewSource(time.Now().UnixNano())
		r := rand.New(s)
		// Select an upstream port which is different from any port in filters
		for {
			cfg.UpPort = 49152 + r.Intn(16384)
			var exist bool
			for _, filter := range filters {
				switch filter.FilterType() {
				case pcap.FilterTypeIP, pcap.FilterTypeIPPort:
					break
				case pcap.FilterTypePort:
					if filter.(*pcap.PortFilter).Port == uint16(cfg.UpPort) {
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
	serverIPPort, err := pcap.ParseIPPort(cfg.Server)
	if err != nil {
		log.Fatalln(fmt.Errorf("parse: %w", fmt.Errorf("server: %w", err)))
	}
	serverIP = serverIPPort.IP
	serverPort = serverIPPort.Port
	c, err = crypto.Parse(cfg.Method, cfg.Password)
	if err != nil {
		log.Fatalln(fmt.Errorf("parse: %w", fmt.Errorf("crypto: %w", err)))
	}
	if len(filters) == 1 {
		log.Infof("Proxy from %s through :%d to %s\n", filters[0], cfg.UpPort, serverIPPort)
	} else {
		log.Info("Proxy:")
		for _, filter := range filters {
			log.Infof("\n  %s", filter)
		}
		log.Infof(" through :%d to %s\n", cfg.UpPort, serverIPPort)
	}

	// Find devices
	listenDevs, err = pcap.FindListenDevs(cfg.ListenDevs)
	if err != nil {
		log.Fatalln(fmt.Errorf("parse: %w", err))
	}
	if len(listenDevs) <= 0 {
		log.Fatalln(fmt.Errorf("parse: %w", errors.New("cannot determine listen device")))
	}
	upDev, gatewayDev, err = pcap.FindUpstreamDevAndGateway(cfg.UpDev)
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
		UpPort:     uint16(cfg.UpPort),
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
