package main

import (
	"errors"
	"flag"
	"fmt"
	"ikago/internal/addr"
	"ikago/internal/config"
	"ikago/internal/crypto"
	"ikago/internal/filter"
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

var argListDevs = flag.Bool("list-devices", false, "List all valid devices in current computer.")
var argConfig = flag.String("c", "", "Configuration file.")
var argListenDevs = flag.String("listen-devices", "", "Devices for listening.")
var argUpDev = flag.String("upstream-device", "", "Device for routing upstream to.")
var argGateway = flag.String("gateway", "", "Gateway address.")
var argMethod = flag.String("method", "plain", "Method of encryption.")
var argPassword = flag.String("password", "", "Password of encryption.")
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
		gateway    net.IP
		filters    = make([]filter.Filter, 0)
		serverIP   net.IP
		serverPort uint16
		listenDevs = make([]*pcap.Device, 0)
		upDev      *pcap.Device
		gatewayDev *pcap.Device
		crypt      crypto.Crypt
	)

	// Configuration
	if *argConfig != "" {
		cfg, err = config.ParseFile(*argConfig)
		if err != nil {
			log.Fatalln(fmt.Errorf("parse config file %s: %w", *argConfig, err))
		}
	} else {
		cfg = &config.Config{
			ListenDevs: splitArg(*argListenDevs),
			UpDev:      *argUpDev,
			Gateway:    *argGateway,
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
	if cfg.Gateway != "" {
		gateway = net.ParseIP(cfg.Gateway)
		if gateway == nil {
			log.Fatalln(fmt.Errorf("invalid gateway %s", cfg.Gateway))
		}
	}
	for _, strFilter := range cfg.Filters {
		f, err := filter.ParseFilter(strFilter)
		if err != nil {
			log.Fatalln(fmt.Errorf("parse filter %s: %w", strFilter, err))
		}
		filters = append(filters, f)
	}
	if cfg.UpPort < 0 || cfg.UpPort > 65535 {
		log.Fatalln(fmt.Errorf("upstream port %d out of range", cfg.UpPort))
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
			for _, f := range filters {
				t := f.FilterType()
				switch t {
				case filter.IP, filter.IPPort:
					break
				case filter.Port:
					if f.(*filter.PortFilter).Port == uint16(cfg.UpPort) {
						exist = true
					}
				default:
					log.Fatalln(fmt.Errorf("parse filter %s: %w", f, fmt.Errorf("type %d not support", t)))
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
	serverIPPort, err := addr.ParseIPPort(cfg.Server)
	if err != nil {
		log.Fatalln(fmt.Errorf("parse server %s: %w", cfg.Server, err))
	}
	serverIP = serverIPPort.MemberIP
	serverPort = serverIPPort.Port
	crypt, err = crypto.ParseCrypt(cfg.Method, cfg.Password)
	if err != nil {
		log.Fatalln(fmt.Errorf("parse crypt: %w", err))
	}
	if len(filters) == 1 {
		log.Infof("Proxy from %s through :%d to %s\n", filters[0], cfg.UpPort, serverIPPort)
	} else {
		log.Info("Proxy:")
		for _, f := range filters {
			log.Infof("\n  %s", f)
		}
		log.Infof(" through :%d to %s\n", cfg.UpPort, serverIPPort)
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
			if dev.IsLoop {
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

	// Packet capture
	p := pcap.NewClient()
	p.Filters = filters
	p.UpPort = uint16(cfg.UpPort)
	p.ServerIP = serverIP
	p.ServerPort = serverPort
	p.ListenDevs = listenDevs
	p.UpDev = upDev
	p.GatewayDev = gatewayDev
	p.Crypt = crypt

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
		log.Fatalln(fmt.Errorf("open pcap: %w", err))
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
