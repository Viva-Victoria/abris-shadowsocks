// Copyright 2018 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"container/list"
	"fmt"
	"github.com/Viva-Victoria/abris-shadowsocks/config"
	"github.com/op/go-logging"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/transport"
	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
	"github.com/Viva-Victoria/abris-shadowsocks/ipinfo"
	"github.com/Viva-Victoria/abris-shadowsocks/service"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/term"
	"gopkg.in/yaml.v2"
)

var logger *logging.Logger

// Set by goreleaser default ldflags. See https://goreleaser.com/customization/build/
var version = "dev"

// 59 seconds is most common timeout for servers that do not respond to invalid requests
const tcpReadTimeout time.Duration = 59 * time.Second

// A UDP NAT timeout of at least 5 minutes is recommended in RFC 4787 Section 4.3.
const defaultNatTimeout time.Duration = 5 * time.Minute

func init() {
	var prefix = "%{level:.1s}%{time:2006-01-02T15:04:05.000Z07:00} %{pid} %{shortfile}]"
	if term.IsTerminal(int(os.Stdout.Fd())) {
		// Add color only if the output is the terminal
		prefix = strings.Join([]string{"%{color}", prefix, "%{color:reset}"}, "")
	}

	logging.SetFormatter(logging.MustStringFormatter(strings.Join([]string{prefix, " %{message}"}, "")))
	logging.SetBackend(logging.NewLogBackend(os.Stdout, "", 0))
	logger = logging.MustGetLogger("")
}

type ssPort struct {
	tcpListener *net.TCPListener
	packetConn  net.PacketConn
	cipherList  service.CipherList
}

type SSServer struct {
	natTimeout  time.Duration
	m           *outlineMetrics
	replayCache service.ReplayCache
	ports       map[int]*ssPort
}

func (s *SSServer) startPort(portNum int) error {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{Port: portNum})
	if err != nil {
		//lint:ignore ST1005 Shadowsocks is capitalized.
		return fmt.Errorf("Shadowsocks TCP service failed to start on port %v: %w", portNum, err)
	}

	logger.Infof("Shadowsocks TCP service listening on %v", listener.Addr().String())
	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: portNum})
	if err != nil {
		//lint:ignore ST1005 Shadowsocks is capitalized.
		return fmt.Errorf("Shadowsocks UDP service failed to start on port %v: %w", portNum, err)
	}

	logger.Infof("Shadowsocks UDP service listening on %v", packetConn.LocalAddr().String())
	port := &ssPort{
		tcpListener: listener,
		packetConn:  packetConn,
		cipherList:  service.NewCipherList(),
	}

	// TODO: Register initial data metrics at zero.
	tcpHandler := service.NewTCPHandler(portNum, port.cipherList, &s.replayCache, s.m, tcpReadTimeout)
	packetHandler := service.NewPacketHandler(s.natTimeout, port.cipherList, s.m)
	s.ports[portNum] = port

	accept := func() (transport.StreamConn, error) {
		conn, err := listener.AcceptTCP()
		if err == nil {
			_ = conn.SetKeepAlive(true)
		}

		return conn, err
	}

	go service.StreamServe(accept, tcpHandler.Handle)
	go packetHandler.Handle(port.packetConn)

	return nil
}

func (s *SSServer) removePort(portNum int) error {
	port, ok := s.ports[portNum]
	if !ok {
		return fmt.Errorf("port %v doesn't exist", portNum)
	}

	tcpErr := port.tcpListener.Close()
	udpErr := port.packetConn.Close()

	delete(s.ports, portNum)

	if tcpErr != nil {
		//lint:ignore ST1005 Shadowsocks is capitalized.
		return fmt.Errorf("Shadowsocks TCP service on port %v failed to stop: %w", portNum, tcpErr)
	}

	logger.Infof("Shadowsocks TCP service on port %v stopped", portNum)
	if udpErr != nil {
		//lint:ignore ST1005 Shadowsocks is capitalized.
		return fmt.Errorf("Shadowsocks UDP service on port %v failed to stop: %w", portNum, udpErr)
	}

	logger.Infof("Shadowsocks UDP service on port %v stopped", portNum)
	return nil
}

func (s *SSServer) loadKeyFile(filename string) error {
	keyFile, err := readKeyFile(filename)
	if err != nil {
		return fmt.Errorf("failed to load config (%v): %w", filename, err)
	}

	portChanges := make(map[int]int)
	portCiphers := make(map[int]*list.List) // Values are *List of *CipherEntry.

	for _, keyConfig := range keyFile.Keys {
		portChanges[keyConfig.Port] = 1
		cipherList, ok := portCiphers[keyConfig.Port]
		if !ok {
			cipherList = list.New()
			portCiphers[keyConfig.Port] = cipherList
		}

		cryptoKey, err := shadowsocks.NewEncryptionKey(keyConfig.Cipher, keyConfig.Secret)
		if err != nil {
			return fmt.Errorf("failed to create encyption key for key %v: %w", keyConfig.ID, err)
		}

		entry := service.MakeCipherEntry(keyConfig.ID, cryptoKey, keyConfig.Secret)
		cipherList.PushBack(&entry)
	}

	for port := range s.ports {
		portChanges[port] = portChanges[port] - 1
	}

	for portNum, count := range portChanges {
		if count == -1 {
			if err := s.removePort(portNum); err != nil {
				return fmt.Errorf("failed to remove port %v: %w", portNum, err)
			}

			continue
		}

		if count == +1 {
			if err := s.startPort(portNum); err != nil {
				return err
			}

			continue
		}
	}

	for portNum, cipherList := range portCiphers {
		s.ports[portNum].cipherList.Update(cipherList)
	}

	logger.Infof("Loaded %v access keys over %v ports", len(keyFile.Keys), len(s.ports))
	s.m.SetNumAccessKeys(len(keyFile.Keys), len(portCiphers))

	return nil
}

// Stop serving on all ports.
func (s *SSServer) Stop() error {
	for portNum := range s.ports {
		if err := s.removePort(portNum); err != nil {
			return err
		}
	}

	return nil
}

// RunSSServer starts a shadowsocks server running, and returns the server or an error.
func RunSSServer(filename string, natTimeout time.Duration, sm *outlineMetrics, replayHistory int) (*SSServer, error) {
	server := &SSServer{
		natTimeout:  natTimeout,
		m:           sm,
		replayCache: service.NewReplayCache(replayHistory),
		ports:       make(map[int]*ssPort),
	}

	err := server.loadKeyFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed configure server: %w", err)
	}

	sigHup := make(chan os.Signal, 1)
	signal.Notify(sigHup, syscall.SIGHUP)
	go func() {
		for range sigHup {
			logger.Infof("SIGHUP received. Loading config from %v", filename)
			if err := server.loadKeyFile(filename); err != nil {
				logger.Errorf("Failed to update server: %v. Server state may be invalid. Fix the error and try the update again", err)
			}
		}
	}()

	return server, nil
}

type KeyFile struct {
	Keys []struct {
		ID     string
		Port   int
		Cipher string
		Secret string
	}
}

func readKeyFile(filename string) (*KeyFile, error) {
	var keyFile KeyFile
	configData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	err = yaml.Unmarshal(configData, &keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return &keyFile, nil
}

func main() {
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}

	if cfg.Verbose {
		logging.SetLevel(logging.DEBUG, "")
	} else {
		logging.SetLevel(logging.INFO, "")
	}

	if metrics := cfg.Listen.Metrics; len(metrics) > 0 {
		http.Handle("/metrics", promhttp.Handler())
		go func() {
			logger.Fatalf("Failed to run metrics server: %v. Aborting.", http.ListenAndServe(metrics, nil))
		}()
		logger.Infof("Prometheus metrics available at http://%v/metrics", metrics)
	}

	_, err = RunSSServer(cfg.Keys.Path, cfg.Timeout.NAT.Duration, initMetrics(cfg), cfg.ReplayHistory)
	if err != nil {
		logger.Fatalf("Server failed to start: %v. Aborting", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}

func initMetrics(cfg config.Config) *outlineMetrics {
	ip2c := cfg.GeoIP.Countries
	if len(ip2c) > 0 {
		logger.Infof("Using IP-Country database at %v", ip2c)
	}

	ip2n := cfg.GeoIP.ASN
	if len(ip2n) > 0 {
		logger.Infof("Using IP-ASN database at %v", ip2n)
	}

	ip2info, err := ipinfo.NewMMDBIPInfoMap(ip2c, ip2n)
	if err != nil {
		logger.Fatalf("Could create IP info map: %v. Aborting", err)
	}
	defer ip2info.Close()

	m := newPrometheusOutlineMetrics(ip2info, prometheus.DefaultRegisterer)
	m.SetBuildInfo(version)

	return m
}
