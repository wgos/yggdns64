package main

// Based on https://github.com/katakonst/go-dns-proxy/releases

import (
	"log"
	"net"
	"time"

	"github.com/WGOS/yggdns64/internal/config"
	"github.com/WGOS/yggdns64/internal/logger"
	"github.com/WGOS/yggdns64/internal/proxy"
	"github.com/miekg/dns"
)

func main() {
	cfg, err := config.InitConfig()
	if err != nil {
		log.Fatalf("Failed to load configs: %s", err)
	}

	prefix := net.ParseIP(cfg.Prefix)
	if len(prefix) != net.IPv6len || prefix.IsUnspecified() {
		log.Fatalf("Wrong prefix format: %s", cfg.Prefix)
	}

	_, yggnet, _ := net.ParseCIDR(cfg.MeshPrefix)

	dnsProxy := proxy.NewProxy(
		proxy.New(cfg.Cache.ExpTime*time.Minute, cfg.Cache.PurgeTime*time.Minute),
		cfg.Static,
		cfg.Forwarders,
		cfg.Default,
		prefix,
		cfg.StrictIPv6,
		cfg.IA,
		cfg.FallBack,
		yggnet,
	)

	logger := logger.NewLogger(cfg.LogLevel)

	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		switch r.Opcode {
		case dns.OpcodeQuery:
			m, err := dnsProxy.GetResponse(r)
			if err != nil {
				logger.Errorf("Failed lookup for %s with error: %s\n", r, err.Error())
			}
			w.WriteMsg(m)
		}
	})

	server := &dns.Server{Addr: cfg.Listen, Net: "udp"}
	logger.Infof("Starting at %s\n", cfg.Listen)
	err = server.ListenAndServe()
	if err != nil {
		logger.Errorf("Failed to start server: %s\n ", err.Error())
	}
}
