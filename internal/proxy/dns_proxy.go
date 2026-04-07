package proxy

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/WGOS/yggdns64/internal/config"
	"github.com/miekg/dns"
)

type DNSProxy struct {
	cache *Cache
	cfg   config.Config
}

func (proxy *DNSProxy) GetResponse(requestMsg *dns.Msg) (*dns.Msg, error) {
	responseMsg := new(dns.Msg)
	var answer *dns.Msg
	var err error

	if len(requestMsg.Question) > 0 {
		question := requestMsg.Question[0]

		upstreams := proxy.getForwarder(question.Name)

		if proxy.cfg.Translation.IsIgnored(question.Name) {
			answer, err = proxy.processOtherTypes(upstreams, &question, requestMsg)
		} else {
			switch question.Qtype {
			case dns.TypeA:
				if proxy.cfg.StrictIPv6 {
					answer, err = proxy.processTypeA(upstreams, &question, requestMsg)
				} else {
					answer, err = proxy.processOtherTypes(upstreams, &question, requestMsg)
				}

			case dns.TypeAAAA:
				answer, err = proxy.processTypeAAAA(upstreams, &question, requestMsg)

			case dns.TypePTR:
				answer, err = proxy.processTypePTR(upstreams, &question, requestMsg)

			case dns.TypeANY:
				answer, err = proxy.processTypeANY(upstreams, &question, requestMsg)

			default:
				answer, err = proxy.processOtherTypes(upstreams, &question, requestMsg)
			}
		}
	}

	if err != nil {
		return responseMsg, err
	}

	//    answer.MsgHdr.RecursionDesired = true
	answer.MsgHdr.RecursionAvailable = true
	return answer, err
}

func (proxy *DNSProxy) processOtherTypes(upstreams []string, q *dns.Question, requestMsg *dns.Msg) (*dns.Msg, error) {
	queryMsg := new(dns.Msg)
	requestMsg.CopyTo(queryMsg)
	queryMsg.Question = []dns.Question{*q}

	msg, err := lookup(upstreams, queryMsg)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

// Query ANY
func (proxy *DNSProxy) processTypeANY(upstreams []string, q *dns.Question, requestMsg *dns.Msg) (*dns.Msg, error) {
	queryMsg := new(dns.Msg)
	requestMsg.CopyTo(queryMsg)
	queryMsg.Question = []dns.Question{*q}

	msg, err := lookup(upstreams, queryMsg)
	if err != nil {
		return nil, err
	}

	// Recompile reply
	msg.Answer = proxy.processAnswerArray(msg.Answer)
	msg.Extra = proxy.processAnswerArray(msg.Extra)

	return msg, nil
}

// process answer array
func (proxy *DNSProxy) processAnswerArray(q []dns.RR) (answer []dns.RR) {
	answer = make([]dns.RR, 0)
	for _, orr := range q {
		switch rr := orr.(type) {
		case *dns.AAAA:
			if rr.AAAA.IsUnspecified() {
				switch proxy.cfg.IA {
				case config.DiscardInvalidAddress: // drop
					continue
				case config.IgnoreInvalidAddress: // also drop
					continue
				case config.ProcessInvalidAddress: // return "as-is"
					answer = append(answer, rr)
				}
			} else {
				// if answer contains ygg address - return it
				if proxy.cfg.MeshPrefix.Contains(rr.AAAA) {
					answer = append(answer, rr)
				}
			}
		case *dns.A:
			if rr.A.IsUnspecified() {
				switch proxy.cfg.IA {
				case config.DiscardInvalidAddress: // drop
					continue
				case config.IgnoreInvalidAddress: // return "as-is"
				case config.ProcessInvalidAddress: // return "[::]"
					nrr, _ := dns.NewRR(rr.Hdr.Name + " IN AAAA ::")
					answer = append(answer, nrr)
					if !proxy.cfg.StrictIPv6 {
						answer = append(answer, rr)
					}
					continue
				}
			}
			nrr, _ := dns.NewRR(rr.Hdr.Name + " IN AAAA " + proxy.MakeFakeIP(rr.Hdr.Name, rr.A))
			answer = append(answer, nrr)
			if !proxy.cfg.StrictIPv6 {
				answer = append(answer, rr)
			}
		default:
			answer = append(answer, rr)
		}
	}
	return
}

// Query PTR
func (proxy *DNSProxy) processTypePTR(upstreams []string, q *dns.Question, requestMsg *dns.Msg) (*dns.Msg, error) {
	queryMsg := new(dns.Msg)
	requestMsg.CopyTo(queryMsg)
	//    queryMsg.Question = []dns.Question{*q}

	ip, err := proxy.ReversePTR(q.Name)
	if err != nil {
		queryMsg.MsgHdr.Rcode = dns.RcodeNameError
		queryMsg.MsgHdr.Opcode = dns.OpcodeNotify
		return queryMsg, nil
	}
	origQuestion := requestMsg.Question
	q.Name, _ = dns.ReverseAddr(ip.String())
	queryMsg.Question = []dns.Question{*q}

	msg, err := lookup(upstreams, queryMsg)
	if err != nil {
		return nil, err
	}
	msg.Question = origQuestion
	answer := make([]dns.RR, 0)
	for _, orr := range msg.Answer {
		a, okA := orr.(*dns.PTR)
		if okA {
			rr, _ := dns.NewRR(origQuestion[0].Name + " IN PTR " + a.Ptr)
			answer = append(answer, rr)
		}
	}
	msg.Answer = answer
	msg.Question[0].Qtype = dns.TypePTR
	//fmt.Printf("\nPTR %s\n",render.Render(msg))
	return msg, nil
}

// Query A record. Emulate "no record" for existings A
func (proxy *DNSProxy) processTypeA(upstreams []string, q *dns.Question, requestMsg *dns.Msg) (*dns.Msg, error) {
	queryMsg := new(dns.Msg)
	requestMsg.CopyTo(queryMsg)
	queryMsg.Question = []dns.Question{*q}
	msg, err := lookup(upstreams, queryMsg)
	if err != nil {
		queryMsg.MsgHdr.Rcode = dns.RcodeServerFailure
		queryMsg.MsgHdr.Opcode = dns.OpcodeNotify
		return queryMsg, err
	}
	msg.Answer = make([]dns.RR, 0)
	return msg, nil
}

func (proxy *DNSProxy) processTypeAAAA(upstreams []string, q *dns.Question, requestMsg *dns.Msg) (msg *dns.Msg, err error) {
	msg = new(dns.Msg)

	cacheAnswer, found := proxy.cache.Get(q.Name)

	// Have cache record?

	if !found {

		// No cache.
		// Have static address?

		ip := proxy.getStatic(q.Name)
		if ip != "" {
			requestMsg.CopyTo(msg)
			answer := make([]dns.RR, 0)
			rr, _ := dns.NewRR(q.Name + " IN AAAA " + proxy.MakeFakeIP(q.Name, net.ParseIP(ip)))
			answer = append(answer, rr)
			msg.Answer = answer
			msg.Question[0].Qtype = dns.TypeAAAA
			msg.MsgHdr.Response = true
			proxy.cache.Set(q.Name, answer, 0)
			return msg, nil
		}

		// No static.
		// Query AAAA address, may be it's already mesh?

		queryMsg := new(dns.Msg)
		requestMsg.CopyTo(queryMsg)
		queryMsg.Question = []dns.Question{*q}

		msg, err = lookup(upstreams, queryMsg)
		if err != nil {
			return nil, err
		}

		answer := make([]dns.RR, 0)
		answerv6 := make([]dns.RR, 0)

		for _, orr := range msg.Answer {
			a, okA := orr.(*dns.AAAA)
			if okA {
				if proxy.cfg.MeshPrefix.Contains(a.AAAA) {
					answer = append(answer, orr)
				}
				answerv6 = append(answerv6, orr)
			}
		}

		if len(answer) != 0 {
			msg.Answer = answer
			msg.MsgHdr.Response = true
			proxy.cache.Set(q.Name, answer, 0)
			return msg, nil
		}

		// No. Ok, query A address and translate to mesh.

		q.Qtype = dns.TypeA
		queryMsg = new(dns.Msg)
		requestMsg.CopyTo(queryMsg)
		queryMsg.Question = []dns.Question{*q}

		msg, err = lookup(upstreams, queryMsg)
		if err != nil {
			return nil, err
		}

		// Build fake answer

		answer = make([]dns.RR, 0)
		for _, orr := range msg.Answer {
			a, okA := orr.(*dns.A)
			if okA {
				if a.A.IsUnspecified() {
					switch proxy.cfg.IA {
					case config.DiscardInvalidAddress: // drop
						continue
					case config.IgnoreInvalidAddress: // return "as-is"
					case config.ProcessInvalidAddress: // return "[::]"
						nrr, _ := dns.NewRR(q.Name + " IN AAAA ::")
						answer = append(answer, nrr)
						continue
					}
				}
				rr, _ := dns.NewRR(q.Name + " IN AAAA " + proxy.MakeFakeIP(q.Name, a.A))
				answer = append(answer, rr)
			}
		}
		msg.Answer = answer
		msg.Question[0].Qtype = dns.TypeAAAA

		if len(answer) > 0 {
			proxy.cache.Set(q.Name, answer, 0)
		} else if proxy.cfg.FallBack && len(answerv6) > 0 {
			msg.Answer = answerv6
			//			msg.MsgHdr.Response = true
			proxy.cache.Set(q.Name, answerv6, 0)
		}
		return msg, nil
	} else {

		// We have cache record

		requestMsg.CopyTo(msg)
		msg.Answer = cacheAnswer.([]dns.RR)
		msg.Question[0].Qtype = dns.TypeAAAA
		msg.MsgHdr.Response = true
		return msg, nil
	}
}

func (dnsProxy *DNSProxy) getForwarder(domain string) []string {
	domainLower := strings.ToLower(domain)
	for _, zone := range dnsProxy.cfg.Forwarders.Zones {
		if strings.HasSuffix(domainLower, zone.Name) {
			return zone.Upstreams
		}
	}
	return dnsProxy.cfg.Forwarders.Default
}

func (dnsProxy *DNSProxy) getStatic(domain string) string {
	for k, v := range dnsProxy.cfg.Static {
		if strings.EqualFold(k+".", domain) {
			return v
		}
	}
	return ""
}

func GetOutboundIP() (net.IP, error) {

	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP, nil
}

func lookup(servers []string, m *dns.Msg) (*dns.Msg, error) {
	if len(servers) == 0 {
		return nil, fmt.Errorf("no upstream servers configured")
	}

	resCh := make(chan *dns.Msg, len(servers))
	errCh := make(chan error, len(servers))

	for _, server := range servers {
		go func(srv string) {
			dnsClient := new(dns.Client)
			dnsClient.Net = "udp"
			msg := m.Copy()
			response, _, err := dnsClient.Exchange(msg, srv)
			if err != nil {
				errCh <- err
				return
			}
			resCh <- response
		}(server)
	}

	var lastErr error
	for i := 0; i < len(servers); i++ {
		select {
		case resp := <-resCh:
			return resp, nil
		case err := <-errCh:
			lastErr = err
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return nil, fmt.Errorf("no response from upstreams")
}

func (proxy *DNSProxy) MakeFakeIP(domain string, r net.IP) string {
	prefix := proxy.cfg.Translation.GetPrefix(domain)
	ip := make(net.IP, len(prefix))
	copy(ip, prefix)

	if len(r) == net.IPv6len {
		ip[15] = r[15]
		ip[14] = r[14]
		ip[13] = r[13]
		ip[12] = r[12]
	} else {
		ip[15] = r[3]
		ip[14] = r[2]
		ip[13] = r[1]
		ip[12] = r[0]
	}

	return ip.String()
}

func ReversePTR(ptr string) (net.IP, error) {
	var ip net.IP
	if !strings.HasSuffix(ptr, ".in-addr.arpa.") && !strings.HasSuffix(ptr, ".ip6.arpa.") {
		return ip, fmt.Errorf("Wrong ptr address in query %s", ptr)
	}
	s := strings.Split(ptr, ".")
	switch len(s) {
	case 7: // ipv4 in-addr arpa
		ip = make([]byte, net.IPv4len)
		for i, j := 0, net.IPv4len-1; i < 4; i, j = i+1, j-1 {
			a, err := strconv.ParseUint(s[i], 10, 8)
			if err != nil {
				return net.IP{}, err
			}
			ip[j] = byte(a)
		}
	case 35: // ipv6 ipv6 arpa
		ip = make([]byte, net.IPv6len)
		for i, j := 0, net.IPv6len-1; i < 32; i, j = i+2, j-1 {
			a, err := strconv.ParseUint(s[i], 16, 8)
			if err != nil {
				return net.IP{}, err
			}
			b, err := strconv.ParseUint(s[i+1], 16, 8)
			if err != nil {
				return net.IP{}, err
			}
			ip[j] = byte(b)<<4 | byte(a)
		}
	default: // wrong length
		return ip, fmt.Errorf("Wrong PTR in query %s", ptr)
	}
	return ip, nil
}

func (proxy *DNSProxy) ReversePTR(ptr string) (ipv4 net.IP, err error) {
	var ip net.IP
	ip, err = ReversePTR(ptr)
	if err != nil {
		return
	}
	if len(ip) != net.IPv6len {
		err = fmt.Errorf("PTR is not IPv6")
	}
	defaultPrefix := proxy.cfg.Translation.DefaultIP
	for i := 0; i < 12; i++ {
		if ip[i] != defaultPrefix[i] {
			err = fmt.Errorf("PTR doesn't have our prefix")
			return
		}
	}
	ipv4 = make([]byte, 4)
	ipv4[3] = ip[15]
	ipv4[2] = ip[14]
	ipv4[1] = ip[13]
	ipv4[0] = ip[12]
	return
}

func NewProxy(cfg config.Config) *DNSProxy {
	return &DNSProxy{
		cfg:   cfg,
		cache: NewCache(cfg.Cache.ExpTime, cfg.Cache.PurgeTime),
	}
}
