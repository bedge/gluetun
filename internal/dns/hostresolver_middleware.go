package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/miekg/dns"
	"github.com/qdm12/golibs/logging"
	"github.com/qdm12/dns/v2/pkg/middlewares/localdns"
	"github.com/qdm12/dns/v2/pkg/plain"
	"github.com/qdm12/dns/v2/pkg/server"
)

// hostResolverMiddleware is a middleware that forwards matching queries to a
// configured list of host resolvers. It implements qdm12/dns middleware style
// by exposing a function that wraps the DNS handler.
func hostResolverMiddleware(hostResolvers []netip.Addr, l Logger, loop *Loop) func(next dns.Handler) dns.Handler {
	return func(next dns.Handler) dns.Handler {
		return dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			if len(r.Question) == 0 {
				next.ServeDNS(w, r)
				return
			}
			qname := strings.TrimSuffix(r.Question[0].Name, ".")
			if !loop.MatchesHostResolverDomain(qname) {
				next.ServeDNS(w, r)
				return
			}

			// matched domain: ensure we have resolvers
			if len(hostResolvers) == 0 {
				l.Error("no host resolvers available for matched domain " + qname + " — returning SERVFAIL")
				_ = w.WriteMsg(new(dns.Msg).SetRcode(r, dns.RcodeServerFailure))
				return
			}

			// Build a plain dialer to the host resolvers and perform the query
			// using UDP first and then TCP on failure.
			l.Info("forwarding " + qname + " to host resolver(s) for DNS_HOST_RESOLVER_DOMAINS: " + formatAddrs(hostResolvers))

			var lastErr error
			for _, addr := range hostResolvers {
				addrStr := net.JoinHostPort(addr.String(), "53")
				// UDP
				conn, err := net.Dial("udp", addrStr)
				if err == nil {
					dnsConn := &dns.Conn{Conn: conn}
					client := &dns.Client{Net: "udp"}
					resp, _, err := client.ExchangeWithConn(r, dnsConn)
					_ = dnsConn.Close()
					if err == nil && resp != nil {
						if err := w.WriteMsg(resp); err != nil {
							l.Warn("cannot write DNS message back to client: " + err.Error())
						}
						return
					}
					lastErr = err
				}

				// try TCP if UDP failed
				conn, err = net.Dial("tcp", addrStr)
				if err != nil {
					lastErr = err
					continue
				}
				dnsConn := &dns.Conn{Conn: conn}
				client := &dns.Client{Net: "tcp"}
				resp, _, err := client.ExchangeWithConn(r, dnsConn)
				_ = dnsConn.Close()
				if err == nil && resp != nil {
					if err := w.WriteMsg(resp); err != nil {
						l.Warn("cannot write DNS message back to client: " + err.Error())
					}
					return
				}
				lastErr = err
			}

			l.Warn("host resolver forwarding failed for " + qname + ": " + errorToString(lastErr))
			_ = w.WriteMsg(new(dns.Msg).SetRcode(r, dns.RcodeServerFailure))
		})
	}
}

func formatAddrs(addrs []netip.Addr) string {
	parts := make([]string, 0, len(addrs))
	for _, a := range addrs {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, ",")
}

func errorToString(err error) string {
	if err == nil {
		return "nil"
	}
	return err.Error()
}
