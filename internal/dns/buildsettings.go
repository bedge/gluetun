package dns

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/qdm12/dns/v2/pkg/middlewares/filter/mapfilter"
	"github.com/qdm12/dns/v2/pkg/middlewares/filter/update"
	"github.com/qdm12/dns/v2/pkg/middlewares/localdns"
	"github.com/qdm12/dns/v2/pkg/server"
	"github.com/qdm12/gluetun/internal/configuration/settings"
)

// buildServerSettings builds the qdm12 DNS server settings and inserts a local
// host resolver middleware that forwards matching queries to host resolvers.
func (l *Loop) buildServerSettings(userSettings settings.DNS,
	filter *mapfilter.Filter, localResolvers []netip.Addr,
	localSubnets []netip.Prefix, logger Logger) (
	serverSettings server.Settings, err error,
) {
	serverSettings.Logger = logger

	upstreamResolvers := buildProviders(userSettings, localSubnets, logger)

	ipVersion := "ipv4"
	if *userSettings.IPv6 {
		ipVersion = "ipv6"
	}

	var dialer server.Dialer
	switch userSettings.UpstreamType {
	case settings.DNSUpstreamTypeDot:
		dialerSettings := dot.Settings{
			UpstreamResolvers: upstreamResolvers,
			IPVersion:         ipVersion,
		}
		dialer, err = dot.New(dialerSettings)
		if err != nil {
			return server.Settings{}, fmt.Errorf("creating DNS over TLS dialer: %w", err)
		}
	case settings.DNSUpstreamTypeDoh:
		dialerSettings := doh.Settings{
			UpstreamResolvers: upstreamResolvers,
			IPVersion:         ipVersion,
		}
		dialer, err = doh.New(dialerSettings)
		if err != nil {
			return server.Settings{}, fmt.Errorf("creating DNS over HTTPS dialer: %w", err)
		}
	case settings.DNSUpstreamTypePlain:
		dialerSettings := plain.Settings{
			UpstreamResolvers: upstreamResolvers,
			IPVersion:         ipVersion,
		}
		dialer, err = plain.New(dialerSettings)
		if err != nil {
			return server.Settings{}, fmt.Errorf("creating plain DNS dialer: %w", err)
		}
	default:
		panic("unknown upstream type: " + userSettings.UpstreamType)
	}
	serverSettings.Dialer = dialer

	if *userSettings.Caching {
		lruCache, err := lru.New(lru.Settings{})
		if err != nil {
			return server.Settings{}, fmt.Errorf("creating LRU cache: %w", err)
		}
		cacheMiddleware, err := cachemiddleware.New(cachemiddleware.Settings{
			Cache: lruCache,
		})
		if err != nil {
			return server.Settings{}, fmt.Errorf("creating cache middleware: %w", err)
		}
		serverSettings.Middlewares = append(serverSettings.Middlewares, cacheMiddleware)
	}

	filterMiddleware, err := filtermiddleware.New(filtermiddleware.Settings{
		Filter: filter,
	})
	if err != nil {
		return server.Settings{}, fmt.Errorf("creating filter middleware: %w", err)
	}
	serverSettings.Middlewares = append(serverSettings.Middlewares, filterMiddleware)

	// Insert localdns middleware which is used for local resolver handling.
	localResolversAddrPorts := make([]netip.AddrPort, len(localResolvers))
	const defaultDNSPort = 53
	for i, addr := range localResolvers {
		localResolversAddrPorts[i] = netip.AddrPortFrom(addr, defaultDNSPort)
	}
	localDNSMiddleware, err := localdns.New(localdns.Settings{
		Resolvers: localResolversAddrPorts, // auto-detected at container start only
		Logger:    logger,
	})
	if err != nil {
		return server.Settings{}, fmt.Errorf("creating local DNS middleware: %w", err)
	}
	// Place after cache middleware, since we want to avoid caching for local
	// hostnames that may change regularly.
	serverSettings.Middlewares = append(serverSettings.Middlewares, localDNSMiddleware)

	return serverSettings, nil
}
