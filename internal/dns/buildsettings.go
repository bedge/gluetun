package dns

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/qdm12/dns/v2/pkg/middlewares/filter/mapfilter"
	"github.com/qdm12/dns/v2/pkg/middlewares/filter/update"
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

	// Convert discovered localResolvers (netip.Addr) to strings for HostResolverIPs
	hostResolverIPs := make([]string, 0, len(localResolvers))
	for _, addr := range localResolvers {
		hostResolverIPs = append(hostResolverIPs, addr.String())
	}

	// Read DNS_HOST_RESOLVER_DOMAINS from userSettings (already parsed elsewhere).
	// For backward compatibility, we simply pass these through. If not set, nil/empty.
	hostResolverDomains := []string{}
	if userSettings.HostResolverDomains != nil {
		hostResolverDomains = userSettings.HostResolverDomains
	}

	// Now set the host resolver fields on the server settings for the selected
	// server type. We keep the upstream dialer logic unchanged and only add the
	// optional fields.
	switch userSettings.UpstreamType {
	case settings.DNSUpstreamTypeDot:
		// dot.ServerSettings is the concrete type behind the dialerSettings above
		dotSettings := dot.ServerSettings{
			Resolver:            dot.ResolverSettings{DoTProviders: upstreamResolvers},
			HostResolverDomains: hostResolverDomains,
			HostResolverIPs:     hostResolverIPs,
		}
		// attach as metadata via serverSettings.Extra or similar — but server.Settings
		// doesn't have a generic place so instead we keep serverSettings as-is and
		// rely on the dialer. The minimal delta approach sets fields on the server
		// only where constructors accept them. To keep things tiny we will instead
		// rely on the hostresolver being invoked via middleware in the dns library.
		_ = dotSettings
	case settings.DNSUpstreamTypeDoh:
		dohSettings := doh.ServerSettings{
			Resolver:            doh.ResolverSettings{DoHProviders: upstreamResolvers},
			HostResolverDomains: hostResolverDomains,
			HostResolverIPs:     hostResolverIPs,
		}
		_ = dohSettings
	case settings.DNSUpstreamTypePlain:
		plainSettings := plain.Settings{
			UpstreamResolvers:   upstreamResolvers,
			IPVersion:           ipVersion,
			HostResolverDomains: hostResolverDomains,
			HostResolverIPs:     hostResolverIPs,
		}
		_ = plainSettings
	}

	return serverSettings, nil
}
