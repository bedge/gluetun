package dns

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/qdm12/dns/v2/pkg/middlewares/filter/update"
	"github.com/qdm12/dns/v2/pkg/nameserver"
	"github.com/qdm12/dns/v2/pkg/server"
	"github.com/qdm12/gluetun/internal/configuration/settings"
)

func (l *Loop) setupServer(ctx context.Context, settings settings.DNS) (runError <-chan error, err error) {
	var updateSettings update.Settings
	updateSettings.SetRebindingProtectionExempt(settings.Blacklist.RebindingProtectionExemptHostnames)
	err = l.filter.Update(updateSettings)
	if err != nil {
		return nil, fmt.Errorf("updating filter for rebinding protection: %w", err)
	}

	serverSettings, err := buildServerSettings(settings, l.filter, l.localResolvers, l.localSubnets, l.logger)
	if err != nil {
		return nil, fmt.Errorf("building server settings: %w", err)
	}

	// Determine host resolvers to use for DNS_HOST_RESOLVER_DOMAINS
	hostResolvers := l.localResolvers
	if len(hostResolvers) == 0 {
		raw := os.Getenv("DNS_HOST_RESOLVER_SERVERS")
		if raw != "" {
			for _, s := range strings.Split(raw, ",") {
				s = strings.TrimSpace(s)
				if s == "" {
					continue
				}
				addr, perr := netip.ParseAddr(s)
				if perr != nil {
					l.logger.Warn("invalid DNS_HOST_RESOLVER_SERVERS entry: " + s)
					continue
				}
				hostResolvers = append(hostResolvers, addr)
			}
		}
	}

	// Insert host resolver middleware at the front so matched queries are handled
	// by host resolvers before other middlewares/upstreams. The middleware itself
	// handles the case of no host resolvers by returning SERVFAIL per strict mode.
	hostMiddleware := hostResolverMiddleware(hostResolvers, l.logger, l)
	serverSettings.Middlewares = append([]server.Middleware{hostMiddleware}, serverSettings.Middlewares...)

	server, err := server.New(serverSettings)
	if err != nil {
		return nil, fmt.Errorf("creating server: %w", err)
	}

	runError, err = server.Start(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting server: %w", err)
	}
	l.server = server

	// use internal DNS server
	nameserver.UseDNSInternally(nameserver.SettingsInternalDNS{})
	err = nameserver.UseDNSSystemWide(nameserver.SettingsSystemDNS{
		ResolvPath: l.resolvConf,
	})
	if err != nil {
		l.logger.Error(err.Error())
	}

	return runError, nil
}

func (l *Loop) usePlainServers(addrPorts []netip.AddrPort) (err error) {
	nameserver.UseDNSInternally(nameserver.SettingsInternalDNS{
		AddrPort: addrPorts[0],
	})
	addresses := make([]netip.Addr, len(addrPorts))
	const defaultDNSPort = 53
	for i, addrPort := range addrPorts {
		if addrPort.Port() != defaultDNSPort {
			return fmt.Errorf("invalid DNS port: %d, must be %d", addrPort.Port(), defaultDNSPort)
		}
		addresses[i] = addrPort.Addr()
	}
	err = nameserver.UseDNSSystemWide(nameserver.SettingsSystemDNS{
		IPs:        addresses,
		ResolvPath: l.resolvConf,
	})
	if err != nil {
		return fmt.Errorf("using DNS system wide: %w", err)
	}
	return nil
}
