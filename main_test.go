package main

import (
	"os"
	"testing"

	"github.com/cert-manager/cert-manager/test/acme/dns"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
)

func TestRunsSuite(t *testing.T) {
	solver := hetznerDNSProviderSolver{}
	fixture := dns.NewFixture(&solver,
		dns.SetResolvedZone(zone),
		dns.SetAllowAmbientCredentials(false),
		dns.SetManifestPath("testdata/hcloud-dns"),
		dns.SetStrict(true),
	)
	fixture.RunConformance(t)
}
