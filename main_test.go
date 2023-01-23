package main

import (
	"github.com/cert-manager/cert-manager/test/acme/dns"

	"os"
	"testing"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
)

func TestRunsSuite(t *testing.T) {
	fixture := dns.NewFixture(&hetznerDNSProviderSolver{},
		dns.SetResolvedZone(zone),
		dns.SetAllowAmbientCredentials(false),
		dns.SetManifestPath("testdata/hcloud-dns"),
		dns.SetStrict(true),
	)
	fixture.RunConformance(t)
}
