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
		//dns.SetDNSServer("127.0.0.1:59351"),
		dns.SetStrict(true),
		dns.SetUseAuthoritative(false),
	)
	//fixture.RunConformance(t)
	fixture.RunBasic(t)
	fixture.RunExtended(t)
}
