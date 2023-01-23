package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"io"
	"net/http"
	"os"
	"strings"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&hetznerDNSProviderSolver{},
	)
}

// hetznerDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type hetznerDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	//client kubernetes.Clientset
}

// hetznerDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type hetznerDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	APIKey string `json:"apiKey"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *hetznerDNSProviderSolver) Name() string {
	return "hetzner"
}

type Zones struct {
	Zones []Zone `json:"zones"`
}

func (zones Zones) String() string {
	var zoneStrings = []string{}
	for _, zone := range zones.Zones {
		zoneStrings = append(zoneStrings, zone.String())
	}
	var joined = strings.Join(zoneStrings, ", ")
	return joined
}

type Zone struct {
	ZoneID string `json:"id"`
	Name   string `json:"name"`
}

func (z Zone) String() string {
	return fmt.Sprintf("Zone '%s' (%s)", z.Name, z.ZoneID)
}

type Entries struct {
	Records []Entry `json:"records"`
}

type Entry struct {
	ID     string `json:"id,omitempty"`
	Name   string `json:"name"`
	TTL    int    `json:"ttl"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	ZoneID string `json:"zone_id"`
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *hetznerDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	name, zone := c.getDomainAndEntry(ch)

	// Get Zones (GET https://dns.hetzner.com/api/v1/zones)
	// Create client
	client := &http.Client{}

	// Create request
	req, err := http.NewRequest("GET", "https://dns.hetzner.com/api/v1/zones?search_name="+zone, nil)
	// Headers
	req.Header.Add("Auth-API-Token", cfg.APIKey)

	// Fetch Request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Failure : ", err)
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("did not get expected HTTP 200 but %s", resp.Status)
	}

	// Read Response Body
	respBody := Zones{}
	json.NewDecoder(resp.Body).Decode(&respBody)

	if len(respBody.Zones) != 1 {
		return fmt.Errorf("domain did not yield exactly 1 zone result but %d: %s", len(respBody.Zones), respBody.Zones)
	}

	// Display Results
	fmt.Println("response Status : ", resp.Status)
	fmt.Println("response Headers : ", resp.Header)
	fmt.Println("response Body : ", respBody.Zones[0].ZoneID)

	// Create DNS
	entry, err := json.Marshal(Entry{"", name, 300, "TXT", ch.Key, respBody.Zones[0].ZoneID})
	body := bytes.NewBuffer(entry)

	// Create request
	req, err = http.NewRequest("POST", "https://dns.hetzner.com/api/v1/records", body)
	// Headers
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Auth-API-Token", cfg.APIKey)

	// Fetch Request
	resp, err = client.Do(req)
	if err != nil {
		fmt.Println("Failure : ", err)
	}

	// Read Response Body
	respBody2, _ := io.ReadAll(resp.Body)

	// Display Results
	fmt.Println("response Status : ", resp.Status)
	fmt.Println("response Headers : ", resp.Header)
	fmt.Println("response Body : ", string(respBody2))

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *hetznerDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	// TODO: do something more useful with the decoded configuration
	fmt.Printf("Decoded configuration %v", cfg)

	name, zone := c.getDomainAndEntry(ch)

	// Get Zones (GET https://dns.hetzner.com/api/v1/zones)
	// Create client
	client := &http.Client{}

	// Create request
	zReq, err := http.NewRequest("GET", "https://dns.hetzner.com/api/v1/zones?search_name="+zone, nil)
	// Headers
	zReq.Header.Add("Auth-API-Token", cfg.APIKey)

	// Fetch Request
	zResp, err := client.Do(zReq)
	if err != nil {
		fmt.Println("Failure : ", err)
		return err
	}
	if zResp.StatusCode != 200 {
		return fmt.Errorf("did not get expected HTTP 200 but %s", zResp.Status)
	}
	// Read Response Body
	zRespBody := Zones{}
	json.NewDecoder(zResp.Body).Decode(&zRespBody)

	// Display Results
	fmt.Println("response Status : ", zResp.Status)
	fmt.Println("response Headers : ", zResp.Header)
	fmt.Println("response Body : ", zRespBody.Zones[0].ZoneID)
	fmt.Println("response Body : ", name)

	// Create request
	eReq, err := http.NewRequest("GET", "https://dns.hetzner.com/api/v1/records?zone_id="+zRespBody.Zones[0].ZoneID, nil)
	// Headers
	eReq.Header.Add("Auth-API-Token", cfg.APIKey)

	// Fetch Request
	eResp, err := client.Do(eReq)
	if err != nil {
		fmt.Println("Failure : ", err)
	}

	// Read Response Body
	eRespBody := Entries{}
	json.NewDecoder(eResp.Body).Decode(&eRespBody)

	// Display Results
	fmt.Println("response Status : ", eResp.Status)
	fmt.Println("response Headers : ", eResp.Header)
	fmt.Println("response Body : ", eRespBody)

	for _, e := range eRespBody.Records {
		if e.Type == "TXT" && e.Name == name && e.Value == ch.Key {
			fmt.Println("Found DOMAIN: ", e)
			// Delete Record (DELETE https://dns.hetzner.com/api/v1/records/1)
			// Create request
			req, err := http.NewRequest("DELETE", "https://dns.hetzner.com/api/v1/records/"+e.ID, nil)

			// Headers
			req.Header.Add("Auth-API-Token", cfg.APIKey)

			// Fetch Request
			resp, err := client.Do(req)

			if err != nil {
				fmt.Println("Failure : ", err)
			}

			// Read Response Body
			respBody, _ := io.ReadAll(resp.Body)

			// Display Results
			fmt.Println("response Status : ", resp.Status)
			fmt.Println("response Headers : ", resp.Header)
			fmt.Println("response Body : ", string(respBody))
		}
	}
	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *hetznerDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (hetznerDNSProviderConfig, error) {
	cfg := hetznerDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func (c *hetznerDNSProviderSolver) getDomainAndEntry(ch *v1alpha1.ChallengeRequest) (string, string) {
	// Both ch.ResolvedZone and ch.ResolvedFQDN end with a dot: '.'
	entry := strings.TrimSuffix(ch.ResolvedFQDN, ch.ResolvedZone)
	entry = strings.TrimSuffix(entry, ".")
	domain := strings.TrimSuffix(ch.ResolvedZone, ".")
	return entry, domain
}
