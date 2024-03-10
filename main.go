package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"

	logf "github.com/cert-manager/cert-manager/pkg/logs"

	corev1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

const (
	serviceAccountNamespaceFile = "/run/secrets/kubernetes.io/serviceaccount/namespace"
)

var (
	GroupName = os.Getenv("GROUP_NAME")
	log = logf.Log
)


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

type hetznerDNSProviderConfigOpts struct {
	ApiKeySecretRef struct {
		Name string `json:"name"`
		Key string `json:"key"`
	} `json:"apiKeySecretRef,omitempty"`

	APIKey string `json:"apiKey,omitempty"`
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
	log.Info("Presenting DNS challenge", "name", ch.DNSName, "namespace", ch.ResourceNamespace)

	name, zone := c.getDomainAndEntry(ch)

	// Get Zones (GET https://dns.hetzner.com/api/v1/zones)
	// Create client
	client := &http.Client{}

	// Create request
	req, err := http.NewRequest("GET", "https://dns.hetzner.com/api/v1/zones?name="+zone, nil)
	if err != nil {
		return err
	}
	// Headers
	req.Header.Add("Auth-API-Token", cfg.APIKey)

	// Fetch Request
	resp, err := client.Do(req)
	if err != nil {
		log.Error(err, "Unable to get DNS Zones")
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("did not get expected HTTP 200 but %s", resp.Status)
	}

	// Read Response Body
	respBody := Zones{}
	err = json.NewDecoder(resp.Body).Decode(&respBody)
	if err != nil {
		return fmt.Errorf("error decoding JSON: %v", err)
	}

	if len(respBody.Zones) != 1 {
		return fmt.Errorf("domain did not yield exactly 1 zone result but %d: %s", len(respBody.Zones), respBody.Zones)
	}

	// Display Results
	log.V(4).Info("response",
		"status", resp.Status,
		"headers", resp.Header,
		"body", respBody.Zones[0].ZoneID)

	// Create DNS
	entry, err := json.Marshal(Entry{"", name, 300, "TXT", ch.Key, respBody.Zones[0].ZoneID})
	if err != nil {
		return err
	}
	body := bytes.NewBuffer(entry)

	// Create request
	req, err = http.NewRequest("POST", "https://dns.hetzner.com/api/v1/records", body)
	if err != nil {
		return err
	}
	// Headers
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Auth-API-Token", cfg.APIKey)

	// Fetch Request
	resp, err = client.Do(req)
	if err != nil {
		log.Error(err, "Unable to update DNS record")
		return err
	}

	// Read Response Body
	respBody2, _ := io.ReadAll(resp.Body)

	// Display Results
	log.V(4).Info("response",
		"status", resp.Status,
		"headers", resp.Header,
		"body", string(respBody2))

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
	log.Info("Cleaning up challenge", "name", ch.DNSName, "namespace", ch.ResourceNamespace)

	name, zone := c.getDomainAndEntry(ch)

	// Get Zones (GET https://dns.hetzner.com/api/v1/zones)
	// Create client
	client := &http.Client{}

	// Create request
	zReq, err := http.NewRequest("GET", "https://dns.hetzner.com/api/v1/zones?name="+zone, nil)
	if err != nil {
		return err
	}
	// Headers
	zReq.Header.Add("Auth-API-Token", cfg.APIKey)

	// Fetch Request
	zResp, err := client.Do(zReq)
	if err != nil {
		log.Error(err, "Failed getting DNS zone")
		return err
	}
	if zResp.StatusCode != 200 {
		return fmt.Errorf("did not get expected HTTP 200 but %s", zResp.Status)
	}
	// Read Response Body
	zRespBody := Zones{}
	err = json.NewDecoder(zResp.Body).Decode(&zRespBody)
	if err != nil {
		return fmt.Errorf("error decoding JSON: %v", err)
	}

	// Display Results
	log.V(4).Info("response",
		"status", zResp.Status,
		"headers", zResp.Header,
		"zoneID", zRespBody.Zones[0].ZoneID,
		"name", name)

	// Create request
	eReq, err := http.NewRequest("GET", "https://dns.hetzner.com/api/v1/records?zone_id="+zRespBody.Zones[0].ZoneID, nil)
	if err != nil {
		return err
	}
	// Headers
	eReq.Header.Add("Auth-API-Token", cfg.APIKey)

	// Fetch Request
	eResp, err := client.Do(eReq)
	if err != nil {
		log.Error(err, "Cannot fetch DNS records")
		return err
	}

	// Read Response Body
	eRespBody := Entries{}
	err = json.NewDecoder(eResp.Body).Decode(&eRespBody)
	if err != nil {
		return fmt.Errorf("error decoding JSON: %v", err)
	}

	// Display Results
	log.V(4).Info("response",
		"status", eResp.Status,
		"headers", eResp.Header,
		"body", eRespBody)

	for _, e := range eRespBody.Records {
		if e.Type == "TXT" && e.Name == name && e.Value == ch.Key {
			log.V(4).Info("Found Domain", "record", fmt.Sprintf("%+v", e))
			// Delete Record (DELETE https://dns.hetzner.com/api/v1/records/1)
			// Create request
			req, err := http.NewRequest("DELETE", "https://dns.hetzner.com/api/v1/records/"+e.ID, nil)
			if err != nil {
				log.Error(err, "Unable to create new delete request")
				continue
			}

			// Headers
			req.Header.Add("Auth-API-Token", cfg.APIKey)

			// Fetch Request
			resp, err := client.Do(req)

			if err != nil {
				log.Error(err, "Cannot delete DNS record", "name", e.Name, "value", e.Value)
				continue
			}

			// Read Response Body
			respBody, _ := io.ReadAll(resp.Body)

			// Display Results
			log.V(4).Info("response",
				"status", resp.Status,
				"headers", resp.Header,
				"body", string(respBody))
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
func loadConfig(cfgJSON *extapi.JSON) (c hetznerDNSProviderConfig, err error) {
	ref := hetznerDNSProviderConfigOpts{}

	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return c, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &ref); err != nil {
		return c, fmt.Errorf("error decoding solver config: %+v", err)
	}
	if ref.APIKey != "" {
		log.Info("Please migrate to a secret based solver configuration see https://github.com/mecodia/cert-manager-webhook-hetzner#issuer for more details")
		c.APIKey = ref.APIKey
		return c, nil
	}
	key, err := ref.getApiKeyFromSecret()
	if err != nil {
		return c, err
	}
	c.APIKey = key
	return c, nil
}

// get API Key from Secret
func (r *hetznerDNSProviderConfigOpts) getApiKeyFromSecret() (string, error) {
	ns, err := GetNamespace()
	if err != nil {
		return "", err
	}

	secret, err := GetSecret(r.ApiKeySecretRef.Name, ns)
	if err != nil {
		return "", err
	}

	key := string(secret.Data[r.ApiKeySecretRef.Key])
	return key, nil
}

func GetNamespace() (string, error) {
	// get namespace from container environment
	data, err := os.ReadFile(serviceAccountNamespaceFile)
	if err != nil {
		return "", err
	}
	log.V(4).Info("Running in namespace", "namespace", string(data))
	return string(data), nil
}

func GetSecret(name string, namespace string) (*corev1.Secret, error) {
	c, err := NewKubernetesConfig()
	if err != nil {
		return nil, err
	}
	// get secret from kubernetes
	secret, err := c.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	log.V(4).Info("Gathered Secret from apiserver", "name", name)
	return secret, nil
}

func NewKubernetesConfig() (*kubernetes.Clientset, error) {
	// creates the in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return clientset, nil
}

func (c *hetznerDNSProviderSolver) getDomainAndEntry(ch *v1alpha1.ChallengeRequest) (string, string) {
	// Both ch.ResolvedZone and ch.ResolvedFQDN end with a dot: '.'
	entry := strings.TrimSuffix(ch.ResolvedFQDN, ch.ResolvedZone)
	entry = strings.TrimSuffix(entry, ".")
	domain := strings.TrimSuffix(ch.ResolvedZone, ".")
	return entry, domain
}
