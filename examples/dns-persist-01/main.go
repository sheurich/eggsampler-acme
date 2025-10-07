//go:build ignore
// +build ignore

package main

// An example demonstrating the dns-persist-01 challenge method for obtaining certificates.
//
// The dns-persist-01 challenge is a persistent DNS-based validation method where you provision
// a TXT record once that can be reused for multiple certificate issuances. This differs from
// dns-01 which requires updating the TXT record for each certificate request.
//
// Usage:
//   go run main.go -domains example.com -dirurl https://localhost:14000/dir
//
// For wildcard certificates:
//   go run main.go -domains "*.example.com,example.com" -wildcard -dirurl https://localhost:14000/dir
//
// This example is designed to work with the Pebble ACME test server (https://github.com/letsencrypt/pebble).

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/eggsampler/acme/v3"
)

var (
	domains         string
	directoryUrl    string
	contactsList    string
	accountFile     string
	certFile        string
	keyFile         string
	wildcard        bool
	persistDays     int
	interactive     bool
	autoProvision   bool
	challTestSrvURL string
)

type acmeAccountFile struct {
	PrivateKey string `json:"privateKey"`
	Url        string `json:"url"`
}

func main() {
	flag.StringVar(&directoryUrl, "dirurl", "https://localhost:14000/dir",
		"acme directory url - defaults to pebble test server url")
	flag.StringVar(&contactsList, "contact", "",
		"a list of comma separated contact emails to use when creating a new account (optional, dont include 'mailto:' prefix)")
	flag.StringVar(&domains, "domains", "",
		"a comma separated list of domains to issue a certificate for (REQUIRED)")
	flag.StringVar(&accountFile, "accountfile", "account.json",
		"the file that the account json data will be saved to/loaded from (will create new file if not exists)")
	flag.StringVar(&certFile, "certfile", "cert.pem",
		"the file that the pem encoded certificate chain will be saved to")
	flag.StringVar(&keyFile, "keyfile", "privkey.pem",
		"the file that the pem encoded certificate private key will be saved to")
	flag.BoolVar(&wildcard, "wildcard", false,
		"request a wildcard certificate and include 'policy=wildcard' in the dns-persist-01 record")
	flag.IntVar(&persistDays, "persistdays", 90,
		"number of days the TXT record should remain valid (adds persistUntil parameter)")
	flag.BoolVar(&interactive, "interactive", true,
		"pause and wait for user confirmation before updating challenges (set to false for automation)")
	flag.BoolVar(&autoProvision, "autoprovision", false,
		"automatically provision DNS records via pebble-challtestsrv (for automated testing)")
	flag.StringVar(&challTestSrvURL, "challtestsrv", "http://localhost:8055",
		"URL of pebble-challtestsrv for auto-provisioning")
	flag.Parse()

	// check domains are provided
	if domains == "" {
		log.Fatal("No domains provided. Use -domains flag to specify one or more domains.")
	}

	// create a new acme client given a provided (or default) directory url
	log.Printf("Connecting to acme directory url: %s", directoryUrl)
	client, err := acme.NewClient(directoryUrl, acme.WithInsecureSkipVerify())
	if err != nil {
		log.Fatalf("Error connecting to acme directory: %v", err)
	}

	// attempt to load an existing account from file
	log.Printf("Loading account file %s", accountFile)
	account, err := loadAccount(client)
	if err != nil {
		log.Printf("Error loading existing account: %v", err)
		// if there was an error loading an account, just create a new one
		log.Printf("Creating new account")
		account, err = createAccount(client)
		if err != nil {
			log.Fatalf("Error creating new account: %v", err)
		}
	}
	log.Printf("Account url: %s", account.URL)

	// collect the comma separated domains into acme identifiers
	domainList := strings.Split(domains, ",")
	var ids []acme.Identifier
	for _, domain := range domainList {
		domain = strings.TrimSpace(domain)
		ids = append(ids, acme.Identifier{Type: "dns", Value: domain})
	}

	// create a new order with the acme service given the provided identifiers
	log.Printf("Creating new order for domains: %s", domainList)
	order, err := client.NewOrder(account, ids)
	if err != nil {
		log.Fatalf("Error creating new order: %v", err)
	}
	log.Printf("Order created: %s", order.URL)

	// Calculate persistUntil timestamp (current time + specified days)
	persistUntil := time.Now().Add(time.Duration(persistDays) * 24 * time.Hour).Unix()

	// loop through each of the provided authorization urls
	for i, authUrl := range order.Authorizations {
		// fetch the authorization data from the acme service given the provided authorization url
		log.Printf("Fetching authorization %d/%d: %s", i+1, len(order.Authorizations), authUrl)
		auth, err := client.FetchAuthorization(account, authUrl)
		if err != nil {
			log.Fatalf("Error fetching authorization url %q: %v", authUrl, err)
		}
		log.Printf("Fetched authorization for: %s", auth.Identifier.Value)

		// Check if this is a wildcard authorization
		isWildcard := auth.Wildcard
		if isWildcard {
			log.Printf("  This is a wildcard authorization")
		}

		// grab a dns-persist-01 challenge from the authorization if it exists
		chal, ok := auth.ChallengeMap[acme.ChallengeTypeDNSPersist01]
		if !ok {
			log.Fatalf("Unable to find dns-persist-01 challenge for auth %s. Available challenges: %v",
				auth.Identifier.Value, auth.ChallengeTypes)
		}

		// ===================================================================
		// IMPORTANT: dns-persist-01 Challenge Setup
		// ===================================================================
		//
		// The dns-persist-01 challenge requires you to provision a TXT record
		// at a specific domain with a specific value. This record can be reused
		// for multiple certificate requests, unlike dns-01 which requires updating
		// the record each time.
		//
		// Key differences from dns-01:
		// 1. Record name: "_validation-persist.{domain}" instead of "_acme-challenge.{domain}"
		// 2. Record value: Uses RFC 8659 CAA issue-value syntax with account and policy information
		// 3. Persistence: The record can remain in DNS and be reused for future requests
		// 4. Account binding: The record is tied to your ACME account
		// ===================================================================

		// The challenge object contains IssuerDomainNames - a list of valid issuer domain names
		// that can be used in the TXT record. You must choose one of these.
		if len(chal.IssuerDomainNames) == 0 {
			log.Fatalf("Challenge missing IssuerDomainNames field")
		}
		log.Printf("\nAvailable issuer domain names:")
		for j, idn := range chal.IssuerDomainNames {
			log.Printf("  %d. %s", j+1, idn)
		}

		// For this example, we'll use the first issuer domain name
		issuerDomainName := chal.IssuerDomainNames[0]
		log.Printf("Using issuer domain name: %s", issuerDomainName)

		// Determine the DNS record name where the TXT record should be placed
		// This is "_validation-persist." prefixed to your domain
		recordDomain := acme.GetDNSPersist01Domain(auth.Identifier.Value)
		log.Printf("\nDNS Record Configuration:")
		log.Printf("  Record Name: %s", recordDomain)

		// Determine the policy parameter based on whether this is a wildcard cert
		policy := ""
		if wildcard || isWildcard {
			policy = "wildcard"
			log.Printf("  Policy: wildcard (allows wildcard certificates)")
		}

		// Create the TXT record value using the helper function
		// This formats the record according to RFC 8659 CAA issue-value syntax:
		// "issuer-domain-name; accounturi=URI[; policy=wildcard][; persistUntil=timestamp]"
		recordValue := acme.EncodeDNSPersist01Record(
			issuerDomainName, // Must be from chal.IssuerDomainNames
			account.URL,      // Your ACME account URL
			policy,           // "wildcard" for wildcard certs, empty otherwise
			persistUntil,     // Unix timestamp when record should expire (optional)
		)

		log.Printf("  Record Value: %s", recordValue)
		log.Printf("  Record Type: TXT")
		if persistUntil > 0 {
			log.Printf("  Valid Until: %s (expires in %d days)",
				time.Unix(persistUntil, 0).Format("2006-01-02 15:04:05"), persistDays)
		}

		// ===================================================================
		// DNS Record Provisioning Instructions
		// ===================================================================
		//
		// You now need to create the DNS TXT record with the information above.
		// There are several ways to do this:
		//
		// 1. For testing with Pebble:
		//    Use the pebble-challtestsrv to automatically set the record:
		//      curl -X POST http://localhost:8055/set-txt \
		//        -H "Content-Type: application/json" \
		//        -d '{"host":"_validation-persist.example.com.","value":"ca.example.com; accounturi=https://..."}'
		//
		// 2. For production with a DNS provider:
		//    Use your DNS provider's API or control panel to create:
		//      Name:  _validation-persist.example.com
		//      Type:  TXT
		//      Value: ca.example.com; accounturi=https://...; policy=wildcard; persistUntil=...
		//
		// 3. Using DNS management tools:
		//    - AWS Route53: aws route53 change-resource-record-sets ...
		//    - Cloudflare API: curl -X POST https://api.cloudflare.com/client/v4/zones/...
		//    - Other providers: check your DNS provider's API documentation
		//
		// The record can remain in DNS and be reused for future certificate requests
		// as long as:
		// - You use the same ACME account
		// - The persistUntil timestamp hasn't expired (if specified)
		// - The policy matches (wildcard vs non-wildcard)
		// ===================================================================

		if autoProvision {
			// Automatically provision DNS record via pebble-challtestsrv
			log.Printf("Auto-provisioning DNS record via challtestsrv...")
			if err := provisionDNSRecord(recordDomain, recordValue, challTestSrvURL); err != nil {
				log.Fatalf("Failed to auto-provision DNS record: %v", err)
			}
			log.Printf("✓ DNS record provisioned successfully")
		} else if interactive {
			log.Printf("\n" + strings.Repeat("=", 70))
			log.Printf("ACTION REQUIRED: Provision the DNS TXT record shown above")
			log.Printf(strings.Repeat("=", 70))
			log.Printf("\nFor Pebble testing, you can use:")
			log.Printf("  curl -X POST http://localhost:8055/set-txt \\")
			log.Printf("    -H 'Content-Type: application/json' \\")
			log.Printf("    -d '{\"host\":\"%s.\",\"value\":\"%s\"}'", recordDomain, recordValue)
			log.Printf("\nFor production, create a TXT record at your DNS provider:")
			log.Printf("  Name:  %s", recordDomain)
			log.Printf("  Type:  TXT")
			log.Printf("  Value: %s", recordValue)
			log.Printf("\nOnce the DNS record is provisioned, press ENTER to continue...")
			log.Printf(strings.Repeat("=", 70))

			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
		}

		// update the acme server that the challenge is ready to be validated
		log.Printf("\nNotifying ACME server to validate challenge for %s", auth.Identifier.Value)
		chal, err = client.UpdateChallenge(account, chal)
		if err != nil {
			log.Fatalf("Error updating authorization %s challenge: %v", auth.Identifier.Value, err)
		}

		if chal.Status == "valid" {
			log.Printf("Challenge validated successfully!")
		} else {
			log.Printf("Challenge status: %s", chal.Status)
			if chal.Error.Type != "" {
				log.Fatalf("Challenge validation failed: %s - %s", chal.Error.Type, chal.Error.Detail)
			}
		}
	}

	log.Printf("\nAll challenges completed successfully!")

	// create a csr for the new certificate
	log.Printf("Generating certificate private key")
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Error generating certificate key: %v", err)
	}

	b := key2pem(certKey)

	// write the key to the key file as a pem encoded key
	log.Printf("Writing key file: %s", keyFile)
	if err := ioutil.WriteFile(keyFile, b, 0600); err != nil {
		log.Fatalf("Error writing key file %q: %v", keyFile, err)
	}

	// create the new csr template
	log.Printf("Creating certificate signing request")
	tpl := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          certKey.Public(),
		Subject:            pkix.Name{CommonName: domainList[0]},
		DNSNames:           domainList,
	}
	csrDer, err := x509.CreateCertificateRequest(rand.Reader, tpl, certKey)
	if err != nil {
		log.Fatalf("Error creating certificate request: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		log.Fatalf("Error parsing certificate request: %v", err)
	}

	// finalize the order with the acme server given a csr
	log.Printf("Finalizing order: %s", order.URL)
	order, err = client.FinalizeOrder(account, order, csr)
	if err != nil {
		log.Fatalf("Error finalizing order: %v", err)
	}

	// fetch the certificate chain from the finalized order provided by the acme server
	log.Printf("Fetching certificate: %s", order.Certificate)
	certs, err := client.FetchCertificates(account, order.Certificate)
	if err != nil {
		log.Fatalf("Error fetching order certificates: %v", err)
	}

	// write the pem encoded certificate chain to file
	log.Printf("Saving certificate to: %s", certFile)
	var pemData []string
	for _, c := range certs {
		pemData = append(pemData, strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		}))))
	}
	if err := ioutil.WriteFile(certFile, []byte(strings.Join(pemData, "\n")), 0600); err != nil {
		log.Fatalf("Error writing certificate file %q: %v", certFile, err)
	}

	log.Printf("\n" + strings.Repeat("=", 70))
	log.Printf("SUCCESS! Certificate obtained and saved")
	log.Printf(strings.Repeat("=", 70))
	log.Printf("Certificate: %s", certFile)
	log.Printf("Private Key: %s", keyFile)
	log.Printf("Domains: %s", domainList)
	log.Printf("\nThe DNS TXT record can remain in place and be reused for:")
	log.Printf("  - Certificate renewals for the same domain(s)")
	log.Printf("  - Multiple certificates using the same ACME account")
	log.Printf("  - Valid until: %s", time.Unix(persistUntil, 0).Format("2006-01-02 15:04:05"))
	log.Printf(strings.Repeat("=", 70))
}

func loadAccount(client acme.Client) (acme.Account, error) {
	raw, err := ioutil.ReadFile(accountFile)
	if err != nil {
		return acme.Account{}, fmt.Errorf("error reading account file %q: %v", accountFile, err)
	}
	var aaf acmeAccountFile
	if err := json.Unmarshal(raw, &aaf); err != nil {
		return acme.Account{}, fmt.Errorf("error parsing account file %q: %v", accountFile, err)
	}
	account, err := client.UpdateAccount(acme.Account{PrivateKey: pem2key([]byte(aaf.PrivateKey)), URL: aaf.Url}, getContacts()...)
	if err != nil {
		return acme.Account{}, fmt.Errorf("error updating existing account: %v", err)
	}
	return account, nil
}

func createAccount(client acme.Client) (acme.Account, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return acme.Account{}, fmt.Errorf("error creating private key: %v", err)
	}
	account, err := client.NewAccount(privKey, false, true, getContacts()...)
	if err != nil {
		return acme.Account{}, fmt.Errorf("error creating new account: %v", err)
	}
	raw, err := json.Marshal(acmeAccountFile{PrivateKey: string(key2pem(privKey)), Url: account.URL})
	if err != nil {
		return acme.Account{}, fmt.Errorf("error parsing new account: %v", err)
	}
	if err := ioutil.WriteFile(accountFile, raw, 0600); err != nil {
		return acme.Account{}, fmt.Errorf("error creating account file: %v", err)
	}
	return account, nil
}

func getContacts() []string {
	var contacts []string
	if contactsList != "" {
		contacts = strings.Split(contactsList, ",")
		for i := 0; i < len(contacts); i++ {
			contacts[i] = "mailto:" + contacts[i]
		}
	}
	return contacts
}

func key2pem(certKey *ecdsa.PrivateKey) []byte {
	certKeyEnc, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		log.Fatalf("Error encoding key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: certKeyEnc,
	})
}

func pem2key(data []byte) *ecdsa.PrivateKey {
	b, _ := pem.Decode(data)
	key, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		log.Fatalf("Error decoding key: %v", err)
	}
	return key
}

func provisionDNSRecord(host, value, challTestSrvURL string) error {
	// Add trailing dot if not present
	if !strings.HasSuffix(host, ".") {
		host = host + "."
	}

	reqBody := map[string]string{
		"host":  host,
		"value": value,
	}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("error marshaling JSON: %v", err)
	}

	resp, err := http.Post(challTestSrvURL+"/set-txt", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("error posting to challtestsrv: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("challtestsrv returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
