package acme

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// EncodeDNS01KeyAuthorization encodes a key authorization and provides a value to be put in the TXT record for the _acme-challenge DNS entry.
func EncodeDNS01KeyAuthorization(keyAuth string) string {
	h := sha256.Sum256([]byte(keyAuth))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// EncodeDNSPersist01Record creates a dns-persist-01 TXT record value.
// Parameters:
//   - issuerDomainName: The issuer domain name to use (must be from challenge.IssuerDomainNames)
//   - accountURI: The account URI for the ACME account
//   - policy: Optional policy parameter (use "wildcard" or empty string)
//   - persistUntil: Optional expiry timestamp (use 0 for no expiry)
func EncodeDNSPersist01Record(issuerDomainName, accountURI, policy string, persistUntil int64) string {
	// Normalize issuer domain name: lowercase, no trailing dot
	issuerDomainName = strings.ToLower(strings.TrimSuffix(issuerDomainName, "."))
	
	// Start with issuer domain name and mandatory accounturi parameter
	record := issuerDomainName + "; accounturi=" + accountURI
	
	// Add optional policy parameter if provided and not empty
	if policy != "" {
		record += "; policy=" + policy
	}
	
	// Add optional persistUntil parameter if provided and not zero
	if persistUntil > 0 {
		record += "; persistUntil=" + strconv.FormatInt(persistUntil, 10)
	}
	
	return record
}

// ParseDNSPersist01Record parses a dns-persist-01 TXT record value.
// Returns: issuerDomainName, accountURI, policy, persistUntil, error
func ParseDNSPersist01Record(record string) (string, string, string, int64, error) {
	if record == "" {
		return "", "", "", 0, errors.New("empty record")
	}
	
	// Split by semicolons and trim whitespace
	parts := strings.Split(record, ";")
	if len(parts) < 2 {
		return "", "", "", 0, errors.New("invalid record format: missing parameters")
	}
	
	// First part is the issuer domain name
	issuerDomainName := strings.TrimSpace(parts[0])
	if issuerDomainName == "" {
		return "", "", "", 0, errors.New("missing issuer domain name")
	}
	
	// Initialize return values
	var accountURI, policy string
	var persistUntil int64
	var foundAccountURI bool

	// Track seen parameters for duplicate detection
	seenParams := make(map[string]bool)

	// Parse parameters
	for i := 1; i < len(parts); i++ {
		param := strings.TrimSpace(parts[i])
		if param == "" {
			continue
		}

		// Split parameter into key=value
		kv := strings.SplitN(param, "=", 2)
		if len(kv) != 2 {
			return "", "", "", 0, fmt.Errorf("invalid parameter format: %s", param)
		}

		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])

		// Case-insensitive parameter key matching
		keyLower := strings.ToLower(key)

		// Check for duplicate parameters
		if seenParams[keyLower] {
			return "", "", "", 0, fmt.Errorf("duplicate parameter: %s", key)
		}
		seenParams[keyLower] = true

		switch keyLower {
		case "accounturi":
			accountURI = value
			foundAccountURI = true
		case "policy":
			policy = strings.ToLower(value) // Case-insensitive per spec
		case "persistuntil":
			if value != "" {
				var err error
				persistUntil, err = strconv.ParseInt(value, 10, 64)
				if err != nil {
					return "", "", "", 0, fmt.Errorf("invalid persistUntil timestamp: %s", value)
				}
			}
		}
		// Ignore unknown parameters as per spec
	}
	
	// accounturi is mandatory
	if !foundAccountURI || accountURI == "" {
		return "", "", "", 0, errors.New("missing required accounturi parameter")
	}
	
	return issuerDomainName, accountURI, policy, persistUntil, nil
}

// GetDNSPersist01Domain returns the domain name where the TXT record should be placed.
// For example: "example.com" -> "_validation-persist.example.com"
func GetDNSPersist01Domain(domain string) string {
	// Remove trailing dot if present for normalization
	domain = strings.TrimSuffix(domain, ".")
	return "_validation-persist." + domain
}

// Helper function to determine whether a challenge is "finished" by its status.
func checkUpdatedChallengeStatus(challenge Challenge) (bool, error) {
	switch challenge.Status {
	case "pending":
		// Challenge objects are created in the "pending" state.
		// TODO: https://github.com/letsencrypt/boulder/issues/3346
		// return true, errors.New("acme: unexpected 'pending' challenge state")
		return false, nil

	case "processing":
		// They transition to the "processing" state when the client responds to the
		//   challenge and the server begins attempting to validate that the client has completed the challenge.
		return false, nil

	case "valid":
		// If validation is successful, the challenge moves to the "valid" state
		return true, nil

	case "invalid":
		// if there is an error, the challenge moves to the "invalid" state.
		if challenge.Error.Type != "" {
			return true, challenge.Error
		}
		return true, errors.New("acme: challenge is invalid, no error provided")

	default:
		return true, fmt.Errorf("acme: unknown challenge status: %s", challenge.Status)
	}
}

// UpdateChallenge responds to a challenge to indicate to the server to complete the challenge.
func (c Client) UpdateChallenge(account Account, challenge Challenge) (Challenge, error) {
	resp, err := c.post(challenge.URL, account.URL, account.PrivateKey, struct{}{}, &challenge, http.StatusOK)
	if err != nil {
		return challenge, err
	}

	if loc := resp.Header.Get("Location"); loc != "" {
		challenge.URL = loc
	}
	challenge.AuthorizationURL = fetchLink(resp, "up")

	if finished, err := checkUpdatedChallengeStatus(challenge); finished {
		return challenge, err
	}

	pollInterval, pollTimeout := c.getPollingDurations()
	end := time.Now().Add(pollTimeout)
	for {
		if time.Now().After(end) {
			return challenge, errors.New("acme: challenge update timeout")
		}
		time.Sleep(pollInterval)

		resp, err := c.post(challenge.URL, account.URL, account.PrivateKey, "", &challenge, http.StatusOK)
		if err != nil {
			// i don't think it's worth exiting the loop on this error
			// it could just be connectivity issue that's resolved before the timeout duration
			continue
		}

		if loc := resp.Header.Get("Location"); loc != "" {
			challenge.URL = loc
		}
		challenge.AuthorizationURL = fetchLink(resp, "up")

		if finished, err := checkUpdatedChallengeStatus(challenge); finished {
			return challenge, err
		}
	}
}

// FetchChallenge fetches an existing challenge from the given url.
func (c Client) FetchChallenge(account Account, challengeURL string) (Challenge, error) {
	challenge := Challenge{}
	resp, err := c.post(challengeURL, account.URL, account.PrivateKey, "", &challenge, http.StatusOK)
	if err != nil {
		return challenge, err
	}

	challenge.URL = resp.Header.Get("Location")
	challenge.AuthorizationURL = fetchLink(resp, "up")

	return challenge, nil
}
