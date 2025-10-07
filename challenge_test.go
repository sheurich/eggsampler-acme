package acme

import (
	"strings"
	"testing"
)

func TestEncodeDns01KeyAuthorization(t *testing.T) {
	tests := []struct {
		KeyAuth string
		Encoded string
	}{
		{
			"YLhavngUj1w8B79rUzxB5imUvO8DPyLDHgce89NuMfw.4fqGG7OQog-EV3ovi0b_amhdzVNWxxswDUN9ypYhWpE",
			"vKcNRAl8IQoDxFFQbEmXHgZ8O1rYk3JTFooIfYJDEEU",
		},
	}

	for _, currentTest := range tests {
		e := EncodeDNS01KeyAuthorization(currentTest.KeyAuth)
		if e != currentTest.Encoded {
			t.Fatalf("expected: %s, got: %s", currentTest.Encoded, e)
		}
	}
}

func TestEncodeDNSPersist01Record(t *testing.T) {
	tests := []struct {
		name             string
		issuerDomainName string
		accountURI       string
		policy           string
		persistUntil     int64
		expected         string
	}{
		{
			name:             "basic record with only required fields",
			issuerDomainName: "ca.example.com",
			accountURI:       "https://ca.example.com/acct/123",
			policy:           "",
			persistUntil:     0,
			expected:         "ca.example.com; accounturi=https://ca.example.com/acct/123",
		},
		{
			name:             "record with wildcard policy",
			issuerDomainName: "ca.example.com",
			accountURI:       "https://ca.example.com/acct/123",
			policy:           "wildcard",
			persistUntil:     0,
			expected:         "ca.example.com; accounturi=https://ca.example.com/acct/123; policy=wildcard",
		},
		{
			name:             "record with persistUntil timestamp",
			issuerDomainName: "ca.example.com",
			accountURI:       "https://ca.example.com/acct/123",
			policy:           "",
			persistUntil:     1721952000,
			expected:         "ca.example.com; accounturi=https://ca.example.com/acct/123; persistUntil=1721952000",
		},
		{
			name:             "record with all parameters",
			issuerDomainName: "ca.example.com",
			accountURI:       "https://ca.example.com/acct/123",
			policy:           "wildcard",
			persistUntil:     1721952000,
			expected:         "ca.example.com; accounturi=https://ca.example.com/acct/123; policy=wildcard; persistUntil=1721952000",
		},
		{
			name:             "domain name normalization - uppercase and trailing dot",
			issuerDomainName: "CA.EXAMPLE.COM.",
			accountURI:       "https://ca.example.com/acct/456",
			policy:           "",
			persistUntil:     0,
			expected:         "ca.example.com; accounturi=https://ca.example.com/acct/456",
		},
		{
			name:             "empty policy should be omitted",
			issuerDomainName: "ca.example.com",
			accountURI:       "https://ca.example.com/acct/789",
			policy:           "",
			persistUntil:     1721952000,
			expected:         "ca.example.com; accounturi=https://ca.example.com/acct/789; persistUntil=1721952000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EncodeDNSPersist01Record(tt.issuerDomainName, tt.accountURI, tt.policy, tt.persistUntil)
			if result != tt.expected {
				t.Errorf("EncodeDNSPersist01Record() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestParseDNSPersist01Record(t *testing.T) {
	tests := []struct {
		name                    string
		record                  string
		expectedIssuerDomain    string
		expectedAccountURI      string
		expectedPolicy          string
		expectedPersistUntil    int64
		expectError             bool
		expectedErrorSubstring  string
	}{
		{
			name:                 "basic valid record",
			record:               "ca.example.com; accounturi=https://ca.example.com/acct/123",
			expectedIssuerDomain: "ca.example.com",
			expectedAccountURI:   "https://ca.example.com/acct/123",
			expectedPolicy:       "",
			expectedPersistUntil: 0,
		},
		{
			name:                 "record with wildcard policy",
			record:               "ca.example.com; accounturi=https://ca.example.com/acct/123; policy=wildcard",
			expectedIssuerDomain: "ca.example.com",
			expectedAccountURI:   "https://ca.example.com/acct/123",
			expectedPolicy:       "wildcard",
			expectedPersistUntil: 0,
		},
		{
			name:                 "record with persistUntil",
			record:               "ca.example.com; accounturi=https://ca.example.com/acct/123; persistUntil=1721952000",
			expectedIssuerDomain: "ca.example.com",
			expectedAccountURI:   "https://ca.example.com/acct/123",
			expectedPolicy:       "",
			expectedPersistUntil: 1721952000,
		},
		{
			name:                 "record with all parameters",
			record:               "ca.example.com; accounturi=https://ca.example.com/acct/123; policy=wildcard; persistUntil=1721952000",
			expectedIssuerDomain: "ca.example.com",
			expectedAccountURI:   "https://ca.example.com/acct/123",
			expectedPolicy:       "wildcard",
			expectedPersistUntil: 1721952000,
		},
		{
			name:                 "record with extra whitespace",
			record:               " ca.example.com ; accounturi = https://ca.example.com/acct/123 ; policy = wildcard ",
			expectedIssuerDomain: "ca.example.com",
			expectedAccountURI:   "https://ca.example.com/acct/123",
			expectedPolicy:       "wildcard",
			expectedPersistUntil: 0,
		},
		{
			name:                 "record with unknown parameters (should be ignored)",
			record:               "ca.example.com; accounturi=https://ca.example.com/acct/123; unknown=value; policy=wildcard",
			expectedIssuerDomain: "ca.example.com",
			expectedAccountURI:   "https://ca.example.com/acct/123",
			expectedPolicy:       "wildcard",
			expectedPersistUntil: 0,
		},
		{
			name:                   "empty record",
			record:                 "",
			expectError:            true,
			expectedErrorSubstring: "empty record",
		},
		{
			name:                   "missing accounturi parameter",
			record:                 "ca.example.com; policy=wildcard",
			expectError:            true,
			expectedErrorSubstring: "missing required accounturi parameter",
		},
		{
			name:                   "missing issuer domain name",
			record:                 "; accounturi=https://ca.example.com/acct/123",
			expectError:            true,
			expectedErrorSubstring: "missing issuer domain name",
		},
		{
			name:                   "invalid parameter format",
			record:                 "ca.example.com; accounturi=https://ca.example.com/acct/123; invalidparam",
			expectError:            true,
			expectedErrorSubstring: "invalid parameter format",
		},
		{
			name:                   "invalid persistUntil timestamp",
			record:                 "ca.example.com; accounturi=https://ca.example.com/acct/123; persistUntil=invalid",
			expectError:            true,
			expectedErrorSubstring: "invalid persistUntil timestamp",
		},
		{
			name:                   "missing parameters",
			record:                 "ca.example.com",
			expectError:            true,
			expectedErrorSubstring: "invalid record format: missing parameters",
		},
		{
			name:                 "case-insensitive parameter key - AccountURI",
			record:               "ca.example.com; AccountURI=https://ca.example.com/acct/123",
			expectedIssuerDomain: "ca.example.com",
			expectedAccountURI:   "https://ca.example.com/acct/123",
			expectedPolicy:       "",
			expectedPersistUntil: 0,
		},
		{
			name:                 "case-insensitive parameter key - ACCOUNTURI",
			record:               "ca.example.com; ACCOUNTURI=https://ca.example.com/acct/456",
			expectedIssuerDomain: "ca.example.com",
			expectedAccountURI:   "https://ca.example.com/acct/456",
			expectedPolicy:       "",
			expectedPersistUntil: 0,
		},
		{
			name:                 "case-insensitive parameter key - POLICY",
			record:               "ca.example.com; accounturi=https://ca.example.com/acct/123; POLICY=wildcard",
			expectedIssuerDomain: "ca.example.com",
			expectedAccountURI:   "https://ca.example.com/acct/123",
			expectedPolicy:       "wildcard",
			expectedPersistUntil: 0,
		},
		{
			name:                 "case-insensitive parameter key - PersistUntil",
			record:               "ca.example.com; accounturi=https://ca.example.com/acct/123; PersistUntil=1721952000",
			expectedIssuerDomain: "ca.example.com",
			expectedAccountURI:   "https://ca.example.com/acct/123",
			expectedPolicy:       "",
			expectedPersistUntil: 1721952000,
		},
		{
			name:                 "case-insensitive parameter key - PERSISTUNTIL",
			record:               "ca.example.com; accounturi=https://ca.example.com/acct/123; PERSISTUNTIL=1721952000",
			expectedIssuerDomain: "ca.example.com",
			expectedAccountURI:   "https://ca.example.com/acct/123",
			expectedPolicy:       "",
			expectedPersistUntil: 1721952000,
		},
		{
			name:                 "case-insensitive policy value - WILDCARD",
			record:               "ca.example.com; accounturi=https://ca.example.com/acct/123; policy=WILDCARD",
			expectedIssuerDomain: "ca.example.com",
			expectedAccountURI:   "https://ca.example.com/acct/123",
			expectedPolicy:       "wildcard",
			expectedPersistUntil: 0,
		},
		{
			name:                 "case-insensitive policy value - Wildcard",
			record:               "ca.example.com; accounturi=https://ca.example.com/acct/123; policy=Wildcard",
			expectedIssuerDomain: "ca.example.com",
			expectedAccountURI:   "https://ca.example.com/acct/123",
			expectedPolicy:       "wildcard",
			expectedPersistUntil: 0,
		},
		{
			name:                 "case-insensitive policy value - WiLdCaRd",
			record:               "ca.example.com; accounturi=https://ca.example.com/acct/123; policy=WiLdCaRd",
			expectedIssuerDomain: "ca.example.com",
			expectedAccountURI:   "https://ca.example.com/acct/123",
			expectedPolicy:       "wildcard",
			expectedPersistUntil: 0,
		},
		{
			name:                 "mixed case parameters and values",
			record:               "ca.example.com; AccountURI=https://ca.example.com/acct/123; POLICY=WiLdCaRd; PersistUntil=1721952000",
			expectedIssuerDomain: "ca.example.com",
			expectedAccountURI:   "https://ca.example.com/acct/123",
			expectedPolicy:       "wildcard",
			expectedPersistUntil: 1721952000,
		},
		{
			name:                   "duplicate accounturi parameter",
			record:                 "ca.example.com; accounturi=https://ca.example.com/acct/123; accounturi=https://ca.example.com/acct/456",
			expectError:            true,
			expectedErrorSubstring: "duplicate parameter",
		},
		{
			name:                   "duplicate policy parameter",
			record:                 "ca.example.com; accounturi=https://ca.example.com/acct/123; policy=wildcard; policy=other",
			expectError:            true,
			expectedErrorSubstring: "duplicate parameter",
		},
		{
			name:                   "duplicate persistUntil parameter",
			record:                 "ca.example.com; accounturi=https://ca.example.com/acct/123; persistUntil=1721952000; persistUntil=1721952001",
			expectError:            true,
			expectedErrorSubstring: "duplicate parameter",
		},
		{
			name:                   "duplicate accounturi with different case",
			record:                 "ca.example.com; accounturi=https://ca.example.com/acct/123; AccountURI=https://ca.example.com/acct/456",
			expectError:            true,
			expectedErrorSubstring: "duplicate parameter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuerDomain, accountURI, policy, persistUntil, err := ParseDNSPersist01Record(tt.record)
			
			if tt.expectError {
				if err == nil {
					t.Errorf("ParseDNSPersist01Record() expected error, got none")
					return
				}
				if tt.expectedErrorSubstring != "" && !containsSubstring(err.Error(), tt.expectedErrorSubstring) {
					t.Errorf("ParseDNSPersist01Record() error = %v, want substring %v", err, tt.expectedErrorSubstring)
				}
				return
			}
			
			if err != nil {
				t.Errorf("ParseDNSPersist01Record() unexpected error = %v", err)
				return
			}
			
			if issuerDomain != tt.expectedIssuerDomain {
				t.Errorf("ParseDNSPersist01Record() issuerDomain = %v, want %v", issuerDomain, tt.expectedIssuerDomain)
			}
			if accountURI != tt.expectedAccountURI {
				t.Errorf("ParseDNSPersist01Record() accountURI = %v, want %v", accountURI, tt.expectedAccountURI)
			}
			if policy != tt.expectedPolicy {
				t.Errorf("ParseDNSPersist01Record() policy = %v, want %v", policy, tt.expectedPolicy)
			}
			if persistUntil != tt.expectedPersistUntil {
				t.Errorf("ParseDNSPersist01Record() persistUntil = %v, want %v", persistUntil, tt.expectedPersistUntil)
			}
		})
	}
}

func TestGetDNSPersist01Domain(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected string
	}{
		{
			name:     "basic domain",
			domain:   "example.com",
			expected: "_validation-persist.example.com",
		},
		{
			name:     "subdomain",
			domain:   "sub.example.com",
			expected: "_validation-persist.sub.example.com",
		},
		{
			name:     "domain with trailing dot",
			domain:   "example.com.",
			expected: "_validation-persist.example.com",
		},
		{
			name:     "single label domain",
			domain:   "localhost",
			expected: "_validation-persist.localhost",
		},
		{
			name:     "deep subdomain",
			domain:   "very.deep.sub.example.com",
			expected: "_validation-persist.very.deep.sub.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetDNSPersist01Domain(tt.domain)
			if result != tt.expected {
				t.Errorf("GetDNSPersist01Domain() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Helper function for string contains check
func containsSubstring(s, substr string) bool {
	return len(substr) <= len(s) && (substr == "" || strings.Contains(s, substr))
}

func TestClient_UpdateChallenge(t *testing.T) {
	account, order := makeOrder(t)
	auth, err := testClient.FetchAuthorization(account, order.Authorizations[0])
	if err != nil {
		t.Fatalf("unexpected error fetching authorization: %v", err)
	}

	chal := auth.ChallengeMap[ChallengeTypeDNS01]

	preChallenge(account, auth, chal)
	defer postChallenge(account, auth, chal)

	updatedChal, err := testClient.UpdateChallenge(account, chal)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if updatedChal.Status != "valid" {
		t.Fatalf("expected valid challenge, got: %s", chal.Status)
	}
}

func TestClient_UpdateChallenge_DNSPersist01(t *testing.T) {
	// dns-persist-01 is pebble-only
	if testClientMeta.Software != clientPebble {
		t.Skipf("skipping dns-persist-01 test for %s", testClientMeta.Software)
	}

	account, order := makeOrder(t)
	auth, err := testClient.FetchAuthorization(account, order.Authorizations[0])
	if err != nil {
		t.Fatalf("unexpected error fetching authorization: %v", err)
	}

	chal, ok := auth.ChallengeMap[ChallengeTypeDNSPersist01]
	if !ok {
		t.Fatalf("challenge %s not found", ChallengeTypeDNSPersist01)
	}

	// Validate challenge has IssuerDomainNames
	if len(chal.IssuerDomainNames) == 0 {
		t.Fatalf("challenge missing IssuerDomainNames")
	}

	// Test helper functions with challenge data
	issuerDomainName := chal.IssuerDomainNames[0]
	
	// Test DNS domain generation
	expectedDomain := GetDNSPersist01Domain(auth.Identifier.Value)
	expectedPrefix := "_validation-persist." + auth.Identifier.Value
	if expectedDomain != expectedPrefix {
		t.Errorf("GetDNSPersist01Domain() = %v, want %v", expectedDomain, expectedPrefix)
	}

	// Test record encoding
	recordValue := EncodeDNSPersist01Record(issuerDomainName, account.URL, "", 0)
	expectedRecord := issuerDomainName + "; accounturi=" + account.URL
	if recordValue != expectedRecord {
		t.Errorf("EncodeDNSPersist01Record() = %v, want %v", recordValue, expectedRecord)
	}

	// Test record parsing
	parsedIssuer, parsedAccountURI, parsedPolicy, parsedPersistUntil, err := ParseDNSPersist01Record(recordValue)
	if err != nil {
		t.Fatalf("ParseDNSPersist01Record() unexpected error: %v", err)
	}
	if parsedIssuer != issuerDomainName {
		t.Errorf("parsed issuer domain = %v, want %v", parsedIssuer, issuerDomainName)
	}
	if parsedAccountURI != account.URL {
		t.Errorf("parsed account URI = %v, want %v", parsedAccountURI, account.URL)
	}
	if parsedPolicy != "" {
		t.Errorf("parsed policy = %v, want empty", parsedPolicy)
	}
	if parsedPersistUntil != 0 {
		t.Errorf("parsed persistUntil = %v, want 0", parsedPersistUntil)
	}

	preChallenge(account, auth, chal)
	defer postChallenge(account, auth, chal)

	updatedChal, err := testClient.UpdateChallenge(account, chal)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if updatedChal.Status != "valid" {
		t.Fatalf("expected valid challenge, got: %s", chal.Status)
	}
}

func TestClient_FetchChallenge(t *testing.T) {
	account, order := makeOrder(t)
	auth, err := testClient.FetchAuthorization(account, order.Authorizations[0])
	if err != nil {
		t.Fatalf("unexpected error fetching authorization: %v", err)
	}

	chal := auth.Challenges[0]

	fetchedChal, err := testClient.FetchChallenge(account, chal.URL)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if chal.Token != fetchedChal.Token {
		t.Fatalf("tokens different")
	}
}

func Test_checkUpdatedChallengeStatus(t *testing.T) {
	tests := []struct {
		Status   string
		Finished bool
		HasError bool
	}{
		{
			Status: "pending",
		},
		{
			Status: "processing",
		},
		{
			Status:   "valid",
			Finished: true,
		},
		{
			Status:   "invalid",
			Finished: true,
			HasError: true,
		},
		{
			Status:   "blah",
			Finished: true,
			HasError: true,
		},
	}
	for _, ct := range tests {
		finished, err := checkUpdatedChallengeStatus(Challenge{
			Status: ct.Status,
		})
		if ct.Finished != finished {
			t.Fatalf("Finished mismatch on status %s, expected: %t got: %t", ct.Status, ct.Finished, finished)
		}
		if ct.HasError && err == nil {
			t.Fatalf("status %s expected error, got none", ct.Status)
		}
		if !ct.HasError && err != nil {
			t.Fatalf("status %s expected no error, got: %v", ct.Status, err)
		}
	}
}
