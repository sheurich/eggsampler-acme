# eggsampler/acme

[![GoDoc](https://godoc.org/github.com/eggsampler/acme?status.svg)](https://godoc.org/github.com/eggsampler/acme)
[![Build Status](https://github.com/eggsampler/acme/actions/workflows/go.yml/badge.svg)](https://github.com/eggsampler/acme/actions)
[![Coverage Status](https://coveralls.io/repos/github/eggsampler/acme/badge.svg)](https://coveralls.io/github/eggsampler/acme)

## About

`eggsampler/acme` is a Go client library implementation for [RFC8555](https://tools.ietf.org/html/rfc8555) (previously ACME v2). This library can be used with the [Let's Encrypt](https://letsencrypt.org/) Certificate Authority (CA), but also other ACME compliant CA's such as [ZeroSSL](https://zerossl.com/), [Google Trust Services](https://pki.goog/) and others listed at https://acmeclients.com/certificate-authorities/. 

The library is designed to provide a zero external dependency wrapper over exposed directory endpoints and provide objects in easy to use structures.

## Requirements

A Go version of at least 1.11 is required as this repository is designed to be imported as a Go module.

## Usage

Simply import the module into a project,

```go
import "github.com/eggsampler/acme/v3"
```

Note the `/v3` major version at the end. Due to the way modules function, this is the major version as represented in the `go.mod` file and latest git repo [semver](https://semver.org/) tag.
All functions are still exported and called using the `acme` package name.

## Examples

A simple [certbot](https://certbot.eff.org/)-like example is provided in the examples/certbot directory.
This code demonstrates account registration, new order submission, fulfilling challenges, finalising an order and fetching the issued certificate chain.

An example of how to use the autocert package is also provided in examples/autocert.

## DNS-Persist-01 Challenge Support

This library implements the `dns-persist-01` ACME challenge method as specified in [draft-sheurich-acme-dns-persist](https://datatracker.ietf.org/doc/draft-sheurich-acme-dns-persist/). This challenge type allows you to provision a DNS TXT record once that can be reused for multiple certificate issuances, unlike `dns-01` which requires updating the record for each request.

### Key Features

- **Persistent DNS Records**: Set a TXT record once and reuse it for renewals and multiple certificates
- **Account Binding**: Records are tied to your ACME account URL
- **Wildcard Support**: Optional policy parameter for wildcard certificates
- **Expiration Control**: Optional `persistUntil` timestamp to control record validity

### Functions

- `GetDNSPersist01Domain(domain string) string` - Returns the DNS name for the TXT record (`_validation-persist.{domain}`)
- `EncodeDNSPersist01Record(issuerDomainName, accountURI, policy string, persistUntil int64) string` - Creates the TXT record value in RFC 8659 CAA issue-value syntax
- `ParseDNSPersist01Record(record string) (DNSPersist01Record, error)` - Parses a TXT record value into its components
- `Challenge.IssuerDomainNames []string` - List of valid issuer domain names from the CA (choose one for your TXT record)

### TXT Record Format

The TXT record follows RFC 8659 CAA issue-value syntax:

```
issuer-domain-name; accounturi=URI[; policy=wildcard][; persistUntil=timestamp]
```

Example:
```
ca.example.com; accounturi=https://acme.example.com/acct/123; policy=wildcard; persistUntil=1735689600
```

### Example Usage

A complete example demonstrating dns-persist-01 usage is available in [examples/dns-persist-01/main.go](examples/dns-persist-01/main.go). The example shows how to:

- Retrieve issuer domain names from the challenge
- Generate the correct DNS record name and value
- Handle both standard and wildcard certificates
- Reuse records for multiple certificate requests

## Tests

The tests can be run against an instance of [boulder](https://github.com/letsencrypt/boulder) or [pebble](https://github.com/letsencrypt/pebble).

Challenge fulfilment is designed to use the new `challtestsrv` server present inside boulder and pebble which responds to dns queries and challenges as required.

To run tests against an already running instance of boulder or pebble, use the `test` target in the Makefile.

Some convenience targets for launching pebble/boulder using their respective docker compose files have also been included in the Makefile.
