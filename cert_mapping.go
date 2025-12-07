// Copyright 2025 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"strings"
)

// CertMappingType specifies how to derive securityName from peer certificate.
// See RFC 6353 section 5.3.2 for the certificate-to-securityName mapping types.
type CertMappingType int

// Certificate mapping types as defined in RFC 6353.
// These map to snmpTlstmCertToTSNMIdentities OIDs.
const (
	// CertMapSpecified uses a pre-configured fingerprint-to-securityName mapping.
	// The fingerprint is matched against the certificate and if found, the
	// associated SecurityName is returned.
	CertMapSpecified CertMappingType = iota

	// CertMapSANRFC822 extracts the first rfc822Name from the certificate's
	// Subject Alternative Name extension. The host part is lowercased per RFC.
	CertMapSANRFC822

	// CertMapSANDNSName extracts the first dNSName from the certificate's
	// Subject Alternative Name extension. The name is fully lowercased.
	CertMapSANDNSName

	// CertMapSANIPAddress extracts the first iPAddress from the certificate's
	// Subject Alternative Name extension.
	CertMapSANIPAddress

	// CertMapSANAny tries rfc822Name, then dNSName, then iPAddress from the
	// Subject Alternative Name extension, returning the first one found.
	CertMapSANAny

	// CertMapCommonName extracts the CommonName from the certificate's
	// distinguished name.
	CertMapCommonName
)

// CertMapping represents a single certificate-to-securityName mapping entry.
// When Type is CertMapSpecified, Fingerprint and SecurityName must be set.
// For other types, the SecurityName is derived from the certificate itself.
type CertMapping struct {
	// Type specifies the mapping algorithm to use.
	Type CertMappingType

	// Fingerprint is the certificate fingerprint for CertMapSpecified type.
	// Must be computed using HashAlgo.
	Fingerprint []byte

	// HashAlgo specifies the hash algorithm used for fingerprint comparison.
	// Common values: crypto.SHA256, crypto.SHA384, crypto.SHA512.
	// Defaults to SHA256 if not specified.
	HashAlgo crypto.Hash

	// SecurityName is the resulting securityName for CertMapSpecified type.
	// For other mapping types, this field is ignored as the name is derived
	// from the certificate.
	SecurityName string
}

// ErrNoCertMapping is returned when no certificate mapping matches.
var ErrNoCertMapping = errors.New("no matching certificate mapping")

// ExtractSecurityName derives a securityName from a certificate using the given mappings.
// Mappings are tried in slice order; the first match wins.
// Returns ErrNoCertMapping if no mapping matches.
func ExtractSecurityName(cert *x509.Certificate, mappings []CertMapping) (string, error) {
	if cert == nil {
		return "", errors.New("certificate is nil")
	}
	if len(mappings) == 0 {
		return "", ErrNoCertMapping
	}

	for _, m := range mappings {
		name, ok := tryMapping(cert, m)
		if ok {
			return name, nil
		}
	}
	return "", ErrNoCertMapping
}

// ExtractSecurityNameFromChain derives a securityName from a certificate chain.
// It tries each certificate in the chain against each mapping.
// Per RFC 6353, the entire certificate chain should be checked.
func ExtractSecurityNameFromChain(chain []*x509.Certificate, mappings []CertMapping) (string, error) {
	if len(chain) == 0 {
		return "", errors.New("certificate chain is empty")
	}
	if len(mappings) == 0 {
		return "", ErrNoCertMapping
	}

	// For each mapping, try each certificate in the chain
	for _, m := range mappings {
		for _, cert := range chain {
			name, ok := tryMapping(cert, m)
			if ok {
				return name, nil
			}
		}
	}
	return "", ErrNoCertMapping
}

// CertFingerprint computes the fingerprint of a certificate using the specified hash algorithm.
// If hashAlgo is 0, defaults to SHA256.
func CertFingerprint(cert *x509.Certificate, hashAlgo crypto.Hash) []byte {
	if hashAlgo == 0 {
		hashAlgo = crypto.SHA256
	}
	h := hashAlgo.New()
	h.Write(cert.Raw)
	return h.Sum(nil)
}

// tryMapping attempts to extract a securityName from a certificate using a single mapping.
// Returns the securityName and true if successful, empty string and false otherwise.
func tryMapping(cert *x509.Certificate, m CertMapping) (string, bool) {
	switch m.Type {
	case CertMapSpecified:
		hashAlgo := m.HashAlgo
		if hashAlgo == 0 {
			hashAlgo = crypto.SHA256
		}
		fp := CertFingerprint(cert, hashAlgo)
		if bytes.Equal(fp, m.Fingerprint) {
			return m.SecurityName, true
		}

	case CertMapSANRFC822:
		// RFC 6353: Email addresses have the host part lowercased
		for _, email := range cert.EmailAddresses {
			return lowercaseEmailHost(email), true
		}

	case CertMapSANDNSName:
		// RFC 6353: DNS names are fully lowercased
		for _, dns := range cert.DNSNames {
			return strings.ToLower(dns), true
		}

	case CertMapSANIPAddress:
		for _, ip := range cert.IPAddresses {
			return ip.String(), true
		}

	case CertMapSANAny:
		// Try in order: rfc822Name, dNSName, iPAddress
		if len(cert.EmailAddresses) > 0 {
			return lowercaseEmailHost(cert.EmailAddresses[0]), true
		}
		if len(cert.DNSNames) > 0 {
			return strings.ToLower(cert.DNSNames[0]), true
		}
		if len(cert.IPAddresses) > 0 {
			return cert.IPAddresses[0].String(), true
		}

	case CertMapCommonName:
		if cert.Subject.CommonName != "" {
			return cert.Subject.CommonName, true
		}
	}
	return "", false
}

// lowercaseEmailHost returns the email with the host part lowercased.
// Per RFC 6353, only the host part (after @) is lowercased, not the local part.
func lowercaseEmailHost(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return email
	}
	return parts[0] + "@" + strings.ToLower(parts[1])
}
