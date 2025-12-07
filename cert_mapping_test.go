// Copyright 2025 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// createTestCert creates a test certificate with the given options.
func createTestCert(t *testing.T, cn string, dnsNames []string, emails []string, ips []net.IP) *x509.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		EmailAddresses:        emails,
		IPAddresses:           ips,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

func TestCertMapSpecified(t *testing.T) {
	cert := createTestCert(t, "test-cn", nil, nil, nil)
	fp := CertFingerprint(cert, crypto.SHA256)

	mappings := []CertMapping{
		{
			Type:         CertMapSpecified,
			Fingerprint:  fp,
			HashAlgo:     crypto.SHA256,
			SecurityName: "testUser",
		},
	}

	name, err := ExtractSecurityName(cert, mappings)
	require.NoError(t, err)
	require.Equal(t, "testUser", name)
}

func TestCertMapSpecifiedMismatch(t *testing.T) {
	cert := createTestCert(t, "test-cn", nil, nil, nil)

	// Wrong fingerprint
	mappings := []CertMapping{
		{
			Type:         CertMapSpecified,
			Fingerprint:  []byte{0x01, 0x02, 0x03},
			HashAlgo:     crypto.SHA256,
			SecurityName: "testUser",
		},
	}

	_, err := ExtractSecurityName(cert, mappings)
	require.ErrorIs(t, err, ErrNoCertMapping)
}

func TestCertMapSANRFC822(t *testing.T) {
	cert := createTestCert(t, "test-cn", nil, []string{"User@Example.COM"}, nil)

	mappings := []CertMapping{
		{Type: CertMapSANRFC822},
	}

	name, err := ExtractSecurityName(cert, mappings)
	require.NoError(t, err)
	// Only host part is lowercased per RFC
	require.Equal(t, "User@example.com", name)
}

func TestCertMapSANDNSName(t *testing.T) {
	cert := createTestCert(t, "test-cn", []string{"Server.Example.COM"}, nil, nil)

	mappings := []CertMapping{
		{Type: CertMapSANDNSName},
	}

	name, err := ExtractSecurityName(cert, mappings)
	require.NoError(t, err)
	// Fully lowercased
	require.Equal(t, "server.example.com", name)
}

func TestCertMapSANIPAddress(t *testing.T) {
	cert := createTestCert(t, "test-cn", nil, nil, []net.IP{net.ParseIP("192.168.1.100")})

	mappings := []CertMapping{
		{Type: CertMapSANIPAddress},
	}

	name, err := ExtractSecurityName(cert, mappings)
	require.NoError(t, err)
	require.Equal(t, "192.168.1.100", name)
}

func TestCertMapSANIPAddressV6(t *testing.T) {
	cert := createTestCert(t, "test-cn", nil, nil, []net.IP{net.ParseIP("2001:db8::1")})

	mappings := []CertMapping{
		{Type: CertMapSANIPAddress},
	}

	name, err := ExtractSecurityName(cert, mappings)
	require.NoError(t, err)
	require.Equal(t, "2001:db8::1", name)
}

func TestCertMapSANAny(t *testing.T) {
	t.Run("prefers email", func(t *testing.T) {
		cert := createTestCert(t, "test-cn",
			[]string{"server.example.com"},
			[]string{"user@example.com"},
			[]net.IP{net.ParseIP("192.168.1.1")})

		mappings := []CertMapping{
			{Type: CertMapSANAny},
		}

		name, err := ExtractSecurityName(cert, mappings)
		require.NoError(t, err)
		require.Equal(t, "user@example.com", name)
	})

	t.Run("falls back to dns", func(t *testing.T) {
		cert := createTestCert(t, "test-cn",
			[]string{"server.example.com"},
			nil,
			[]net.IP{net.ParseIP("192.168.1.1")})

		mappings := []CertMapping{
			{Type: CertMapSANAny},
		}

		name, err := ExtractSecurityName(cert, mappings)
		require.NoError(t, err)
		require.Equal(t, "server.example.com", name)
	})

	t.Run("falls back to ip", func(t *testing.T) {
		cert := createTestCert(t, "test-cn", nil, nil, []net.IP{net.ParseIP("10.0.0.1")})

		mappings := []CertMapping{
			{Type: CertMapSANAny},
		}

		name, err := ExtractSecurityName(cert, mappings)
		require.NoError(t, err)
		require.Equal(t, "10.0.0.1", name)
	})
}

func TestCertMapCommonName(t *testing.T) {
	cert := createTestCert(t, "MyCommonName", nil, nil, nil)

	mappings := []CertMapping{
		{Type: CertMapCommonName},
	}

	name, err := ExtractSecurityName(cert, mappings)
	require.NoError(t, err)
	require.Equal(t, "MyCommonName", name)
}

func TestCertMapSliceOrder(t *testing.T) {
	// First matching mapping wins
	cert := createTestCert(t, "test-cn", []string{"dns.example.com"}, []string{"email@example.com"}, nil)
	fp := CertFingerprint(cert, crypto.SHA256)

	mappings := []CertMapping{
		{Type: CertMapSANDNSName},      // Should match first
		{Type: CertMapSANRFC822},       // Would also match
		{Type: CertMapSpecified, Fingerprint: fp, HashAlgo: crypto.SHA256, SecurityName: "specified"},
	}

	name, err := ExtractSecurityName(cert, mappings)
	require.NoError(t, err)
	require.Equal(t, "dns.example.com", name)
}

func TestCertMapChainIteration(t *testing.T) {
	// Create a chain of certificates
	issuer := createTestCert(t, "Issuer CA", nil, nil, nil)
	leaf := createTestCert(t, "Leaf Cert", []string{"leaf.example.com"}, nil, nil)

	chain := []*x509.Certificate{leaf, issuer}

	// Mapping that only matches issuer
	issuerFp := CertFingerprint(issuer, crypto.SHA256)
	mappings := []CertMapping{
		{Type: CertMapSpecified, Fingerprint: issuerFp, HashAlgo: crypto.SHA256, SecurityName: "issuerMatch"},
	}

	name, err := ExtractSecurityNameFromChain(chain, mappings)
	require.NoError(t, err)
	require.Equal(t, "issuerMatch", name)
}

func TestFingerprintSHA256(t *testing.T) {
	cert := createTestCert(t, "test", nil, nil, nil)
	fp := CertFingerprint(cert, crypto.SHA256)
	require.Len(t, fp, 32, "SHA256 fingerprint should be 32 bytes")
}

func TestFingerprintSHA384(t *testing.T) {
	cert := createTestCert(t, "test", nil, nil, nil)
	fp := CertFingerprint(cert, crypto.SHA384)
	require.Len(t, fp, 48, "SHA384 fingerprint should be 48 bytes")
}

func TestFingerprintSHA512(t *testing.T) {
	cert := createTestCert(t, "test", nil, nil, nil)
	fp := CertFingerprint(cert, crypto.SHA512)
	require.Len(t, fp, 64, "SHA512 fingerprint should be 64 bytes")
}

func TestFingerprintDefaultsSHA256(t *testing.T) {
	cert := createTestCert(t, "test", nil, nil, nil)
	fpDefault := CertFingerprint(cert, 0)
	fpExplicit := CertFingerprint(cert, crypto.SHA256)
	require.Equal(t, fpExplicit, fpDefault, "Default should use SHA256")
}

func TestExtractSecurityNameNilCert(t *testing.T) {
	mappings := []CertMapping{{Type: CertMapCommonName}}
	_, err := ExtractSecurityName(nil, mappings)
	require.Error(t, err)
	require.Contains(t, err.Error(), "nil")
}

func TestExtractSecurityNameEmptyMappings(t *testing.T) {
	cert := createTestCert(t, "test", nil, nil, nil)
	_, err := ExtractSecurityName(cert, nil)
	require.ErrorIs(t, err, ErrNoCertMapping)

	_, err = ExtractSecurityName(cert, []CertMapping{})
	require.ErrorIs(t, err, ErrNoCertMapping)
}

func TestExtractSecurityNameFromChainEmpty(t *testing.T) {
	mappings := []CertMapping{{Type: CertMapCommonName}}
	_, err := ExtractSecurityNameFromChain(nil, mappings)
	require.Error(t, err)

	_, err = ExtractSecurityNameFromChain([]*x509.Certificate{}, mappings)
	require.Error(t, err)
}

func TestLowercaseEmailHost(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"user@EXAMPLE.COM", "user@example.com"},
		{"User.Name@EXAMPLE.COM", "User.Name@example.com"},
		{"noatsign", "noatsign"},
		{"multiple@at@signs.com", "multiple@at@signs.com"},
	}

	for _, tc := range tests {
		result := lowercaseEmailHost(tc.input)
		require.Equal(t, tc.expected, result, "input: %s", tc.input)
	}
}
