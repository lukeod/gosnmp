// Copyright 2025 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build tsm_integration

package gosnmp

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/stretchr/testify/require"
)

// Default test certificate paths - relative to repo root
const (
	defaultCertDir    = "../issues/488/testing/certs"
	defaultClientCert = "client.crt"
	defaultClientKey  = "client.key"
	defaultCACert     = "ca.crt"
)

// Default test endpoint
const (
	defaultTSMTarget = "localhost"
	defaultTSMPort   = 10161
)

// getEnvOrDefault returns the environment variable value or a default.
func getEnvOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

// getCertPath returns the absolute path to a certificate file.
func getCertPath(t *testing.T, filename string) string {
	t.Helper()

	certDir := getEnvOrDefault("GOSNMP_TSM_CERT_DIR", defaultCertDir)
	path := filepath.Join(certDir, filename)

	// Convert to absolute path
	absPath, err := filepath.Abs(path)
	require.NoError(t, err, "failed to get absolute path for %s", filename)

	return absPath
}

// loadTestCerts loads the client certificate and CA pool for TSM testing.
func loadTestCerts(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	// Load client certificate
	certPath := getCertPath(t, defaultClientCert)
	keyPath := getCertPath(t, defaultClientKey)

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err, "failed to load client certificate from %s and %s", certPath, keyPath)

	// Load CA certificate
	caPath := getCertPath(t, defaultCACert)
	caCert, err := os.ReadFile(caPath)
	require.NoError(t, err, "failed to read CA certificate from %s", caPath)

	caPool := x509.NewCertPool()
	ok := caPool.AppendCertsFromPEM(caCert)
	require.True(t, ok, "failed to parse CA certificate")

	return cert, caPool
}

// makeDTLSConfig creates a DTLS configuration for testing.
func makeDTLSConfig(cert tls.Certificate, caPool *x509.CertPool) *dtls.Config {
	return &dtls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caPool,
		InsecureSkipVerify: false,
	}
}

// makeTLSConfig creates a TLS configuration for testing.
func makeTLSConfig(cert tls.Certificate, caPool *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}
}

// getTSMTarget returns the target address for TSM testing.
func getTSMTarget() string {
	return getEnvOrDefault("GOSNMP_TSM_TARGET", defaultTSMTarget)
}

// getTSMPort returns the port for TSM testing.
func getTSMPort() uint16 {
	// For simplicity, just use default - could parse env var if needed
	return defaultTSMPort
}

// TestLoadTestCertificates verifies that test certificates can be loaded.
func TestLoadTestCertificates(t *testing.T) {
	cert, caPool := loadTestCerts(t)

	// Verify certificate was loaded
	require.NotEmpty(t, cert.Certificate, "certificate should have at least one cert in chain")

	// Verify we can parse the certificate
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err, "should be able to parse certificate")
	require.NotNil(t, x509Cert, "parsed certificate should not be nil")

	// Verify CA pool is populated
	require.NotNil(t, caPool, "CA pool should not be nil")
}

// TestDTLSConfigCreation verifies that a valid DTLS config can be created.
func TestDTLSConfigCreation(t *testing.T) {
	cert, caPool := loadTestCerts(t)
	config := makeDTLSConfig(cert, caPool)

	require.NotNil(t, config, "DTLS config should not be nil")
	require.Len(t, config.Certificates, 1, "DTLS config should have one certificate")
	require.NotNil(t, config.RootCAs, "DTLS config should have RootCAs set")
	require.False(t, config.InsecureSkipVerify, "InsecureSkipVerify should be false")
}

// TestTLSConfigCreation verifies that a valid TLS config can be created.
func TestTLSConfigCreation(t *testing.T) {
	cert, caPool := loadTestCerts(t)
	config := makeTLSConfig(cert, caPool)

	require.NotNil(t, config, "TLS config should not be nil")
	require.Len(t, config.Certificates, 1, "TLS config should have one certificate")
	require.NotNil(t, config.RootCAs, "TLS config should have RootCAs set")
	require.Equal(t, uint16(tls.VersionTLS12), config.MinVersion, "MinVersion should be TLS 1.2")
}

// TestDTLSHandshake verifies DTLS connection can be established with net-snmp.
// Requires: sudo snmpd -f -Lo -C -c /home/luke/dev/snmp/issues/488/testing/config/snmpd.conf
func TestDTLSHandshake(t *testing.T) {
	cert, caPool := loadTestCerts(t)

	g := &GoSNMP{
		Target:             getTSMTarget(),
		Port:               getTSMPort(),
		Transport:          "dtls",
		Version:            Version3,
		SecurityModel:      TransportSecurityModel,
		MsgFlags:           AuthPriv,
		SecurityParameters: &TsmSecurityParameters{},
		DTLSConfig:         makeDTLSConfig(cert, caPool),
		Timeout:            5 * time.Second,
	}

	err := g.Connect()
	require.NoError(t, err, "DTLS Connect should succeed")
	defer g.Conn.Close()

	// Verify connection is established
	require.NotNil(t, g.Conn, "Connection should not be nil")

	// Get connection state to verify handshake completed
	dtlsConn, ok := g.Conn.(*dtls.Conn)
	require.True(t, ok, "Connection should be *dtls.Conn")

	// ConnectionState() returns (State, bool) - bool indicates handshake complete
	state, handshakeComplete := dtlsConn.ConnectionState()
	require.True(t, handshakeComplete, "Handshake should be complete")

	t.Logf("DTLS handshake successful, cipher suite: %s", state.CipherSuiteID)
}

// TestDTLSGetSysUpTime performs a full SNMP GET over DTLS.
// Requires: sudo snmpd -f -Lo -C -c /home/luke/dev/snmp/issues/488/testing/config/snmpd.conf
func TestDTLSGetSysUpTime(t *testing.T) {
	cert, caPool := loadTestCerts(t)

	g := &GoSNMP{
		Target:             getTSMTarget(),
		Port:               getTSMPort(),
		Transport:          "dtls",
		Version:            Version3,
		SecurityModel:      TransportSecurityModel,
		MsgFlags:           AuthPriv,
		SecurityParameters: &TsmSecurityParameters{},
		DTLSConfig:         makeDTLSConfig(cert, caPool),
		Timeout:            5 * time.Second,
	}

	err := g.Connect()
	require.NoError(t, err, "DTLS Connect should succeed")
	defer g.Conn.Close()

	// GET sysUpTime.0
	result, err := g.Get([]string{".1.3.6.1.2.1.1.3.0"})
	require.NoError(t, err, "GET should succeed")
	require.NotNil(t, result, "Result should not be nil")
	require.Len(t, result.Variables, 1, "Should have one variable")

	// sysUpTime is TimeTicks
	require.Equal(t, TimeTicks, result.Variables[0].Type, "sysUpTime should be TimeTicks")
	t.Logf("sysUpTime.0 = %v", result.Variables[0].Value)
}

// TestDTLSGetSysDescr performs SNMP GET of sysDescr over DTLS.
func TestDTLSGetSysDescr(t *testing.T) {
	cert, caPool := loadTestCerts(t)

	g := &GoSNMP{
		Target:             getTSMTarget(),
		Port:               getTSMPort(),
		Transport:          "dtls",
		Version:            Version3,
		SecurityModel:      TransportSecurityModel,
		MsgFlags:           AuthPriv,
		SecurityParameters: &TsmSecurityParameters{},
		DTLSConfig:         makeDTLSConfig(cert, caPool),
		Timeout:            5 * time.Second,
	}

	err := g.Connect()
	require.NoError(t, err, "DTLS Connect should succeed")
	defer g.Conn.Close()

	// GET sysDescr.0
	result, err := g.Get([]string{".1.3.6.1.2.1.1.1.0"})
	require.NoError(t, err, "GET should succeed")
	require.NotNil(t, result, "Result should not be nil")
	require.Len(t, result.Variables, 1, "Should have one variable")

	// sysDescr is OctetString
	require.Equal(t, OctetString, result.Variables[0].Type, "sysDescr should be OctetString")
	t.Logf("sysDescr.0 = %v", result.Variables[0].Value)
}
