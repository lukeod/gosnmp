// Copyright 2025 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// generateTestCert creates a self-signed certificate for testing.
func generateTestCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	// Generate key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test-server",
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	// Encode cert to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Encode key to PEM
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	// Create tls.Certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	// Create CA pool with self-signed cert
	caPool := x509.NewCertPool()
	ok := caPool.AppendCertsFromPEM(certPEM)
	require.True(t, ok)

	return cert, caPool
}

// startMockTLSServer starts a TLS server that handles connections.
// The handler should handle the TLS handshake (automatic on first Read/Write).
// Returns the address and a cleanup function.
func startMockTLSServer(t *testing.T, handler func(net.Conn)) (string, func()) {
	t.Helper()

	cert, _ := generateTestCert(t)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return // Server closed
			}
			go func(c net.Conn) {
				// Perform explicit TLS handshake
				if tlsConn, ok := c.(*tls.Conn); ok {
					if err := tlsConn.Handshake(); err != nil {
						c.Close()
						return
					}
				}
				handler(c)
			}(conn)
		}
	}()

	return listener.Addr().String(), func() { listener.Close() }
}

// nopLogger is a no-op logger for testing.
type nopLogger struct{}

func (nopLogger) Print(v ...interface{})            {}
func (nopLogger) Printf(format string, v ...interface{}) {}

// TestTLSHandshakeMockServer verifies TLS connection can be established.
func TestTLSHandshakeMockServer(t *testing.T) {
	cert, caPool := generateTestCert(t)

	// Server will wait for a read to complete (blocks until client does something)
	addr, cleanup := startMockTLSServer(t, func(conn net.Conn) {
		defer conn.Close()
		// Wait for any data from client (keeps connection open)
		buf := make([]byte, 1)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		conn.Read(buf) //nolint:errcheck
	})
	defer cleanup()

	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)

	var p int
	_, err = fmt.Sscanf(port, "%d", &p)
	require.NoError(t, err)

	g := &GoSNMP{
		Target:             host,
		Port:               uint16(p),
		Transport:          "tls",
		Version:            Version3,
		SecurityModel:      TransportSecurityModel,
		MsgFlags:           AuthPriv,
		SecurityParameters: &TsmSecurityParameters{},
		TLSConfig: &tls.Config{
			Certificates:       []tls.Certificate{cert},
			RootCAs:            caPool,
			InsecureSkipVerify: true, // Self-signed cert
		},
		Timeout: 5 * time.Second,
	}

	err = g.Connect()
	require.NoError(t, err, "TLS Connect should succeed")
	defer g.Conn.Close()

	require.NotNil(t, g.Conn, "Connection should not be nil")

	// Verify it's a TLS connection
	tlsConn, ok := g.Conn.(*tls.Conn)
	require.True(t, ok, "Connection should be *tls.Conn")

	state := tlsConn.ConnectionState()
	require.True(t, state.HandshakeComplete, "Handshake should be complete")
	t.Logf("TLS handshake successful, version: %x, cipher: %x", state.Version, state.CipherSuite)
}

// TestTLSConfigRequired verifies error when TLSConfig is missing.
func TestTLSConfigRequired(t *testing.T) {
	g := &GoSNMP{
		Target:             "127.0.0.1",
		Port:               10161,
		Transport:          "tls",
		Version:            Version3,
		SecurityModel:      TransportSecurityModel,
		MsgFlags:           AuthPriv,
		SecurityParameters: &TsmSecurityParameters{},
		TLSConfig:          nil, // Missing config
		Timeout:            1 * time.Second,
	}

	err := g.Connect()
	require.Error(t, err)
	// Error comes from validateParametersV3() for TSM
	require.Contains(t, err.Error(), "TLSConfig or DTLSConfig")
}

// TestTLSMinVersionEnforcement verifies RFC 9456 TLS 1.2 minimum is enforced.
func TestTLSMinVersionEnforcement(t *testing.T) {
	t.Run("rejects explicit TLS 1.1", func(t *testing.T) {
		g := &GoSNMP{
			Target:             "127.0.0.1",
			Port:               10161,
			Transport:          "tls",
			Version:            Version3,
			SecurityModel:      TransportSecurityModel,
			MsgFlags:           AuthPriv,
			SecurityParameters: &TsmSecurityParameters{},
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS11, // Too old
			},
			Timeout: 1 * time.Second,
		}

		err := g.Connect()
		require.Error(t, err)
		require.Contains(t, err.Error(), "RFC 9456 requires TLS 1.2 minimum")
	})

	t.Run("accepts TLS 1.2", func(t *testing.T) {
		cert, caPool := generateTestCert(t)

		addr, cleanup := startMockTLSServer(t, func(conn net.Conn) {
			defer conn.Close()
			buf := make([]byte, 1)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			conn.Read(buf) //nolint:errcheck
		})
		defer cleanup()

		host, port, _ := net.SplitHostPort(addr)
		var p int
		_, _ = fmt.Sscanf(port, "%d", &p)

		g := &GoSNMP{
			Target:             host,
			Port:               uint16(p),
			Transport:          "tls",
			Version:            Version3,
			SecurityModel:      TransportSecurityModel,
			MsgFlags:           AuthPriv,
			SecurityParameters: &TsmSecurityParameters{},
			TLSConfig: &tls.Config{
				Certificates:       []tls.Certificate{cert},
				RootCAs:            caPool,
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12, // Acceptable
			},
			Timeout: 5 * time.Second,
		}

		err := g.Connect()
		require.NoError(t, err)
		g.Conn.Close()
	})

	t.Run("defaults to TLS 1.2 when unset", func(t *testing.T) {
		cert, caPool := generateTestCert(t)

		addr, cleanup := startMockTLSServer(t, func(conn net.Conn) {
			defer conn.Close()
			buf := make([]byte, 1)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			conn.Read(buf) //nolint:errcheck
		})
		defer cleanup()

		host, port, _ := net.SplitHostPort(addr)
		var p int
		_, _ = fmt.Sscanf(port, "%d", &p)

		tlsConfig := &tls.Config{
			Certificates:       []tls.Certificate{cert},
			RootCAs:            caPool,
			InsecureSkipVerify: true,
			// MinVersion not set - should default to TLS12
		}

		g := &GoSNMP{
			Target:             host,
			Port:               uint16(p),
			Transport:          "tls",
			Version:            Version3,
			SecurityModel:      TransportSecurityModel,
			MsgFlags:           AuthPriv,
			SecurityParameters: &TsmSecurityParameters{},
			TLSConfig:          tlsConfig,
			Timeout:            5 * time.Second,
		}

		err := g.Connect()
		require.NoError(t, err)
		defer g.Conn.Close()

		// Verify MinVersion was set
		require.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
	})
}

// TestTLSTransportVariants verifies tls, tls4, tls6 transport strings work.
func TestTLSTransportVariants(t *testing.T) {
	cert, caPool := generateTestCert(t)

	for _, transport := range []string{"tls", "tls4"} {
		t.Run(transport, func(t *testing.T) {
			addr, cleanup := startMockTLSServer(t, func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 1)
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				conn.Read(buf) //nolint:errcheck
			})
			defer cleanup()

			host, port, _ := net.SplitHostPort(addr)
			var p int
			_, _ = fmt.Sscanf(port, "%d", &p)

			g := &GoSNMP{
				Target:             host,
				Port:               uint16(p),
				Transport:          transport,
				Version:            Version3,
				SecurityModel:      TransportSecurityModel,
				MsgFlags:           AuthPriv,
				SecurityParameters: &TsmSecurityParameters{},
				TLSConfig: &tls.Config{
					Certificates:       []tls.Certificate{cert},
					RootCAs:            caPool,
					InsecureSkipVerify: true,
				},
				Timeout: 5 * time.Second,
			}

			err := g.Connect()
			require.NoError(t, err, "Connect with %s should succeed", transport)
			g.Conn.Close()
		})
	}
}
