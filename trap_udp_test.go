// Copyright 2026 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build all || trap

package gosnmp

import (
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func skipWithoutIPv6Loopback(t *testing.T) {
	t.Helper()
	c, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	c.Close()
}

func TestReflectorUDPConn(t *testing.T) {
	subs := []struct {
		name                      string
		bindIP, targetIP, bindNet string
		clientIP, clientNet       string
		linuxOnly                 bool
	}{
		// Only Linux binds the whole 127.0.0.0/8 to loopback by default. The kernel's own source selection
		// for a destination of 127.0.0.3 is 127.0.0.1, so this case fails without source reflection.
		{"udp bind * send 127.0.0.2 from 127.0.0.3", "*", "127.0.0.2", "udp", "127.0.0.3", "udp", true},

		{"udp bind * send localhost", "*", "127.0.0.1", "udp", "*", "udp", false},
		{"udp bind * send localhost6", "*", "::1", "udp", "*", "udp", false},
		{"udp4 bind * send localhost", "*", "127.0.0.1", "udp4", "*", "udp", false},
		{"udp6 bind * send localhost6", "*", "::1", "udp6", "*", "udp", false},

		{"udp bind localhost send localhost", "127.0.0.1", "127.0.0.1", "udp", "*", "udp", false},
		{"udp bind localhost6 send localhost6", "::1", "::1", "udp", "*", "udp", false},
		{"udp4 bind localhost send localhost", "127.0.0.1", "127.0.0.1", "udp4", "*", "udp", false},
		{"udp6 bind localhost6 send localhost6", "::1", "::1", "udp6", "*", "udp", false},
	}

	for _, sub := range subs {
		t.Run(sub.name, func(t *testing.T) {
			if sub.linuxOnly && runtime.GOOS != "linux" {
				t.Skipf("requires Linux loopback address binding behavior")
			}
			if strings.Contains(sub.bindIP, ":") || strings.Contains(sub.targetIP, ":") {
				skipWithoutIPv6Loopback(t)
			}

			srvAddr := &net.UDPAddr{IP: net.ParseIP(sub.bindIP)}
			srv, err := net.ListenUDP(sub.bindNet, srvAddr)
			require.NoError(t, err)
			defer srv.Close()

			srvRealAddr := srv.LocalAddr().(*net.UDPAddr)

			r := newReflectorUDPConn(srv)

			t.Logf("SERVER: bind %v real %v\n", srvAddr, srvRealAddr)

			clientAddr := &net.UDPAddr{IP: net.ParseIP(sub.clientIP)}
			client, err := net.ListenUDP(sub.clientNet, clientAddr)
			require.NoError(t, err)
			defer client.Close()

			t.Logf("CLIENT: bind %v real %v\n", clientAddr, client.LocalAddr())

			payload := []byte("payload")
			srvErr := make(chan error, 1)
			go func() {
				require.NoError(t, srv.SetDeadline(time.Now().Add(1*time.Second)))
				buf := make([]byte, 1024)
				n, src, respond, err := r.readUDPFrom(buf)
				if err != nil {
					srvErr <- err
					return
				}
				t.Logf("REQUEST: from %v", src)

				_, err = respond(buf[:n])
				if err != nil {
					srvErr <- err
					return
				}

				srvErr <- nil
			}()

			_, err = client.WriteToUDP(payload, &net.UDPAddr{IP: net.ParseIP(sub.targetIP), Port: srvRealAddr.Port})
			require.NoError(t, err)

			require.NoError(t, <-srvErr) // wait for the server to respond

			require.NoError(t, client.SetDeadline(time.Now().Add(1*time.Second)))
			buf := make([]byte, 1024)
			n, src, err := client.ReadFromUDP(buf)
			require.NoError(t, err)
			require.Equal(t, payload, buf[:n])

			t.Logf("RESPONSE: from %v", src)
			require.Equal(t, net.UDPAddr{IP: net.ParseIP(sub.targetIP).To16(), Port: srvRealAddr.Port}, net.UDPAddr{IP: src.IP.To16(), Port: src.Port})
		})
	}
}

// TestReflectorUDPConnFallback simulates receiving packets whose destination is not usable as a response source
// (broadcast, multicast, or no destination information at all). The response must still be delivered via ordinary
// kernel source selection rather than being dropped.
func TestReflectorUDPConnFallback(t *testing.T) {
	subs := []struct {
		name string
		dst  net.IP
	}{
		{"no destination info", nil},
		{"IPv4 multicast", net.ParseIP("224.0.0.251")},
		{"IPv4 limited broadcast", net.ParseIP("255.255.255.255")},
		{"IPv4 directed broadcast", net.ParseIP("127.255.255.255")},
		{"IPv6 multicast", net.ParseIP("ff02::fb")},
		{"unspecified", net.ParseIP("::")},
	}

	srv, err := net.ListenUDP("udp", &net.UDPAddr{})
	require.NoError(t, err)
	defer srv.Close()
	r := newReflectorUDPConn(srv)

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	defer client.Close()
	clientAddr := client.LocalAddr().(*net.UDPAddr)

	payload := []byte("payload")
	for _, sub := range subs {
		t.Run(sub.name, func(t *testing.T) {
			respond := r.respondFunc(clientAddr, sub.dst)
			n, err := respond(payload)
			require.NoError(t, err)
			require.Equal(t, len(payload), n)

			require.NoError(t, client.SetDeadline(time.Now().Add(1*time.Second)))
			buf := make([]byte, 1024)
			rn, _, err := client.ReadFromUDP(buf)
			require.NoError(t, err)
			require.Equal(t, payload, buf[:rn])
		})
	}
}

// listenWildcardEphemeral starts tl on an unspecified address and an ephemeral port, returning the port.
func listenWildcardEphemeral(t *testing.T, tl *TrapListener) uint16 {
	t.Helper()

	errch := make(chan error, 1)
	go func() {
		errch <- tl.Listen(":0")
	}()

	select {
	case <-tl.Listening():
		return uint16(tl.conn.LocalAddr().(*net.UDPAddr).Port) //nolint:gosec
	case err := <-errch:
		t.Fatalf("error in listen: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for listener")
	}
	return 0
}

// TestSendInformReflectedSource sends an Inform to a wildcard listener through 127.0.0.2. The client socket is
// connected, so its kernel discards responses that are not sourced from 127.0.0.2; receiving the Inform response
// proves the listener reflected the request's destination address.
func TestSendInformReflectedSource(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("requires Linux loopback address binding behavior")
	}

	done := make(chan error, 1)

	tl := NewTrapListener()
	defer tl.Close()
	tl.OnNewTrap = makeTestTrapHandler(done, Version2c)
	tl.Params = newTestGoSNMP()

	gs := newTestGoSNMP()
	gs.Target = "127.0.0.2"
	gs.Port = listenWildcardEphemeral(t, tl)

	require.NoError(t, gs.Connect())
	defer gs.Conn.Close()

	trap := SnmpTrap{
		Variables: []SnmpPDU{{Name: trapTestOid, Type: OctetString, Value: trapTestPayload}},
		IsInform:  true,
	}

	resp, err := gs.SendTrap(trap)
	require.NoError(t, err)

	waitForTestTrap(t, done)

	require.Equal(t, GetResponse, resp.PDUType)
}

// TestSendV3ReportReflectedSource performs SNMPv3 engine ID discovery against a wildcard listener through 127.0.0.2.
// The connected client socket discards responses that are not sourced from 127.0.0.2; receiving the Report proves the
// listener reflected the request's destination address.
func TestSendV3ReportReflectedSource(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("requires Linux loopback address binding behavior")
	}

	tl := NewTrapListener()
	defer tl.Close()
	authoritativeEngineID := string([]byte{0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04})
	unknownEngineID := string([]byte{0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x05})
	sp := &UsmSecurityParameters{
		UserName:                 "test",
		AuthenticationProtocol:   SHA,
		AuthenticationPassphrase: "password",
		PrivacyProtocol:          AES256,
		PrivacyPassphrase:        "password",
		AuthoritativeEngineBoots: 1,
		AuthoritativeEngineTime:  1,
		AuthoritativeEngineID:    authoritativeEngineID,
	}
	tl.Params = newTestGoSNMPv3(AuthPriv, sp)

	clientParams := sp.Copy()
	clientParams.(*UsmSecurityParameters).AuthoritativeEngineID = ""
	gs := newTestGoSNMPv3(AuthPriv, clientParams)
	gs.Target = "127.0.0.2"
	gs.Port = listenWildcardEphemeral(t, tl)
	require.NoError(t, gs.Connect())
	defer gs.Conn.Close()

	getEngineIDRequest := SnmpPacket{
		Version:            Version3,
		MsgFlags:           Reportable,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: &UsmSecurityParameters{},
		ContextEngineID:    unknownEngineID,
		PDUType:            GetRequest,
		MsgID:              1824792385,
		RequestID:          1411852680,
		MsgMaxSize:         65507,
	}
	result, err := gs.sendOneRequest(&getEngineIDRequest, true)
	require.NoError(t, err, "sendOneRequest failed")

	require.Equal(t, authoritativeEngineID, result.SecurityParameters.(*UsmSecurityParameters).AuthoritativeEngineID)
	require.Equal(t, Report, result.PDUType)
}
