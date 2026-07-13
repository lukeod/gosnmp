// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build all || misc

package gosnmp

import (
	"context"
	"io"
	"log"
	"net"
	"reflect"
	"syscall"
	"testing"
	"time"
)

// copyTestCtxKey is a local context key type (staticcheck SA1029 forbids
// using an empty anonymous struct as a context key).
type copyTestCtxKey struct{}

// copyTestSource returns a GoSNMP with every exported field set to a non-zero
// value, so TestCopyFields notices when a newly added field is missing here
// and a Copy decision has not been made for it.
func copyTestSource() (*GoSNMP, net.Conn) {
	conn, peer := net.Pipe()
	logger := NewLogger(log.New(io.Discard, "", 0))
	return &GoSNMP{
		Conn:               conn,
		Target:             "198.51.100.1",
		Port:               1161,
		Transport:          "tcp",
		Community:          "notpublic",
		Version:            Version3,
		Context:            context.WithValue(context.Background(), copyTestCtxKey{}, "v"),
		Timeout:            5 * time.Second,
		Retries:            2,
		ExponentialTimeout: true,
		Logger:             logger,
		PreSend:            func(*GoSNMP) {},
		OnSent:             func(*GoSNMP) {},
		OnRecv:             func(*GoSNMP) {},
		OnRetry:            func(*GoSNMP) {},
		OnFinish:           func(*GoSNMP) {},
		MaxOids:            30,
		MaxRepetitions:     25,
		NonRepeaters:       1,

		UseUnconnectedUDPSocket: true,
		Control: func(_, _ string, _ syscall.RawConn) error {
			return nil
		},
		LocalAddr: "127.0.0.1:1234",
		AppOpts:   map[string]any{"c": true},
		MsgFlags:  AuthPriv,

		SecurityModel: UserSecurityModel,
		SecurityParameters: &UsmSecurityParameters{
			UserName:                 "user",
			AuthoritativeEngineID:    "engineid",
			AuthoritativeEngineBoots: 7,
			AuthoritativeEngineTime:  1234,
			AuthenticationProtocol:   SHA,
			AuthenticationPassphrase: "authpass",
			PrivacyProtocol:          AES,
			PrivacyPassphrase:        "privpass",
			SecretKey:                []byte{1, 2, 3},
			PrivacyKey:               []byte{4, 5, 6},
			Logger:                   logger,
		},
		TrapSecurityParametersTable: NewSnmpV3SecurityParametersTable(logger),
		ContextEngineID:             "ctxengine",
		ContextName:                 "ctxname",
	}, peer
}

// TestCopyFields checks every exported field of GoSNMP against an explicit
// Copy expectation, so adding a struct field without deciding how Copy
// handles it fails this test.
func TestCopyFields(t *testing.T) {
	src, peer := copyTestSource()
	defer peer.Close()
	defer src.Conn.Close()

	c := src.Copy()

	sv := reflect.ValueOf(src).Elem()
	cv := reflect.ValueOf(c).Elem()
	st := sv.Type()
	for i := 0; i < st.NumField(); i++ {
		f := st.Field(i)
		if !f.IsExported() {
			continue
		}
		if sv.Field(i).IsZero() {
			t.Errorf("copyTestSource leaves %s zero: set it and decide how Copy handles it", f.Name)
			continue
		}
		switch f.Name {
		case "Conn":
			if c.Conn != nil {
				t.Errorf("Copy: Conn = %v, want nil", c.Conn)
			}
		case "LocalAddr":
			if c.LocalAddr != "127.0.0.1:0" {
				t.Errorf("Copy: LocalAddr = %q, want %q", c.LocalAddr, "127.0.0.1:0")
			}
		case "SecurityParameters":
			if c.SecurityParameters == src.SecurityParameters {
				t.Error("Copy: SecurityParameters shares the original instance, want deep copy")
			}
			if !reflect.DeepEqual(c.SecurityParameters, src.SecurityParameters) {
				t.Errorf("Copy: SecurityParameters = %+v, want %+v", c.SecurityParameters, src.SecurityParameters)
			}
		default:
			if f.Type.Kind() == reflect.Func {
				if sv.Field(i).Pointer() != cv.Field(i).Pointer() {
					t.Errorf("Copy: %s does not reference the original function", f.Name)
				}
				continue
			}
			if !reflect.DeepEqual(sv.Field(i).Interface(), cv.Field(i).Interface()) {
				t.Errorf("Copy: %s = %#v, want %#v", f.Name, cv.Field(i).Interface(), sv.Field(i).Interface())
			}
		}
	}
}

func TestCopyLocalAddrPort(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"127.0.0.1:1234", "127.0.0.1:0"},
		{"[::1]:161", "[::1]:0"},
		{"127.0.0.1:", "127.0.0.1:0"},
		{"0.0.0.0:0", "0.0.0.0:0"},
		{"", ""},
		{"127.0.0.1", "127.0.0.1"},
		{"host:port:extra", "host:port:extra"},
	}
	for _, tt := range tests {
		g := &GoSNMP{LocalAddr: tt.in}
		if got := g.Copy().LocalAddr; got != tt.want {
			t.Errorf("Copy: LocalAddr %q = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestCopyConnectVariant checks that connecting a copy with the same
// Connect variant used on the original works: connect replaces a previous
// IPv4/IPv6 network qualifier instead of appending another one.
func TestCopyConnectVariant(t *testing.T) {
	const udp4 = "udp4"
	pc, err := net.ListenPacket(udp4, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port

	g := &GoSNMP{
		Target:  "127.0.0.1",
		Port:    uint16(port), //nolint:gosec
		Version: Version2c,
		Timeout: time.Second,
	}
	if err = g.ConnectIPv4(); err != nil {
		t.Fatalf("ConnectIPv4 original: %v", err)
	}
	defer g.Conn.Close()

	c := g.Copy()
	if err = c.ConnectIPv4(); err != nil {
		t.Fatalf("ConnectIPv4 copy: %v", err)
	}
	defer c.Conn.Close()
	if c.Transport != udp4 {
		t.Errorf("copy Transport = %q, want udp4", c.Transport)
	}
}

// TestCopyTypedNilSecurityParameters checks that a typed-nil value stored in
// the SecurityParameters interface does not panic Copy.
func TestCopyTypedNilSecurityParameters(t *testing.T) {
	g := &GoSNMP{SecurityParameters: (*UsmSecurityParameters)(nil)}
	if c := g.Copy(); c.SecurityParameters != nil {
		t.Errorf("Copy: SecurityParameters = %v, want nil", c.SecurityParameters)
	}
}

// TestCopyAppOptsIndependent checks that setting an AppOpts key on the
// original does not modify the copy's map.
func TestCopyAppOptsIndependent(t *testing.T) {
	g := &GoSNMP{AppOpts: map[string]any{"c": true}}
	c := g.Copy()
	g.AppOpts["extra"] = true
	if _, ok := c.AppOpts["extra"]; ok {
		t.Error("Copy: AppOpts shares the original map, want shallow copy")
	}
	if v, ok := c.AppOpts["c"]; !ok || v != true {
		t.Errorf("Copy: AppOpts[\"c\"] = %v, %v; want true", v, ok)
	}
}

func TestCopyNilSecurityParameters(t *testing.T) {
	g := &GoSNMP{Target: "127.0.0.1"}
	if c := g.Copy(); c.SecurityParameters != nil {
		t.Errorf("Copy: SecurityParameters = %v, want nil", c.SecurityParameters)
	}
}

// TestCopyRetainsDiscoveredSecurityParameters checks that a copy keeps the
// discovered engine state (so it skips SNMPv3 discovery) and is not affected
// by later changes to the original.
func TestCopyRetainsDiscoveredSecurityParameters(t *testing.T) {
	usm := &UsmSecurityParameters{
		UserName:                 "user",
		AuthoritativeEngineID:    "engineid",
		AuthoritativeEngineBoots: 7,
		AuthoritativeEngineTime:  1234,
		SecretKey:                []byte{1, 2, 3},
		PrivacyKey:               []byte{4, 5, 6},
	}
	g := &GoSNMP{Version: Version3, SecurityParameters: usm}

	c := g.Copy()

	usm.AuthoritativeEngineID = "changed"

	got, ok := c.SecurityParameters.(*UsmSecurityParameters)
	if !ok {
		t.Fatalf("Copy: SecurityParameters type %T, want *UsmSecurityParameters", c.SecurityParameters)
	}
	if got.AuthoritativeEngineID != "engineid" {
		t.Errorf("Copy: AuthoritativeEngineID = %q, want %q", got.AuthoritativeEngineID, "engineid")
	}
	if got.AuthoritativeEngineBoots != 7 || got.AuthoritativeEngineTime != 1234 {
		t.Errorf("Copy: engine boots/time = %d/%d, want 7/1234", got.AuthoritativeEngineBoots, got.AuthoritativeEngineTime)
	}
}
