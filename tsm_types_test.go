// Copyright 2025 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"crypto"
	"crypto/tls"
	"testing"

	"github.com/pion/dtls/v3"
)

// TestTransportSecurityModelConstant verifies TSM constant has correct value.
func TestTransportSecurityModelConstant(t *testing.T) {
	// RFC 5591 specifies TSM as security model 4
	if TransportSecurityModel != 4 {
		t.Errorf("TransportSecurityModel = %d; want 4", TransportSecurityModel)
	}

	// Verify USM is still 3
	if UserSecurityModel != 3 {
		t.Errorf("UserSecurityModel = %d; want 3", UserSecurityModel)
	}
}

// TestCertMappingTypes verifies all 6 certificate mapping types are defined.
func TestCertMappingTypes(t *testing.T) {
	// RFC 6353 defines 6 mapping types
	tests := []struct {
		name  string
		value CertMappingType
		want  int
	}{
		{"CertMapSpecified", CertMapSpecified, 0},
		{"CertMapSANRFC822", CertMapSANRFC822, 1},
		{"CertMapSANDNSName", CertMapSANDNSName, 2},
		{"CertMapSANIPAddress", CertMapSANIPAddress, 3},
		{"CertMapSANAny", CertMapSANAny, 4},
		{"CertMapCommonName", CertMapCommonName, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if int(tt.value) != tt.want {
				t.Errorf("%s = %d; want %d", tt.name, tt.value, tt.want)
			}
		})
	}
}

// TestGoSNMPHasTLSFields verifies TLSConfig and DTLSConfig fields exist on GoSNMP.
func TestGoSNMPHasTLSFields(t *testing.T) {
	g := &GoSNMP{}

	// Verify TLSConfig field exists and can be set
	g.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if g.TLSConfig == nil {
		t.Error("TLSConfig should be settable")
	}
	if g.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("TLSConfig.MinVersion = %d; want %d", g.TLSConfig.MinVersion, tls.VersionTLS12)
	}

	// Verify DTLSConfig field exists and can be set
	g.DTLSConfig = &dtls.Config{}
	if g.DTLSConfig == nil {
		t.Error("DTLSConfig should be settable")
	}
}

// TestCertMappingStruct verifies CertMapping struct fields.
func TestCertMappingStruct(t *testing.T) {
	// Create a mapping with all fields set
	mapping := CertMapping{
		Type:         CertMapSpecified,
		Fingerprint:  []byte{0x01, 0x02, 0x03},
		HashAlgo:     crypto.SHA256,
		SecurityName: "testUser",
	}

	if mapping.Type != CertMapSpecified {
		t.Errorf("Type = %d; want %d", mapping.Type, CertMapSpecified)
	}
	if len(mapping.Fingerprint) != 3 {
		t.Errorf("Fingerprint length = %d; want 3", len(mapping.Fingerprint))
	}
	if mapping.HashAlgo != crypto.SHA256 {
		t.Errorf("HashAlgo = %v; want crypto.SHA256", mapping.HashAlgo)
	}
	if mapping.SecurityName != "testUser" {
		t.Errorf("SecurityName = %s; want testUser", mapping.SecurityName)
	}
}

// TestSecurityModelValues ensures security model values don't overlap.
func TestSecurityModelValues(t *testing.T) {
	if UserSecurityModel == TransportSecurityModel {
		t.Error("UserSecurityModel and TransportSecurityModel should have different values")
	}
}

// TestTsmImplementsInterface verifies TsmSecurityParameters implements SnmpV3SecurityParameters.
func TestTsmImplementsInterface(t *testing.T) {
	// This is a compile-time check via the var _ declaration in v3_tsm.go
	// but we can also verify at runtime
	var sp SnmpV3SecurityParameters = &TsmSecurityParameters{}
	if sp == nil {
		t.Error("TsmSecurityParameters should implement SnmpV3SecurityParameters")
	}
}

// TestTsmValidateAuthPriv verifies TSM accepts AuthPriv security level.
func TestTsmValidateAuthPriv(t *testing.T) {
	sp := &TsmSecurityParameters{}
	err := sp.validate(AuthPriv)
	if err != nil {
		t.Errorf("TSM should accept AuthPriv: %v", err)
	}
}

// TestTsmValidateNoAuth verifies TSM rejects NoAuthNoPriv security level.
func TestTsmValidateNoAuth(t *testing.T) {
	sp := &TsmSecurityParameters{}
	err := sp.validate(NoAuthNoPriv)
	if err == nil {
		t.Error("TSM should reject NoAuthNoPriv")
	}
}

// TestTsmValidateAuthNoPriv verifies TSM rejects AuthNoPriv security level.
func TestTsmValidateAuthNoPriv(t *testing.T) {
	sp := &TsmSecurityParameters{}
	err := sp.validate(AuthNoPriv)
	if err == nil {
		t.Error("TSM should reject AuthNoPriv")
	}
}

// TestTsmMarshal verifies TSM security parameters marshal to empty bytes.
// RFC 5591: "The securityParameters field is an empty OCTET STRING."
// The caller wraps our output in an OCTET STRING, so we return empty bytes.
func TestTsmMarshal(t *testing.T) {
	sp := &TsmSecurityParameters{SecurityName: "testUser"}
	data, err := sp.marshal(AuthPriv)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// TSM should marshal to empty bytes (caller wraps in OCTET STRING)
	if len(data) != 0 {
		t.Errorf("marshal length = %d; want 0", len(data))
	}
}

// TestTsmUnmarshal verifies TSM security parameters unmarshal correctly.
// For TSM, unmarshal is a no-op - security parameters are empty on the wire
// and the cursor is already positioned after the empty OCTET STRING wrapper.
func TestTsmUnmarshal(t *testing.T) {
	sp := &TsmSecurityParameters{}

	// The packet contains data at position 5 (scopedPDU starts here)
	// TSM unmarshal should just return the cursor unchanged
	packet := []byte{0x30, 0x10, 0x04, 0x05, 'h', 'e', 'l', 'l', 'o'}
	startCursor := 5
	cursor, err := sp.unmarshal(AuthPriv, packet, startCursor)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	// Cursor should be unchanged - TSM has nothing to parse
	if cursor != startCursor {
		t.Errorf("cursor = %d; want %d (unchanged)", cursor, startCursor)
	}
}

// TestTsmCopy verifies Copy creates an independent copy.
func TestTsmCopy(t *testing.T) {
	original := &TsmSecurityParameters{
		SecurityName: "originalUser",
	}

	copied := original.Copy()
	copiedTsm, ok := copied.(*TsmSecurityParameters)
	if !ok {
		t.Fatal("Copy should return *TsmSecurityParameters")
	}

	if copiedTsm.SecurityName != original.SecurityName {
		t.Errorf("copied SecurityName = %s; want %s", copiedTsm.SecurityName, original.SecurityName)
	}

	// Modify original and verify copy is independent
	original.SecurityName = "modifiedUser"
	if copiedTsm.SecurityName == original.SecurityName {
		t.Error("Copy should be independent from original")
	}
}

// TestTsmDescription verifies Description returns expected format.
func TestTsmDescription(t *testing.T) {
	sp := &TsmSecurityParameters{SecurityName: "testUser"}
	desc := sp.Description()
	expected := "tsm,securityName=testUser"
	if desc != expected {
		t.Errorf("Description = %s; want %s", desc, expected)
	}
}

// TestTsmGetIdentifier verifies getIdentifier returns SecurityName.
func TestTsmGetIdentifier(t *testing.T) {
	sp := &TsmSecurityParameters{SecurityName: "testUser"}
	id := sp.getIdentifier()
	if id != "testUser" {
		t.Errorf("getIdentifier = %s; want testUser", id)
	}
}

// TestTsmEncryptDecryptNoOp verifies encrypt/decrypt are no-ops.
func TestTsmEncryptDecryptNoOp(t *testing.T) {
	sp := &TsmSecurityParameters{}

	// Test encrypt
	plaintext := []byte{0x01, 0x02, 0x03}
	encrypted, err := sp.encryptPacket(plaintext)
	if err != nil {
		t.Fatalf("encryptPacket failed: %v", err)
	}
	if len(encrypted) != len(plaintext) {
		t.Errorf("encrypted length = %d; want %d", len(encrypted), len(plaintext))
	}

	// Test decrypt
	decrypted, err := sp.decryptPacket(encrypted, 0)
	if err != nil {
		t.Fatalf("decryptPacket failed: %v", err)
	}
	if len(decrypted) != len(encrypted) {
		t.Errorf("decrypted length = %d; want %d", len(decrypted), len(encrypted))
	}
}

// TestTsmIsAuthentic verifies isAuthentic always returns true.
func TestTsmIsAuthentic(t *testing.T) {
	sp := &TsmSecurityParameters{}
	packet := &SnmpPacket{}

	authentic, err := sp.isAuthentic([]byte{}, packet)
	if err != nil {
		t.Fatalf("isAuthentic failed: %v", err)
	}
	if !authentic {
		t.Error("TSM isAuthentic should always return true")
	}
}

// TestTsmDiscoveryNotRequired verifies TSM doesn't require discovery.
func TestTsmDiscoveryNotRequired(t *testing.T) {
	sp := &TsmSecurityParameters{}
	discoveryPkt := sp.discoveryRequired()
	if discoveryPkt != nil {
		t.Error("TSM should not require discovery")
	}
}

// TestValidateParametersV3WithTSM verifies validateParametersV3 accepts TSM.
func TestValidateParametersV3WithTSM(t *testing.T) {
	g := &GoSNMP{
		Version:            Version3,
		SecurityModel:      TransportSecurityModel,
		MsgFlags:           AuthPriv,
		SecurityParameters: &TsmSecurityParameters{},
		DTLSConfig:         &dtls.Config{},
	}

	err := g.validateParametersV3()
	if err != nil {
		t.Errorf("validateParametersV3 should accept TSM with DTLSConfig: %v", err)
	}
}

// TestValidateParametersV3TSMRequiresConfig verifies TSM requires TLS/DTLS config.
func TestValidateParametersV3TSMRequiresConfig(t *testing.T) {
	g := &GoSNMP{
		Version:            Version3,
		SecurityModel:      TransportSecurityModel,
		MsgFlags:           AuthPriv,
		SecurityParameters: &TsmSecurityParameters{},
		// No TLSConfig or DTLSConfig
	}

	err := g.validateParametersV3()
	if err == nil {
		t.Error("validateParametersV3 should reject TSM without TLS/DTLS config")
	}
}
