// Copyright 2025 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"errors"
	"fmt"
)

// TsmSecurityParameters implements SnmpV3SecurityParameters for the Transport Security Model (RFC 5591).
// TSM delegates all cryptographic operations to the transport layer (TLS/DTLS), so most methods
// are no-ops. The SecurityName is derived from the peer certificate by the transport layer.
type TsmSecurityParameters struct {
	// SecurityName is derived from the peer certificate by the transport layer.
	// For outgoing requests, this may be empty (the server identifies the client by cert).
	// For incoming traps/informs, this is populated from the peer certificate.
	SecurityName string

	Logger Logger
}

// Compile-time interface check
var _ SnmpV3SecurityParameters = (*TsmSecurityParameters)(nil)

// Log logs security parameter information
func (sp *TsmSecurityParameters) Log() {
	sp.Logger.Printf("TSM SECURITY PARAMETERS: %s", sp.SafeString())
}

// Copy returns a copy of the TsmSecurityParameters
func (sp *TsmSecurityParameters) Copy() SnmpV3SecurityParameters {
	return &TsmSecurityParameters{
		SecurityName: sp.SecurityName,
		Logger:       sp.Logger,
	}
}

// Description returns a string description of the security parameters
func (sp *TsmSecurityParameters) Description() string {
	return fmt.Sprintf("tsm,securityName=%s", sp.SecurityName)
}

// SafeString returns a logging-safe string (no secrets) of the security parameters
func (sp *TsmSecurityParameters) SafeString() string {
	return fmt.Sprintf("SecurityName:%s", sp.SecurityName)
}

// InitPacket initializes packet-specific security parameters.
// TSM has no per-packet security state to initialize.
func (sp *TsmSecurityParameters) InitPacket(packet *SnmpPacket) error {
	return nil
}

// InitSecurityKeys initializes security keys.
// TSM delegates key management to TLS/DTLS, so this is a no-op.
func (sp *TsmSecurityParameters) InitSecurityKeys() error {
	return nil
}

// validate checks that security parameters are valid for the given flags.
// TSM requires AuthPriv since transport layer provides both.
func (sp *TsmSecurityParameters) validate(flags SnmpV3MsgFlags) error {
	securityLevel := flags & AuthPriv
	if securityLevel != AuthPriv {
		return errors.New("TSM requires AuthPriv security level (transport provides auth+priv)")
	}
	return nil
}

// init initializes the security parameters with a logger.
func (sp *TsmSecurityParameters) init(log Logger) error {
	sp.Logger = log
	return nil
}

// discoveryRequired returns a discovery packet if engine discovery is needed.
// TSM does not require SNMP-level engine discovery; the TLS/DTLS handshake
// establishes the session. Return nil to skip discovery.
func (sp *TsmSecurityParameters) discoveryRequired() *SnmpPacket {
	return nil
}

// getDefaultContextEngineID returns the default context engine ID.
// TSM doesn't have an authoritative engine ID from discovery.
// The application should set ContextEngineID explicitly when needed.
func (sp *TsmSecurityParameters) getDefaultContextEngineID() string {
	return ""
}

// setSecurityParameters copies security parameters from another instance.
func (sp *TsmSecurityParameters) setSecurityParameters(in SnmpV3SecurityParameters) error {
	insp, ok := in.(*TsmSecurityParameters)
	if !ok {
		return errors.New("param SnmpV3SecurityParameters is not of type *TsmSecurityParameters")
	}
	sp.SecurityName = insp.SecurityName
	return nil
}

// marshal serializes the security parameters for the wire.
// RFC 5591 section 5.2: "The securityParameters field is an empty OCTET STRING."
// The caller wraps our return value in an OCTET STRING, so we return empty bytes
// to produce an empty OCTET STRING on the wire.
func (sp *TsmSecurityParameters) marshal(flags SnmpV3MsgFlags) ([]byte, error) {
	// TSM wire format: empty (caller wraps in OCTET STRING)
	return []byte{}, nil
}

// unmarshal parses the security parameters from the wire.
// TSM security parameters are empty on the wire, so there's nothing to parse.
// The caller (parseRawField) already parsed the empty OCTET STRING wrapper,
// and cursor is now at the start of the scopedPDU. We just return cursor unchanged.
func (sp *TsmSecurityParameters) unmarshal(flags SnmpV3MsgFlags, packet []byte, cursor int) (int, error) {
	// TSM security parameters are empty - nothing to parse
	// The cursor is already at the scopedPDU position after parseRawField
	sp.Logger.Printf("Parsed TSM security parameters (empty)")
	return cursor, nil
}

// authenticate adds authentication to the packet.
// TSM delegates authentication to TLS/DTLS, so this is a no-op.
func (sp *TsmSecurityParameters) authenticate(packet []byte) error {
	return nil
}

// isAuthentic verifies the packet is authentic.
// TSM delegates authentication to TLS/DTLS. If we received the packet
// over a valid TLS/DTLS connection, it is authentic.
func (sp *TsmSecurityParameters) isAuthentic(packetBytes []byte, packet *SnmpPacket) (bool, error) {
	return true, nil
}

// encryptPacket encrypts the scoped PDU.
// TSM delegates encryption to TLS/DTLS, so this returns the PDU unchanged.
func (sp *TsmSecurityParameters) encryptPacket(scopedPdu []byte) ([]byte, error) {
	return scopedPdu, nil
}

// decryptPacket decrypts the scoped PDU.
// TSM delegates decryption to TLS/DTLS, so this returns the packet unchanged.
func (sp *TsmSecurityParameters) decryptPacket(packet []byte, cursor int) ([]byte, error) {
	return packet, nil
}

// getIdentifier returns an identifier for this security parameters instance.
// For TSM, this is the security name derived from the certificate.
func (sp *TsmSecurityParameters) getIdentifier() string {
	return sp.SecurityName
}

// getLogger returns the logger
func (sp *TsmSecurityParameters) getLogger() Logger {
	return sp.Logger
}

// setLogger sets the logger
func (sp *TsmSecurityParameters) setLogger(log Logger) {
	sp.Logger = log
}
