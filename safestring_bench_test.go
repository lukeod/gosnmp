package gosnmp

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// Optimized SafeString using strings.Builder for SnmpPacket
func (packet *SnmpPacket) safeStringBuilder() string {
	var b strings.Builder
	b.Grow(512) // pre-allocate

	b.WriteString("Version:")
	b.WriteString(packet.Version.String())
	b.WriteString(", MsgFlags:")
	b.WriteString(packet.MsgFlags.String())
	b.WriteString(", SecurityModel:")
	b.WriteString(packet.SecurityModel.String())
	b.WriteString(", SecurityParameters:")
	if packet.SecurityParameters != nil {
		b.WriteString(packet.SecurityParameters.SafeString())
	}
	b.WriteString(", ContextEngineID:")
	b.WriteString(packet.ContextEngineID)
	b.WriteString(", ContextName:")
	b.WriteString(packet.ContextName)
	b.WriteString(", Community:")
	b.WriteString(packet.Community)
	b.WriteString(", PDUType:")
	b.WriteString(packet.PDUType.String())
	b.WriteString(", MsgID:")
	b.WriteString(strconv.FormatUint(uint64(packet.MsgID), 10))
	b.WriteString(", RequestID:")
	b.WriteString(strconv.FormatUint(uint64(packet.RequestID), 10))
	b.WriteString(", MsgMaxSize:")
	b.WriteString(strconv.FormatUint(uint64(packet.MsgMaxSize), 10))
	b.WriteString(", Error:")
	b.WriteString(packet.Error.String())
	b.WriteString(", ErrorIndex:")
	b.WriteString(strconv.FormatUint(uint64(packet.ErrorIndex), 10))
	b.WriteString(", NonRepeaters:")
	b.WriteString(strconv.FormatUint(uint64(packet.NonRepeaters), 10))
	b.WriteString(", MaxRepetitions:")
	b.WriteString(strconv.FormatUint(uint64(packet.MaxRepetitions), 10))
	b.WriteString(", Variables:")
	fmt.Fprintf(&b, "%v", packet.Variables)

	return b.String()
}

// Version without Grow - minimal memory
func (packet *SnmpPacket) safeStringBuilderNoGrow() string {
	var b strings.Builder

	b.WriteString("Version:")
	b.WriteString(packet.Version.String())
	b.WriteString(", MsgFlags:")
	b.WriteString(packet.MsgFlags.String())
	b.WriteString(", SecurityModel:")
	b.WriteString(packet.SecurityModel.String())
	b.WriteString(", SecurityParameters:")
	if packet.SecurityParameters != nil {
		b.WriteString(packet.SecurityParameters.SafeString())
	}
	b.WriteString(", ContextEngineID:")
	b.WriteString(packet.ContextEngineID)
	b.WriteString(", ContextName:")
	b.WriteString(packet.ContextName)
	b.WriteString(", Community:")
	b.WriteString(packet.Community)
	b.WriteString(", PDUType:")
	b.WriteString(packet.PDUType.String())
	b.WriteString(", MsgID:")
	b.WriteString(strconv.FormatUint(uint64(packet.MsgID), 10))
	b.WriteString(", RequestID:")
	b.WriteString(strconv.FormatUint(uint64(packet.RequestID), 10))
	b.WriteString(", MsgMaxSize:")
	b.WriteString(strconv.FormatUint(uint64(packet.MsgMaxSize), 10))
	b.WriteString(", Error:")
	b.WriteString(packet.Error.String())
	b.WriteString(", ErrorIndex:")
	b.WriteString(strconv.FormatUint(uint64(packet.ErrorIndex), 10))
	b.WriteString(", NonRepeaters:")
	b.WriteString(strconv.FormatUint(uint64(packet.NonRepeaters), 10))
	b.WriteString(", MaxRepetitions:")
	b.WriteString(strconv.FormatUint(uint64(packet.MaxRepetitions), 10))
	b.WriteString(", Variables:")
	fmt.Fprintf(&b, "%v", packet.Variables)

	return b.String()
}

// Optimized SafeString using strings.Builder for UsmSecurityParameters
func (sp *UsmSecurityParameters) safeStringBuilder() string {
	var b strings.Builder
	b.Grow(256)

	b.WriteString("AuthoritativeEngineID:")
	b.WriteString(sp.AuthoritativeEngineID)
	b.WriteString(", AuthoritativeEngineBoots:")
	b.WriteString(strconv.FormatUint(uint64(sp.AuthoritativeEngineBoots), 10))
	b.WriteString(", AuthoritativeEngineTimes:")
	b.WriteString(strconv.FormatUint(uint64(sp.AuthoritativeEngineTime), 10))
	b.WriteString(", UserName:")
	b.WriteString(sp.UserName)
	b.WriteString(", AuthenticationParameters:")
	b.WriteString(sp.AuthenticationParameters)
	b.WriteString(", PrivacyParameters:")
	fmt.Fprintf(&b, "%v", sp.PrivacyParameters)
	b.WriteString(", AuthenticationProtocol:")
	b.WriteString(sp.AuthenticationProtocol.String())
	b.WriteString(", PrivacyProtocol:")
	b.WriteString(sp.PrivacyProtocol.String())

	return b.String()
}

// Version that avoids fmt entirely by formatting []byte manually
func (sp *UsmSecurityParameters) safeStringBuilderNoFmt() string {
	var b strings.Builder
	b.Grow(256)

	b.WriteString("AuthoritativeEngineID:")
	b.WriteString(sp.AuthoritativeEngineID)
	b.WriteString(", AuthoritativeEngineBoots:")
	b.WriteString(strconv.FormatUint(uint64(sp.AuthoritativeEngineBoots), 10))
	b.WriteString(", AuthoritativeEngineTimes:")
	b.WriteString(strconv.FormatUint(uint64(sp.AuthoritativeEngineTime), 10))
	b.WriteString(", UserName:")
	b.WriteString(sp.UserName)
	b.WriteString(", AuthenticationParameters:")
	b.WriteString(sp.AuthenticationParameters)
	b.WriteString(", PrivacyParameters:[")
	for i, v := range sp.PrivacyParameters {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	}
	b.WriteString("], AuthenticationProtocol:")
	b.WriteString(sp.AuthenticationProtocol.String())
	b.WriteString(", PrivacyProtocol:")
	b.WriteString(sp.PrivacyProtocol.String())

	return b.String()
}

func createTestPacket() *SnmpPacket {
	return &SnmpPacket{
		Version:       Version3,
		MsgFlags:      AuthPriv,
		SecurityModel: UserSecurityModel,
		SecurityParameters: &UsmSecurityParameters{
			AuthoritativeEngineID:    "80001234567890",
			AuthoritativeEngineBoots: 12345,
			AuthoritativeEngineTime:  67890,
			UserName:                 "testuser",
			AuthenticationParameters: "authparams",
			PrivacyParameters:        []byte{0x01, 0x02, 0x03, 0x04},
			AuthenticationProtocol:   SHA,
			PrivacyProtocol:          AES,
		},
		ContextEngineID: "contextengine123",
		ContextName:     "contextname",
		Community:       "public",
		PDUType:         GetRequest,
		MsgID:           12345,
		RequestID:       67890,
		MsgMaxSize:      65535,
		Error:           NoError,
		ErrorIndex:      0,
		NonRepeaters:    0,
		MaxRepetitions:  10,
		Variables: []SnmpPDU{
			{Name: ".1.3.6.1.2.1.1.1.0", Type: OctetString, Value: "test value"},
			{Name: ".1.3.6.1.2.1.1.3.0", Type: TimeTicks, Value: uint32(12345)},
		},
	}
}

func createTestSecurityParams() *UsmSecurityParameters {
	return &UsmSecurityParameters{
		AuthoritativeEngineID:    "80001234567890",
		AuthoritativeEngineBoots: 12345,
		AuthoritativeEngineTime:  67890,
		UserName:                 "testuser",
		AuthenticationParameters: "authparams",
		PrivacyParameters:        []byte{0x01, 0x02, 0x03, 0x04},
		AuthenticationProtocol:   SHA,
		PrivacyProtocol:          AES,
	}
}

// Benchmarks for SnmpPacket.SafeString
func BenchmarkSnmpPacketSafeString_Current(b *testing.B) {
	packet := createTestPacket()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = packet.SafeString()
	}
}

func BenchmarkSnmpPacketSafeString_Builder(b *testing.B) {
	packet := createTestPacket()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = packet.safeStringBuilder()
	}
}

func BenchmarkSnmpPacketSafeString_BuilderNoGrow(b *testing.B) {
	packet := createTestPacket()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = packet.safeStringBuilderNoGrow()
	}
}

// Benchmarks for UsmSecurityParameters.SafeString
func BenchmarkUsmSecurityParamsSafeString_Current(b *testing.B) {
	sp := createTestSecurityParams()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sp.SafeString()
	}
}

func BenchmarkUsmSecurityParamsSafeString_Builder(b *testing.B) {
	sp := createTestSecurityParams()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sp.safeStringBuilder()
	}
}

func BenchmarkUsmSecurityParamsSafeString_BuilderNoFmt(b *testing.B) {
	sp := createTestSecurityParams()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sp.safeStringBuilderNoFmt()
	}
}

// Test that both implementations produce equivalent output
func TestSafeStringEquivalence(t *testing.T) {
	packet := createTestPacket()
	current := packet.SafeString()
	builder := packet.safeStringBuilder()

	if current != builder {
		t.Errorf("SnmpPacket outputs differ:\nCurrent: %s\nBuilder: %s", current, builder)
	}

	sp := createTestSecurityParams()
	currentSp := sp.SafeString()
	builderSp := sp.safeStringBuilder()

	if currentSp != builderSp {
		t.Errorf("UsmSecurityParameters outputs differ:\nCurrent: %s\nBuilder: %s", currentSp, builderSp)
	}
}
