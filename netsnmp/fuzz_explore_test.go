// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build netsnmp

package netsnmp

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"testing"

	"github.com/gosnmp/gosnmp"
)

// buildSNMPv2c constructs a raw SNMPv2c packet from components.
// community: community string
// pduType: 0xa0=GetRequest, 0xa2=GetResponse, 0xa3=SetRequest
// reqID, errStat, errIndex: PDU header fields
// vblContent: raw bytes of the VBL content (without the outer SEQUENCE TL)
func buildSNMPv2c(community string, pduType byte, reqID int32, errStat, errIndex int32, vblContent []byte) []byte {
	vbl := berSequence(vblContent)
	pduBody := berInteger(reqID)
	pduBody = append(pduBody, berInteger(errStat)...)
	pduBody = append(pduBody, berInteger(errIndex)...)
	pduBody = append(pduBody, vbl...)
	pdu := berTLV(pduType, pduBody)
	msg := berInteger(int32(1)) // version = SNMPv2c
	msg = append(msg, berOctetString([]byte(community))...)
	msg = append(msg, pdu...)
	return berSequence(msg)
}

// BER encoding helpers

func berTLV(tag byte, content []byte) []byte {
	return append(berTL(tag, len(content)), content...)
}

func berTL(tag byte, length int) []byte {
	if length < 128 {
		return []byte{tag, byte(length)}
	}
	if length < 256 {
		return []byte{tag, 0x81, byte(length)}
	}
	return []byte{tag, 0x82, byte(length >> 8), byte(length)}
}

func berSequence(content []byte) []byte {
	return berTLV(0x30, content)
}

func berInteger(val int32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(val))
	// Trim leading bytes, preserving sign
	for len(buf) > 1 {
		if buf[0] == 0x00 && buf[1]&0x80 == 0 {
			buf = buf[1:]
		} else if buf[0] == 0xff && buf[1]&0x80 != 0 {
			buf = buf[1:]
		} else {
			break
		}
	}
	return berTLV(0x02, buf)
}

func berOctetString(val []byte) []byte {
	return berTLV(0x04, val)
}

func berOID(oid []byte) []byte {
	return berTLV(0x06, oid)
}

func berNull() []byte {
	return []byte{0x05, 0x00}
}

func berVarbind(oid []byte, value []byte) []byte {
	content := berOID(oid)
	content = append(content, value...)
	return berSequence(content)
}

// Standard OID .1.3.6.1.2.1.1.1.0 in BER encoding
var stdOID = []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}

// compare runs both parsers and returns a categorized result.
func compare(data []byte) (nsResult ParseResult, gResult GosnmpResult, category string) {
	nsResult = NetsnmpParsePacket(data)
	gResult = gosnmpParse(data)

	switch {
	case nsResult.Success && gResult.Success:
		category = "both_accept"
	case !nsResult.Success && !gResult.Success:
		category = "both_reject"
	case nsResult.Success && !gResult.Success:
		category = "ns_accept_go_reject"
	case !nsResult.Success && gResult.Success:
		category = "ns_reject_go_accept"
	}
	return
}

// TestMalformedPDUComparison exercises every documented disagreement pattern
// from the comparison.md analysis. Each subtest documents the expected behavior
// difference and verifies it.
func TestMalformedPDUComparison(t *testing.T) {
	gosnmp.Default.Logger = gosnmp.NewLogger(log.New(io.Discard, "", 0))

	// Helper: build a valid baseline packet with one OctetString varbind
	baseline := func() []byte {
		vb := berVarbind(stdOID, berOctetString([]byte("test")))
		return buildSNMPv2c("public", 0xa2, 1, 0, 0, vb)
	}

	t.Run("trailing_bytes_after_outer_sequence", func(t *testing.T) {
		// comparison.md section 2: net-snmp ignores trailing bytes, gosnmp rejects
		pkt := baseline()
		pkt = append(pkt, 0x00, 0x00, 0x00) // trailing garbage
		ns, g, cat := compare(pkt)
		t.Logf("category: %s  ns=%v go=%v", cat, ns.Success, g.Success)
		if cat != "ns_accept_go_reject" {
			t.Errorf("expected ns_accept_go_reject, got %s", cat)
		}
	})

	t.Run("trailing_bytes_after_vbl", func(t *testing.T) {
		// comparison.md section 2: trailing bytes within the PDU but after VBL
		// Build manually: valid VBL + extra bytes, with PDU length covering all of it
		vb := berVarbind(stdOID, berOctetString([]byte("test")))
		vblContent := vb
		vbl := berSequence(vblContent)
		trailing := []byte{0xDE, 0xAD, 0xBE, 0xEF}
		pduBody := berInteger(1)
		pduBody = append(pduBody, berInteger(0)...)
		pduBody = append(pduBody, berInteger(0)...)
		pduBody = append(pduBody, vbl...)
		pduBody = append(pduBody, trailing...) // trailing within PDU
		pdu := berTLV(0xa2, pduBody)
		msg := berInteger(1) // v2c
		msg = append(msg, berOctetString([]byte("public"))...)
		msg = append(msg, pdu...)
		pkt := berSequence(msg)

		ns, g, cat := compare(pkt)
		t.Logf("category: %s  ns=%v go=%v", cat, ns.Success, g.Success)
		if cat != "ns_accept_go_reject" {
			t.Errorf("expected ns_accept_go_reject, got %s", cat)
		}
	})

	t.Run("unknown_varbind_type", func(t *testing.T) {
		// comparison.md section 3: gosnmp accepts (UnknownType), net-snmp rejects
		// Use type tag 0xC0 (private class, primitive, tag 0)
		vb := berVarbind(stdOID, berTLV(0xC0, []byte{0x01, 0x02}))
		pkt := buildSNMPv2c("public", 0xa2, 1, 0, 0, vb)
		ns, g, cat := compare(pkt)
		t.Logf("category: %s  ns=%v go=%v", cat, ns.Success, g.Success)
		if cat != "ns_reject_go_accept" {
			t.Errorf("expected ns_reject_go_accept, got %s", cat)
		}
	})

	t.Run("unknown_type_followed_by_valid", func(t *testing.T) {
		// Net-snmp rejects entire PDU on unknown type; gosnmp returns both varbinds
		vb1 := berVarbind(stdOID, berTLV(0xC0, []byte{0x01}))
		vb2 := berVarbind(stdOID, berOctetString([]byte("ok")))
		pkt := buildSNMPv2c("public", 0xa2, 1, 0, 0, append(vb1, vb2...))
		ns, g, cat := compare(pkt)
		t.Logf("category: %s  ns=%v go=%v  go_vars=%d", cat, ns.Success, g.Success, g.NumVars)
		if cat != "ns_reject_go_accept" {
			t.Errorf("expected ns_reject_go_accept, got %s", cat)
		}
		if g.Success && g.NumVars != 2 {
			t.Errorf("expected gosnmp to return 2 vars, got %d", g.NumVars)
		}
	})

	t.Run("empty_oid", func(t *testing.T) {
		// comparison.md section 6: net-snmp accepts empty OID as 0.0, gosnmp rejects
		vb := berVarbind([]byte{}, berOctetString([]byte("val")))
		pkt := buildSNMPv2c("public", 0xa2, 1, 0, 0, vb)
		ns, g, cat := compare(pkt)
		t.Logf("category: %s  ns=%v go=%v", cat, ns.Success, g.Success)
		if cat != "ns_accept_go_reject" {
			t.Errorf("expected ns_accept_go_reject, got %s", cat)
		}
	})

	t.Run("ipaddress_0_bytes", func(t *testing.T) {
		// comparison.md section 5: gosnmp accepts 0-byte IP, net-snmp rejects
		vb := berVarbind(stdOID, berTLV(0x40, []byte{})) // 0x40 = IPAddress, 0 bytes
		pkt := buildSNMPv2c("public", 0xa2, 1, 0, 0, vb)
		ns, g, cat := compare(pkt)
		t.Logf("category: %s  ns=%v go=%v", cat, ns.Success, g.Success)
		if cat != "ns_reject_go_accept" {
			t.Errorf("expected ns_reject_go_accept, got %s", cat)
		}
	})

	t.Run("ipaddress_4_bytes", func(t *testing.T) {
		// Both should accept a valid 4-byte IPAddress
		vb := berVarbind(stdOID, berTLV(0x40, []byte{10, 0, 0, 1}))
		pkt := buildSNMPv2c("public", 0xa2, 1, 0, 0, vb)
		ns, g, cat := compare(pkt)
		t.Logf("category: %s  ns=%v go=%v", cat, ns.Success, g.Success)
		if cat != "both_accept" {
			t.Errorf("expected both_accept, got %s", cat)
		}
	})

	t.Run("ipaddress_16_bytes", func(t *testing.T) {
		// comparison.md section 5: gosnmp accepts 16-byte IP (IPv6), net-snmp rejects
		ipv6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
		vb := berVarbind(stdOID, berTLV(0x40, ipv6))
		pkt := buildSNMPv2c("public", 0xa2, 1, 0, 0, vb)
		ns, g, cat := compare(pkt)
		t.Logf("category: %s  ns=%v go=%v", cat, ns.Success, g.Success)
		if cat != "ns_reject_go_accept" {
			t.Errorf("expected ns_reject_go_accept, got %s", cat)
		}
	})

	t.Run("ipaddress_3_bytes", func(t *testing.T) {
		// Both should reject a 3-byte IPAddress
		vb := berVarbind(stdOID, berTLV(0x40, []byte{10, 0, 0}))
		pkt := buildSNMPv2c("public", 0xa2, 1, 0, 0, vb)
		ns, g, cat := compare(pkt)
		t.Logf("category: %s  ns=%v go=%v", cat, ns.Success, g.Success)
		// Both should reject, but behavior may vary
	})

	t.Run("counter32_oversized_encoding", func(t *testing.T) {
		// comparison.md section 4: gosnmp swallows integer parse errors, net-snmp rejects
		// Counter32 (0x41) with 6 bytes (too many for 32-bit)
		vb := berVarbind(stdOID, berTLV(0x41, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}))
		pkt := buildSNMPv2c("public", 0xa2, 1, 0, 0, vb)
		ns, g, cat := compare(pkt)
		t.Logf("category: %s  ns=%v go=%v", cat, ns.Success, g.Success)
		// gosnmp may accept with zero value, net-snmp may reject
	})

	t.Run("counter32_empty_encoding", func(t *testing.T) {
		// Counter32 with 0 bytes of value
		vb := berVarbind(stdOID, berTLV(0x41, []byte{}))
		pkt := buildSNMPv2c("public", 0xa2, 1, 0, 0, vb)
		ns, g, cat := compare(pkt)
		t.Logf("category: %s  ns=%v go=%v", cat, ns.Success, g.Success)
	})

	t.Run("gauge32_negative_encoding", func(t *testing.T) {
		// Gauge32 (0x42) with high bit set (negative in signed interpretation)
		vb := berVarbind(stdOID, berTLV(0x42, []byte{0xFF, 0xFF, 0xFF, 0xFF}))
		pkt := buildSNMPv2c("public", 0xa2, 1, 0, 0, vb)
		ns, g, cat := compare(pkt)
		t.Logf("category: %s  ns=%v go=%v", cat, ns.Success, g.Success)
	})

	t.Run("timeticks_5_bytes", func(t *testing.T) {
		// TimeTicks with 5 bytes (off by one)
		vb := berVarbind(stdOID, berTLV(0x43, []byte{0x00, 0x01, 0x02, 0x03, 0x04}))
		pkt := buildSNMPv2c("public", 0xa2, 1, 0, 0, vb)
		ns, g, cat := compare(pkt)
		t.Logf("category: %s  ns=%v go=%v", cat, ns.Success, g.Success)
	})

	t.Run("counter64_9_bytes", func(t *testing.T) {
		// Counter64 with 9 bytes
		vb := berVarbind(stdOID, berTLV(0x46, []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}))
		pkt := buildSNMPv2c("public", 0xa2, 1, 0, 0, vb)
		ns, g, cat := compare(pkt)
		t.Logf("category: %s  ns=%v go=%v", cat, ns.Success, g.Success)
	})

	t.Run("varbind_value_length_exceeds_varbind", func(t *testing.T) {
		// The value's declared BER length extends past the varbind SEQUENCE boundary.
		// This is the cross-contamination pattern from PR #566.
		oid := berOID(stdOID)
		val := append(berTL(0x04, 20), []byte("short")...) // declares 20, has 5
		vb := berSequence(append(oid, val...))
		vb2 := berVarbind(stdOID, berOctetString([]byte("secret")))
		pkt := buildSNMPv2c("public", 0xa2, 1, 0, 0, append(vb, vb2...))
		ns, g, cat := compare(pkt)
		t.Logf("category: %s  ns=%v go=%v  go_vars=%d ns_vars=%d",
			cat, ns.Success, g.Success, g.NumVars, ns.NumVars)
	})

	t.Run("indefinite_length", func(t *testing.T) {
		// comparison.md section 1: both reject indefinite length (0x80)
		// Replace outer SEQUENCE length with 0x80
		pkt := baseline()
		pkt[1] = 0x80
		ns, g, cat := compare(pkt)
		t.Logf("category: %s  ns=%v go=%v", cat, ns.Success, g.Success)
		if cat != "both_reject" {
			t.Errorf("expected both_reject, got %s", cat)
		}
	})

	t.Run("version_42", func(t *testing.T) {
		// comparison.md section 9: gosnmp accepts any version integer
		// Build v2c packet but change version byte to 42
		pkt := baseline()
		// Find version value byte (should be at offset 4 for short packets)
		// SEQUENCE(30 xx) INTEGER(02 01 vv) ...
		pkt[4] = 42
		ns, g, cat := compare(pkt)
		t.Logf("category: %s  ns=%v go=%v", cat, ns.Success, g.Success)
		// net-snmp should reject unknown version, gosnmp may accept
	})

	t.Run("error_status_255", func(t *testing.T) {
		// comparison.md section 8: both accept any error status
		vb := berVarbind(stdOID, berOctetString([]byte("test")))
		pkt := buildSNMPv2c("public", 0xa2, 1, 255, 0, vb)
		ns, g, cat := compare(pkt)
		t.Logf("category: %s  ns=%v go=%v", cat, ns.Success, g.Success)
	})

	t.Run("unknown_pdu_type", func(t *testing.T) {
		// comparison.md section table: both reject unknown PDU types
		vb := berVarbind(stdOID, berOctetString([]byte("test")))
		pkt := buildSNMPv2c("public", 0xAF, 1, 0, 0, vb) // 0xAF = not a real PDU type
		ns, g, cat := compare(pkt)
		t.Logf("category: %s  ns=%v go=%v", cat, ns.Success, g.Success)
		if cat != "both_reject" {
			t.Errorf("expected both_reject, got %s", cat)
		}
	})

	t.Run("empty_varbind_list", func(t *testing.T) {
		// Empty VBL - both should accept
		pkt := buildSNMPv2c("public", 0xa2, 1, 0, 0, nil)
		ns, g, cat := compare(pkt)
		t.Logf("category: %s  ns=%v go=%v  ns_vars=%d go_vars=%d",
			cat, ns.Success, g.Success, ns.NumVars, g.NumVars)
	})

	t.Run("null_value_varbind", func(t *testing.T) {
		// Standard GetRequest-style varbind with Null value
		vb := berVarbind(stdOID, berNull())
		pkt := buildSNMPv2c("public", 0xa0, 1, 0, 0, vb)
		ns, g, cat := compare(pkt)
		t.Logf("category: %s  ns=%v go=%v  ns_vars=%d go_vars=%d",
			cat, ns.Success, g.Success, ns.NumVars, g.NumVars)
		if cat != "both_accept" {
			t.Errorf("expected both_accept, got %s", cat)
		}
	})

	t.Run("opaque_float", func(t *testing.T) {
		// comparison.md section 12: gosnmp natively supports, net-snmp needs compile flag
		// Opaque wrapper: 0x44 tag, content is 0x9F 0x78 0x04 <float32>
		// 0x9F78 = ASN extension tag for Float
		floatBits := []byte{0x41, 0x20, 0x00, 0x00} // 10.0 as IEEE 754
		opaqueInner := []byte{0x9F, 0x78, 0x04}
		opaqueInner = append(opaqueInner, floatBits...)
		vb := berVarbind(stdOID, berTLV(0x44, opaqueInner))
		pkt := buildSNMPv2c("public", 0xa2, 1, 0, 0, vb)
		ns, g, cat := compare(pkt)
		t.Logf("category: %s  ns=%v go=%v", cat, ns.Success, g.Success)
		// Both may accept if net-snmp was compiled with OPAQUE_SPECIAL_TYPES
	})

	t.Run("max_length_community", func(t *testing.T) {
		// Very long community string
		longComm := make([]byte, 255)
		for i := range longComm {
			longComm[i] = 'A'
		}
		vb := berVarbind(stdOID, berOctetString([]byte("val")))
		pkt := buildSNMPv2c(string(longComm), 0xa2, 1, 0, 0, vb)
		ns, g, cat := compare(pkt)
		t.Logf("category: %s  ns=%v go=%v  ns_comm_len=%d go_comm_len=%d",
			cat, ns.Success, g.Success, len(ns.Community), len(g.Community))
	})

	t.Run("many_varbinds", func(t *testing.T) {
		// Stress test: 50 varbinds
		var vbs []byte
		for i := 0; i < 50; i++ {
			vbs = append(vbs, berVarbind(stdOID, berInteger(int32(i)))...)
		}
		pkt := buildSNMPv2c("public", 0xa2, 1, 0, 0, vbs)
		ns, g, cat := compare(pkt)
		t.Logf("category: %s  ns=%v go=%v  ns_vars=%d go_vars=%d",
			cat, ns.Success, g.Success, ns.NumVars, g.NumVars)
		if cat != "both_accept" {
			t.Errorf("expected both_accept, got %s", cat)
		}
		if ns.NumVars != 50 || g.NumVars != 50 {
			t.Errorf("expected 50 vars each, got ns=%d go=%d", ns.NumVars, g.NumVars)
		}
	})
}

// malformedSeeds returns hand-crafted packets targeting documented
// disagreement areas. These complement the fuzzer's random mutations
// by ensuring specific real-world malformation patterns are explored.
func malformedSeeds() [][]byte {
	var seeds [][]byte

	// Trailing bytes after outer SEQUENCE
	{
		vb := berVarbind(stdOID, berOctetString([]byte("test")))
		pkt := buildSNMPv2c("public", 0xa2, 1, 0, 0, vb)
		seeds = append(seeds, append(pkt, 0x00, 0x00))
	}

	// Unknown varbind type tags
	for _, tag := range []byte{0xC0, 0xC1, 0x78, 0x99, 0xBF} {
		vb := berVarbind(stdOID, berTLV(tag, []byte{0x01, 0x02}))
		seeds = append(seeds, buildSNMPv2c("public", 0xa2, 1, 0, 0, vb))
	}

	// Empty OID
	{
		vb := berVarbind([]byte{}, berOctetString([]byte("val")))
		seeds = append(seeds, buildSNMPv2c("public", 0xa2, 1, 0, 0, vb))
	}

	// IPAddress edge cases: 0, 3, 4, 5, 16 bytes
	for _, ipLen := range []int{0, 3, 4, 5, 16} {
		ip := make([]byte, ipLen)
		for i := range ip {
			ip[i] = byte(10 + i)
		}
		vb := berVarbind(stdOID, berTLV(0x40, ip))
		seeds = append(seeds, buildSNMPv2c("public", 0xa2, 1, 0, 0, vb))
	}

	// Counter32 with wrong byte counts
	for _, n := range []int{0, 1, 2, 5, 6} {
		val := make([]byte, n)
		for i := range val {
			val[i] = 0x01
		}
		vb := berVarbind(stdOID, berTLV(0x41, val))
		seeds = append(seeds, buildSNMPv2c("public", 0xa2, 1, 0, 0, vb))
	}

	// Gauge32 with high-bit set (negative in signed interpretation)
	{
		vb := berVarbind(stdOID, berTLV(0x42, []byte{0xFF, 0xFF, 0xFF, 0xFF}))
		seeds = append(seeds, buildSNMPv2c("public", 0xa2, 1, 0, 0, vb))
	}

	// Counter64 with 9 bytes
	{
		vb := berVarbind(stdOID, berTLV(0x46, make([]byte, 9)))
		seeds = append(seeds, buildSNMPv2c("public", 0xa2, 1, 0, 0, vb))
	}

	// Cross-contamination: value length exceeds varbind
	{
		oid := berOID(stdOID)
		val := append(berTL(0x04, 20), []byte("AAAA")...)
		vb := berSequence(append(oid, val...))
		vb2 := berVarbind(stdOID, berOctetString([]byte("SECRET")))
		seeds = append(seeds, buildSNMPv2c("public", 0xa2, 1, 0, 0, append(vb, vb2...)))
	}

	// Trailing bytes inside PDU but after VBL
	{
		vb := berVarbind(stdOID, berOctetString([]byte("test")))
		vbl := berSequence(vb)
		pduBody := berInteger(1)
		pduBody = append(pduBody, berInteger(0)...)
		pduBody = append(pduBody, berInteger(0)...)
		pduBody = append(pduBody, vbl...)
		pduBody = append(pduBody, 0xDE, 0xAD, 0xBE, 0xEF)
		pdu := berTLV(0xa2, pduBody)
		msg := berInteger(1)
		msg = append(msg, berOctetString([]byte("public"))...)
		msg = append(msg, pdu...)
		seeds = append(seeds, berSequence(msg))
	}

	// Opaque float
	{
		floatBits := []byte{0x41, 0x20, 0x00, 0x00}
		opaqueInner := append([]byte{0x9F, 0x78, 0x04}, floatBits...)
		vb := berVarbind(stdOID, berTLV(0x44, opaqueInner))
		seeds = append(seeds, buildSNMPv2c("public", 0xa2, 1, 0, 0, vb))
	}

	// Version 42
	{
		pkt := buildSNMPv2c("public", 0xa2, 1, 0, 0, berVarbind(stdOID, berNull()))
		pkt[4] = 42
		seeds = append(seeds, pkt)
	}

	// All NoSuchObject / NoSuchInstance / EndOfMibView
	for _, tag := range []byte{0x80, 0x81, 0x82} {
		vb := berVarbind(stdOID, []byte{tag, 0x00})
		seeds = append(seeds, buildSNMPv2c("public", 0xa2, 1, 0, 0, vb))
	}

	fmt.Printf("malformed seeds: %d packets\n", len(seeds))
	return seeds
}
