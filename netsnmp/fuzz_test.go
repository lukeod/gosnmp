// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build netsnmp

package netsnmp

import (
	"fmt"
	"io"
	"log"
	"testing"

	"github.com/gosnmp/gosnmp"
)

// GosnmpResult holds parsed fields from a gosnmp packet parse.
type GosnmpResult struct {
	Success   bool
	Version   int
	Community string
	PDUType   int
	NumVars   int
	VarTypes  []byte
}

// gosnmpParse parses raw SNMP packet bytes using gosnmp.
func gosnmpParse(data []byte) GosnmpResult {
	g := &gosnmp.GoSNMP{}
	g.Logger = gosnmp.NewLogger(log.New(io.Discard, "", 0))
	g.Version = gosnmp.Version2c

	pkt, err := g.SnmpDecodePacket(data)
	if err != nil {
		return GosnmpResult{}
	}

	ver := 0
	switch pkt.Version {
	case gosnmp.Version1:
		ver = 0
	case gosnmp.Version2c:
		ver = 1
	case gosnmp.Version3:
		ver = 3
	}

	var varTypes []byte
	for _, v := range pkt.Variables {
		varTypes = append(varTypes, byte(v.Type))
	}

	return GosnmpResult{
		Success:   true,
		Version:   ver,
		Community: pkt.Community,
		PDUType:   int(pkt.PDUType),
		NumVars:   len(pkt.Variables),
		VarTypes:  varTypes,
	}
}

// TestParseAgreement verifies that both parsers agree on a known-good packet.
func TestParseAgreement(t *testing.T) {
	// Build a valid SNMPv2c GetResponse packet using gosnmp's marshaling
	sess := gosnmp.Default
	sess.Version = gosnmp.Version2c
	sess.Community = "public"
	sess.Logger = gosnmp.NewLogger(log.New(io.Discard, "", 0))

	pdus := []gosnmp.SnmpPDU{
		{
			Name:  ".1.3.6.1.2.1.1.1.0",
			Type:  gosnmp.OctetString,
			Value: []byte("test system"),
		},
		{
			Name:  ".1.3.6.1.2.1.1.3.0",
			Type:  gosnmp.TimeTicks,
			Value: uint32(12345),
		},
	}

	pkt := sess.MkSnmpPacket(gosnmp.GetResponse, pdus, 0, 0)
	pkt.RequestID = 42

	raw, err := pkt.MarshalMsg()
	if err != nil {
		t.Fatalf("MarshalMsg: %v", err)
	}

	t.Logf("packet (%d bytes): %x", len(raw), raw)

	// Parse with net-snmp
	nsResult := NetsnmpParsePacket(raw)
	t.Logf("net-snmp: success=%v version=%d community=%q pduType=0x%x reqid=%d vars=%d",
		nsResult.Success, nsResult.Version, nsResult.Community,
		nsResult.PDUType, nsResult.RequestID, nsResult.NumVars)

	// Parse with gosnmp
	gResult := gosnmpParse(raw)
	t.Logf("gosnmp:   success=%v version=%d community=%q pduType=0x%x vars=%d",
		gResult.Success, gResult.Version, gResult.Community, gResult.PDUType, gResult.NumVars)

	if !nsResult.Success {
		t.Fatal("net-snmp failed to parse a gosnmp-generated packet")
	}
	if !gResult.Success {
		t.Fatal("gosnmp failed to parse its own packet")
	}

	if nsResult.Version != gResult.Version {
		t.Errorf("version mismatch: netsnmp=%d gosnmp=%d", nsResult.Version, gResult.Version)
	}
	if nsResult.Community != gResult.Community {
		t.Errorf("community mismatch: netsnmp=%q gosnmp=%q", nsResult.Community, gResult.Community)
	}
	if nsResult.NumVars != gResult.NumVars {
		t.Errorf("varbind count mismatch: netsnmp=%d gosnmp=%d", nsResult.NumVars, gResult.NumVars)
	}
}

// FuzzDifferentialParse is the differential fuzz target.
// It feeds the same bytes to both gosnmp and net-snmp and checks for
// disagreements on parse success and basic structure.
func FuzzDifferentialParse(f *testing.F) {
	// Seed with valid packets built by gosnmp
	for _, seed := range differentialSeeds() {
		f.Add(seed)
	}
	// Seed with malformed packets targeting documented disagreement areas
	for _, seed := range malformedSeeds() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		nsResult := NetsnmpParsePacket(data)
		gResult := gosnmpParse(data)

		// Case 1: net-snmp rejects, gosnmp accepts
		if !nsResult.Success && gResult.Success {
			// gosnmp may be too permissive. Interesting but not a hard failure.
			return
		}

		// Case 2: both reject - nothing to compare
		if !nsResult.Success && !gResult.Success {
			return
		}

		// Case 3: net-snmp accepts, gosnmp rejects
		if nsResult.Success && !gResult.Success {
			// gosnmp may be too strict. Interesting but not a hard failure.
			return
		}

		// Case 4: both accept - compare parsed fields
		if nsResult.Version != gResult.Version {
			t.Errorf("version mismatch: netsnmp=%d gosnmp=%d packet=%x",
				nsResult.Version, gResult.Version, data)
		}
		if nsResult.Community != gResult.Community {
			t.Errorf("community mismatch: netsnmp=%q gosnmp=%q packet=%x",
				nsResult.Community, gResult.Community, data)
		}
		if nsResult.NumVars != gResult.NumVars {
			t.Errorf("varbind count mismatch: netsnmp=%d gosnmp=%d packet=%x",
				nsResult.NumVars, gResult.NumVars, data)
		}
		// Compare per-varbind types
		minVars := nsResult.NumVars
		if gResult.NumVars < minVars {
			minVars = gResult.NumVars
		}
		for i := 0; i < minVars; i++ {
			nsType := nsResult.VarTypes[i]
			gType := gResult.VarTypes[i]
			if nsType == gType {
				continue
			}
			// gosnmp maps unrecognized types to UnknownType (0x00).
			// net-snmp preserves the original type byte. Skip this
			// known difference to find more interesting mismatches.
			if gType == 0x00 {
				continue
			}
			t.Errorf("varbind[%d] type mismatch: netsnmp=0x%02x gosnmp=0x%02x packet=%x",
				i, nsType, gType, data)
		}
	})
}

// differentialSeeds builds a set of valid SNMP packets to seed the fuzzer.
func differentialSeeds() [][]byte {
	logger := gosnmp.NewLogger(log.New(io.Discard, "", 0))
	var seeds [][]byte

	for _, ver := range []gosnmp.SnmpVersion{gosnmp.Version1, gosnmp.Version2c} {
		for _, pduType := range []gosnmp.PDUType{gosnmp.GetRequest, gosnmp.GetResponse, gosnmp.SetRequest, gosnmp.GetNextRequest} {
			sess := &gosnmp.GoSNMP{
				Version:   ver,
				Community: "public",
				Logger:    logger,
			}

			pdus := []gosnmp.SnmpPDU{
				{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.OctetString, Value: []byte("test")},
				{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(100)},
				{Name: ".1.3.6.1.2.1.1.7.0", Type: gosnmp.Integer, Value: 42},
			}

			pkt := sess.MkSnmpPacket(pduType, pdus, 0, 0)
			pkt.RequestID = 1

			raw, err := pkt.MarshalMsg()
			if err != nil {
				continue
			}
			seeds = append(seeds, raw)
		}
	}

	// Also seed with single-varbind packets for each type
	sess := &gosnmp.GoSNMP{
		Version:   gosnmp.Version2c,
		Community: "public",
		Logger:    logger,
	}
	typedPDUs := []gosnmp.SnmpPDU{
		{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.Integer, Value: 104},
		{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.Counter32, Value: uint32(271070065)},
		{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.Gauge32, Value: uint32(100)},
		{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.OctetString, Value: []byte("hello world")},
		{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.IPAddress, Value: "10.0.0.1"},
		{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.TimeTicks, Value: uint32(318870100)},
		{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.Counter64, Value: uint64(1234567890)},
		{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.Null, Value: nil},
	}
	for _, pdu := range typedPDUs {
		pkt := sess.MkSnmpPacket(gosnmp.SetRequest, []gosnmp.SnmpPDU{pdu}, 0, 0)
		pkt.RequestID = 1
		raw, err := pkt.MarshalMsg()
		if err != nil {
			continue
		}
		seeds = append(seeds, raw)
	}

	// Seed with some minimal/edge-case raw packets
	seeds = append(seeds,
		// Minimal valid-ish v2c GetRequest with empty varbind list
		[]byte{0x30, 0x1a, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x0d, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x02, 0x30, 0x00},
	)

	fmt.Printf("differential fuzz: %d seed packets\n", len(seeds))
	return seeds
}
