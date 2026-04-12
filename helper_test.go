// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build all || helper

package gosnmp

import (
	"encoding/base64"
	"io"
	"log"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// https://www.scadacore.com/tools/programming-calculators/online-hex-converter/ is useful

func TestParseObjectIdentifier(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    string
		wantErr error
	}{
		// First byte encoding: first two sub-identifiers encoded as (x*40 + y)
		// where x is first sub-id (0, 1, or 2) and y is second sub-id
		{
			name: "iso.org (1.3)",
			data: []byte{43}, // 1*40 + 3 = 43
			want: ".1.3",
		},
		{
			name: "iso.member-body (1.2)",
			data: []byte{42}, // 1*40 + 2 = 42
			want: ".1.2",
		},
		{
			name: "joint-iso-itu-t (2.0)",
			data: []byte{80}, // 2*40 + 0 = 80
			want: ".2.0",
		},
		{
			name: "itu-t (0.0)",
			data: []byte{0}, // 0*40 + 0 = 0
			want: ".0.0",
		},
		{
			name: "first byte max second sub-id (0.39)",
			data: []byte{39}, // 0*40 + 39 = 39
			want: ".0.39",
		},
		{
			name: "first byte boundary (1.0)",
			data: []byte{40}, // 1*40 + 0 = 40
			want: ".1.0",
		},
		// Multi-byte first sub-identifier (X.690 8.19.5)
		{
			name: "joint-iso-itu-t 2.999 (X.690 example)",
			data: []byte{0x88, 0x37, 0x03}, // first sub-id 1079 = 2*40+999, then arc 3
			want: ".2.999.3",
		},
		{
			name: "joint-iso-itu-t 2.40",
			data: []byte{0x81, 0x00}, // first sub-id 128 = 2*40+48
			want: ".2.48",
		},
		{
			name: "joint-iso-itu-t 2.100 (stdlib test vector)",
			data: []byte{0x81, 0x34, 0x03}, // first sub-id 180 = 2*40+100, then arc 3
			want: ".2.100.3",
		},
		// Standard OIDs
		{
			name: "sysDescr (1.3.6.1.2.1.1.1)",
			data: []byte{43, 6, 1, 2, 1, 1, 1},
			want: ".1.3.6.1.2.1.1.1",
		},
		{
			name: "ifTable (1.3.6.1.2.1.2.2)",
			data: []byte{43, 6, 1, 2, 1, 2, 2},
			want: ".1.3.6.1.2.1.2.2",
		},
		{
			name: "enterprises (1.3.6.1.4.1)",
			data: []byte{43, 6, 1, 4, 1},
			want: ".1.3.6.1.4.1",
		},
		// Multi-byte sub-identifiers
		{
			name: "two-byte sub-id (128)",
			data: []byte{43, 0x81, 0x00}, // .1.3.128
			want: ".1.3.128",
		},
		{
			name: "two-byte sub-id (255)",
			data: []byte{43, 0x81, 0x7F}, // .1.3.255
			want: ".1.3.255",
		},
		{
			name: "three-byte sub-id (16384)",
			data: []byte{43, 0x81, 0x80, 0x00}, // .1.3.16384
			want: ".1.3.16384",
		},
		{
			name: "max uint32 sub-id (4294967295)",
			data: []byte{43, 0x8F, 0xFF, 0xFF, 0xFF, 0x7F},
			want: ".1.3.4294967295",
		},
		{
			name: "mixed sub-id sizes",
			data: []byte{43, 6, 1, 2, 1, 31, 1, 1, 1, 10, 0x8F, 0xFF, 0xFF, 0xFF, 0x7F},
			want: ".1.3.6.1.2.1.31.1.1.1.10.4294967295",
		},
		// Error cases
		{
			name:    "empty input",
			data:    []byte{},
			want:    "",
			wantErr: ErrInvalidOidLength,
		},
		{
			name:    "overflow sub-id (4294967296)",
			data:    []byte{43, 0x90, 0x80, 0x80, 0x80, 0x00},
			want:    "",
			wantErr: ErrBase128IntegerTooLarge,
		},
		{
			name:    "truncated first sub-id",
			data:    []byte{0x80}, // continuation byte as only byte
			want:    "",
			wantErr: ErrBase128IntegerTruncated,
		},
		{
			name:    "truncated multi-byte sub-id",
			data:    []byte{43, 0x81}, // continuation byte without termination
			want:    "",
			wantErr: ErrBase128IntegerTruncated,
		},
		{
			name:    "truncated mid-sequence",
			data:    []byte{43, 6, 0x81, 0x82}, // two continuation bytes
			want:    "",
			wantErr: ErrBase128IntegerTruncated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseObjectIdentifier(tt.data)
			if err != tt.wantErr {
				t.Errorf("parseObjectIdentifier() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseObjectIdentifier() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseBase128Uint32(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		initOffset int
		want       uint32
		wantOffset int
		wantErr    error
	}{
		// Single byte values (0-127)
		{
			name:       "zero",
			data:       []byte{0x00},
			want:       0,
			wantOffset: 1,
		},
		{
			name:       "one",
			data:       []byte{0x01},
			want:       1,
			wantOffset: 1,
		},
		{
			name:       "max single byte (127)",
			data:       []byte{0x7F},
			want:       127,
			wantOffset: 1,
		},
		// Two byte values (128-16383)
		{
			name:       "min two byte (128)",
			data:       []byte{0x81, 0x00},
			want:       128,
			wantOffset: 2,
		},
		{
			name:       "two byte value 300",
			data:       []byte{0x82, 0x2C}, // 2*128 + 44 = 300
			want:       300,
			wantOffset: 2,
		},
		{
			name:       "max two byte (16383)",
			data:       []byte{0xFF, 0x7F}, // 127*128 + 127 = 16383
			want:       16383,
			wantOffset: 2,
		},
		// Three byte values
		{
			name:       "min three byte (16384)",
			data:       []byte{0x81, 0x80, 0x00},
			want:       16384,
			wantOffset: 3,
		},
		// Four byte values
		{
			name:       "four byte value",
			data:       []byte{0x81, 0x80, 0x80, 0x00}, // 2097152
			want:       2097152,
			wantOffset: 4,
		},
		// Five byte values - boundary cases
		{
			name:       "max uint32 (4294967295)",
			data:       []byte{0x8F, 0xFF, 0xFF, 0xFF, 0x7F},
			want:       4294967295,
			wantOffset: 5,
		},
		// Overflow cases
		{
			name:    "overflow - uint32 max + 1 (4294967296)",
			data:    []byte{0x90, 0x80, 0x80, 0x80, 0x00},
			want:    0,
			wantErr: ErrBase128IntegerTooLarge,
		},
		{
			name:    "overflow - 6 bytes (exceeds max base128 length for uint32)",
			data:    []byte{0x81, 0x80, 0x80, 0x80, 0x80, 0x00},
			want:    0,
			wantErr: ErrBase128IntegerTooLarge,
		},
		// Truncation cases
		{
			name:    "truncated - single continuation byte",
			data:    []byte{0x80},
			want:    0,
			wantErr: ErrBase128IntegerTruncated,
		},
		{
			name:    "truncated - multiple continuation bytes",
			data:    []byte{0x81, 0x82, 0x83},
			want:    0,
			wantErr: ErrBase128IntegerTruncated,
		},
		{
			name:    "truncated - empty input",
			data:    []byte{},
			want:    0,
			wantErr: ErrBase128IntegerTruncated,
		},
		// Non-minimal encoding (accepted per permissive parsing)
		{
			name:       "non-minimal encoding of 1",
			data:       []byte{0x80, 0x01}, // could be just 0x01
			want:       1,
			wantOffset: 2,
		},
		// Offset handling
		{
			name:       "value with trailing data",
			data:       []byte{0x7F, 0x99, 0x99}, // 127 followed by garbage
			want:       127,
			wantOffset: 1, // should stop after first byte
		},
		{
			name:       "parse from middle of slice",
			data:       []byte{0x99, 0x99, 0x82, 0x2C, 0x99}, // garbage, 300, garbage
			initOffset: 2,
			want:       300,
			wantOffset: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, offset, err := parseBase128Uint32(tt.data, tt.initOffset)
			if err != tt.wantErr {
				t.Errorf("parseBase128Uint32() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if got != tt.want {
					t.Errorf("parseBase128Uint32() value = %v, want %v", got, tt.want)
				}
				if offset != tt.wantOffset {
					t.Errorf("parseBase128Uint32() offset = %v, want %v", offset, tt.wantOffset)
				}
			}
		})
	}
}

func BenchmarkParseObjectIdentifier(b *testing.B) {
	oid := []byte{43, 6, 3, 30, 11, 1, 10}
	for i := 0; i < b.N; i++ {
		parseObjectIdentifier(oid)
	}
}

func BenchmarkMarshalObjectIdentifier(b *testing.B) {
	oid := ".1.3.6.3.30.11.1.10"
	for i := 0; i < b.N; i++ {
		marshalObjectIdentifier(oid)
	}
}

type testsMarshalUint32T struct {
	value     uint32
	goodBytes []byte
}

var testsMarshalUint32 = []testsMarshalUint32T{
	{0, []byte{0x00}},
	{2, []byte{0x02}}, // 2
	{128, []byte{0x00, 0x80}},
	{257, []byte{0x01, 0x01}},                  // FF + 2
	{65537, []byte{0x01, 0x00, 0x01}},          // FFFF + 2
	{16777217, []byte{0x01, 0x00, 0x00, 0x01}}, // FFFFFF + 2
	{18542501, []byte{0x01, 0x1a, 0xef, 0xa5}},
	{2147483647, []byte{0x7f, 0xff, 0xff, 0xff}},
	{2147483648, []byte{0x00, 0x80, 0x00, 0x0, 0x0}},
}

func TestMarshalUint32(t *testing.T) {
	for i, test := range testsMarshalUint32 {
		result, err := marshalUint32(test.value)
		if err != nil {
			t.Errorf("%d: expected %0x got err %v", i, test.goodBytes, err)
		}
		if !checkByteEquality2(test.goodBytes, result) {
			t.Errorf("%d: expected %0x got %0x", i, test.goodBytes, result)
		}
	}
}

func TestMarshalUint64(t *testing.T) {
	tests := []struct {
		value    interface{}
		expected []byte
	}{
		// RFC 2578 Section 7.1.15: Counter64 is an unsigned 64-bit integer.
		// X.690 Section 8.3.1: Integers shall be encoded in two's complement binary.
		// X.690 Section 8.3.2: Use the minimum number of octets.

		// Case 1: Zero should be encoded as a single byte: 0x00
		{uint64(0), []byte{0x00}},

		// Case 2: 127 (0x7F) has MSB clear, encoded as single byte
		{uint64(127), []byte{0x7F}},

		// Case 3: 128 (0x80) has MSB set, must prepend 0x00
		{uint64(128), []byte{0x00, 0x80}},

		// Case 4: 255 (0xFF) has MSB set, must prepend 0x00
		{uint64(255), []byte{0x00, 0xFF}},

		// Case 5: 256 (0x0100) MSB of first byte is 0, no need to prepend
		{uint64(256), []byte{0x01, 0x00}},

		// Case 6: 2^32 - 1 = 0xFFFFFFFF MSB set in first byte, must prepend 0x00
		{uint64(0xFFFFFFFF), []byte{0x00, 0xFF, 0xFF, 0xFF, 0xFF}},

		// Case 7: 2^63 = 0x8000000000000000 MSB set in trimmed output, must prepend 0x00
		{uint64(0x8000000000000000), []byte{
			0x00, // prepend
			0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}},

		// Case 8: Max uint64 = 0xFFFFFFFFFFFFFFFF, must prepend 0x00 to keep positive
		{uint64(0xFFFFFFFFFFFFFFFF), []byte{
			0x00, // prepend
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		}},
	}

	for _, test := range tests {
		actual, err := marshalUint64(test.value)
		if err != nil {
			t.Errorf("marshalUint64(%v) returned unexpected error: %v", test.value, err)
			continue
		}
		if !reflect.DeepEqual(actual, test.expected) {
			t.Errorf("marshalUint64(%v) = %x, expected %x", test.value, actual, test.expected)
		}
	}
}

var testsMarshalInt32 = []struct {
	value     int
	goodBytes []byte
}{
	{0, []byte{0x00}},
	{2, []byte{0x02}}, // 2
	{128, []byte{0x00, 0x80}},
	{257, []byte{0x01, 0x01}},                  // FF + 2
	{65537, []byte{0x01, 0x00, 0x01}},          // FFFF + 2
	{16777217, []byte{0x01, 0x00, 0x00, 0x01}}, // FFFFFF + 2
	{2147483647, []byte{0x7f, 0xff, 0xff, 0xff}},
	{-2147483648, []byte{0x80, 0x00, 0x00, 0x00}},
	{-16777217, []byte{0xfe, 0xff, 0xff, 0xff}},
	{-16777216, []byte{0xff, 0x00, 0x00, 0x00}},
	{-65537, []byte{0xfe, 0xff, 0xff}},
	{-65536, []byte{0xff, 0x00, 0x00}},
	{-257, []byte{0xfe, 0xff}},
	{-256, []byte{0xff, 0x00}},
	{-2, []byte{0xfe}},
	{-1, []byte{0xff}},
}

func TestMarshalInt32(t *testing.T) {
	for _, aTest := range testsMarshalInt32 {
		result, err := marshalInt32(aTest.value)
		assert.NoErrorf(t, err, "value %d", aTest.value)
		assert.EqualValues(t, aTest.goodBytes, result, "bad marshalInt32()")
	}
}

func TestParseUint64(t *testing.T) {
	tests := []struct {
		data []byte
		n    uint64
	}{
		{[]byte{}, 0},
		{[]byte{0x00}, 0},
		{[]byte{0x01}, 1},
		{[]byte{0x01, 0x01}, 257},
		{[]byte{0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1e, 0xb3, 0xbf}, 18446744073694786495},
	}
	for _, test := range tests {
		if ret, err := parseUint64(test.data); err != nil || ret != test.n {
			t.Errorf("parseUint64(%v) = %d, %v want %d, <nil>", test.data, ret, err, test.n)
		}
	}
}

var testsInvalidSNMPResponses = []string{
	"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",
	"MBoCAQEEB3ByaXZhdGWiDAIESESkywIBBQIBAA==",
	"MEo=",
}

func TestInvalidSNMPResponses(t *testing.T) {

	g := &GoSNMP{
		Target:    "127.0.0.1",
		Port:      161,
		Community: "public",
		Version:   Version2c,
	}

	for i, test := range testsInvalidSNMPResponses {
		testBytes, _ := base64.StdEncoding.DecodeString(test)
		result, err := g.SnmpDecodePacket(testBytes)
		if err == nil {
			t.Errorf("#%d, failed to error %v", i, result)
		}
	}
}

func checkByteEquality2(a, b []byte) bool {

	if a == nil && b == nil {
		return true
	}

	if a == nil || b == nil {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

func TestPacketReaderAdvance(t *testing.T) {
	data := []byte{0x30, 0x05, 0x01, 0x02, 0x03}
	r, err := newPacketReader(data, 0)
	if err != nil {
		t.Fatalf("newPacketReader: %v", err)
	}

	if r.position() != 0 {
		t.Fatalf("initial position = %d, want 0", r.position())
	}

	// valid advance
	if err := r.advance(2); err != nil {
		t.Fatalf("advance(2) unexpected error: %v", err)
	}
	if r.position() != 2 {
		t.Fatalf("position after advance(2) = %d, want 2", r.position())
	}

	// advance to exact end
	if err := r.advance(3); err != nil {
		t.Fatalf("advance(3) to end unexpected error: %v", err)
	}
	if r.position() != 5 {
		t.Fatalf("position at end = %d, want 5", r.position())
	}
	if len(r.remaining()) != 0 {
		t.Fatalf("remaining at end = %d, want 0", len(r.remaining()))
	}

	// advance past end
	if err := r.advance(1); err == nil {
		t.Fatal("advance(1) past end should error")
	}

	// negative result
	r2, err := newPacketReader(data, 1)
	if err != nil {
		t.Fatalf("newPacketReader: %v", err)
	}
	if err := r2.advance(-2); err == nil {
		t.Fatal("advance(-2) from pos 1 should error")
	}
}

func TestPacketReaderParseLength(t *testing.T) {
	// OctetString with 3-byte value: tag=0x04, len=0x03, then 3 bytes
	data := []byte{0x04, 0x03, 0xAA, 0xBB, 0xCC}
	r, err := newPacketReader(data, 0)
	if err != nil {
		t.Fatalf("newPacketReader: %v", err)
	}

	length, err := r.parseLength()
	if err != nil {
		t.Fatalf("parseLength unexpected error: %v", err)
	}
	// length should be total TLV = 5
	if length != 5 {
		t.Fatalf("parseLength length = %d, want 5", length)
	}
	// cursor should have advanced past the header (tag + 1 byte length = 2)
	if r.position() != 2 {
		t.Fatalf("position after parseLength = %d, want 2", r.position())
	}
}

func TestPacketReaderParseRawField(t *testing.T) {
	// Integer TLV: tag=0x02, len=0x01, value=0x05
	data := []byte{0x02, 0x01, 0x05}
	r, err := newPacketReader(data, 0)
	if err != nil {
		t.Fatalf("newPacketReader: %v", err)
	}

	val, err := r.parseRawField(NewLogger(log.New(io.Discard, "", 0)), "test-int")
	if err != nil {
		t.Fatalf("parseRawField unexpected error: %v", err)
	}
	intVal, ok := val.(int)
	if !ok {
		t.Fatalf("parseRawField returned %T, want int", val)
	}
	if intVal != 5 {
		t.Fatalf("parseRawField value = %d, want 5", intVal)
	}
	// cursor should have advanced past the entire TLV (3 bytes)
	if r.position() != 3 {
		t.Fatalf("position after parseRawField = %d, want 3", r.position())
	}
}

func TestPacketReaderSkipTLV(t *testing.T) {
	// Two TLVs: Integer(5) then OctetString("hi")
	data := []byte{
		0x02, 0x01, 0x05, // Integer, len 1, value 5
		0x04, 0x02, 0x68, 0x69, // OctetString, len 2, "hi"
	}
	r, err := newPacketReader(data, 0)
	if err != nil {
		t.Fatalf("newPacketReader: %v", err)
	}

	length, err := r.skipTLV()
	if err != nil {
		t.Fatalf("skipTLV unexpected error: %v", err)
	}
	if length != 3 {
		t.Fatalf("skipTLV length = %d, want 3", length)
	}
	if r.position() != 3 {
		t.Fatalf("position after skipTLV = %d, want 3", r.position())
	}

	// skip second TLV
	length, err = r.skipTLV()
	if err != nil {
		t.Fatalf("second skipTLV unexpected error: %v", err)
	}
	if length != 4 {
		t.Fatalf("second skipTLV length = %d, want 4", length)
	}
	if r.position() != 7 {
		t.Fatalf("position after second skipTLV = %d, want 7", r.position())
	}
}

func TestPacketReaderEmptyData(t *testing.T) {
	r, err := newPacketReader([]byte{}, 0)
	if err != nil {
		t.Fatalf("newPacketReader: %v", err)
	}

	// parseLength returns (0, 0, nil) for empty input via the len < 2 fallback
	length, err := r.parseLength()
	if err != nil {
		t.Fatalf("parseLength on empty data unexpected error: %v", err)
	}
	if length != 0 {
		t.Fatalf("parseLength on empty data length = %d, want 0", length)
	}

	// parseRawField rejects empty data
	if _, err := r.parseRawField(NewLogger(log.New(io.Discard, "", 0)), "test"); err == nil {
		t.Fatal("parseRawField on empty data should error")
	}
}

func TestPacketReaderSetData(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	r, err := newPacketReader(data, 2)
	if err != nil {
		t.Fatalf("newPacketReader: %v", err)
	}

	if len(r.remaining()) != 3 {
		t.Fatalf("initial remaining = %d, want 3", len(r.remaining()))
	}

	// simulate truncation (as decryptPacket does)
	if err := r.setData(data[:3]); err != nil {
		t.Fatalf("setData unexpected error: %v", err)
	}
	if len(r.remaining()) != 1 {
		t.Fatalf("remaining after setData = %d, want 1", len(r.remaining()))
	}
}

func TestNewPacketReaderRejectsInvalidPos(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}

	// position beyond data length
	if _, err := newPacketReader(data, 4); err == nil {
		t.Fatal("pos > len(data) should error")
	}

	// negative position
	if _, err := newPacketReader(data, -1); err == nil {
		t.Fatal("pos < 0 should error")
	}

	// boundary: pos == len(data) is valid (empty remaining)
	r, err := newPacketReader(data, 3)
	if err != nil {
		t.Fatalf("pos == len(data) unexpected error: %v", err)
	}
	if len(r.remaining()) != 0 {
		t.Fatalf("remaining at end = %d, want 0", len(r.remaining()))
	}
}

func TestPacketReaderSetDataRejectsInvalidPos(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	r, err := newPacketReader(data, 4)
	if err != nil {
		t.Fatalf("newPacketReader: %v", err)
	}

	// shrink data so pos is beyond new length
	if err := r.setData(data[:2]); err == nil {
		t.Fatal("setData with pos > len(newData) should error")
	}
}

// TestPacketReaderRejectsOverflow demonstrates that packetReader.advance
// catches integer overflow that the old manual "cursor < 0" checks were
// added to detect (commit d61b830). parseRawField can return a count
// derived from a crafted BER length that, when added to a large cursor,
// overflows int to negative. The old pattern was:
//
//	cursor += count
//	if cursor < 0 || cursor > len(packet) { ... }
//
// With packetReader, advance() rejects this before the cursor is updated.
func TestPacketReaderRejectsOverflow(t *testing.T) {
	data := make([]byte, 10)
	r, err := newPacketReader(data, 5)
	if err != nil {
		t.Fatalf("newPacketReader: %v", err)
	}

	// Simulate what happens if a crafted BER length causes parseLength
	// to return a huge cursor value (hypothetically bypassing its own
	// checks). advance() must reject it regardless.
	err = r.advance(1<<63 - 1) // MaxInt — would wrap to negative when added
	if err == nil {
		t.Fatal("advance with MaxInt should error, got nil")
	}

	// Position must not have changed
	if r.position() != 5 {
		t.Fatalf("position changed to %d after rejected advance", r.position())
	}
}

// TestPacketReaderSequentialFieldParsing mirrors the real unmarshal pattern:
// parseLength to skip a SEQUENCE header, then multiple parseRawField calls.
// Verifies the reader tracks position correctly across a realistic sequence
// of operations.
func TestPacketReaderSequentialFieldParsing(t *testing.T) {
	// Build a minimal USM-like structure:
	// SEQUENCE { INTEGER(42), OctetString("hi") }
	packet := []byte{
		0x30, 0x08, // SEQUENCE, length 8 (total TLV = 10)
		0x02, 0x01, 0x2a, // INTEGER, length 1, value 42
		0x04, 0x02, 0x68, 0x69, // OctetString, length 2, "hi"
		// extra byte to prove we stop at the right place
		0xff,
	}

	r, err := newPacketReader(packet, 0)
	if err != nil {
		t.Fatalf("newPacketReader: %v", err)
	}
	logger := NewLogger(log.New(io.Discard, "", 0))

	// Skip SEQUENCE header (advances past tag+length = 2 bytes)
	seqLength, err := r.parseLength()
	if err != nil {
		t.Fatalf("parseLength: %v", err)
	}
	if seqLength != 10 {
		t.Fatalf("sequence TLV length = %d, want 10", seqLength)
	}
	if r.position() != 2 {
		t.Fatalf("position after SEQUENCE header = %d, want 2", r.position())
	}

	// Parse first field
	val1, err := r.parseRawField(logger, "field1")
	if err != nil {
		t.Fatalf("parseRawField field1: %v", err)
	}
	if val1.(int) != 42 {
		t.Fatalf("field1 = %v, want 42", val1)
	}
	if r.position() != 5 {
		t.Fatalf("position after field1 = %d, want 5", r.position())
	}

	// Parse second field
	val2, err := r.parseRawField(logger, "field2")
	if err != nil {
		t.Fatalf("parseRawField field2: %v", err)
	}
	if val2.(string) != "hi" {
		t.Fatalf("field2 = %v, want \"hi\"", val2)
	}
	if r.position() != 9 {
		t.Fatalf("position after field2 = %d, want 9", r.position())
	}

	// Remaining should be just the trailing 0xff
	if len(r.remaining()) != 1 {
		t.Fatalf("remaining = %d, want 1", len(r.remaining()))
	}
}

// TestParseLength tests the parseLength function with various BER length encodings
func TestParseLength(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		wantLength int
		wantCursor int
		wantErr    bool
		errContain string
	}{
		// Short form length encoding (length byte <= 127)
		{
			name:       "short form length 4",
			data:       []byte{0x04, 0x04, 0x01, 0x02, 0x03, 0x04},
			wantLength: 6,
			wantCursor: 2,
			wantErr:    false,
		},
		{
			name:       "short form length 0 (null)",
			data:       []byte{0x04, 0x00},
			wantLength: 2,
			wantCursor: 2,
			wantErr:    false,
		},
		{
			name:       "short form max length 127",
			data:       append([]byte{0x04, 0x7F}, make([]byte, 127)...),
			wantLength: 129,
			wantCursor: 2,
			wantErr:    false,
		},
		// Long form length encoding (first byte > 127, subsequent bytes contain length)
		{
			name:       "long form 1 byte length (0x81 0x80 = 128)",
			data:       append([]byte{0x04, 0x81, 0x80}, make([]byte, 128)...),
			wantLength: 131,
			wantCursor: 3,
			wantErr:    false,
		},
		{
			name:       "long form 2 byte length (0x82 0x01 0x00 = 256)",
			data:       append([]byte{0x04, 0x82, 0x01, 0x00}, make([]byte, 256)...),
			wantLength: 260,
			wantCursor: 4,
			wantErr:    false,
		},
		// Edge cases
		{
			name:       "exactly 2 bytes should use short form parsing",
			data:       []byte{0x04, 0x00},
			wantLength: 2,
			wantCursor: 2,
			wantErr:    false,
		},
		{
			name:       "1 byte input uses fallback",
			data:       []byte{0x04},
			wantLength: 1,
			wantCursor: 1,
			wantErr:    false,
		},
		{
			name:       "empty input uses fallback",
			data:       []byte{},
			wantLength: 0,
			wantCursor: 0,
			wantErr:    false,
		},
		// Indefinite length encoding - prohibited per RFC 3417 Section 8
		{
			name:       "indefinite length 0x80 should be rejected",
			data:       []byte{0x04, 0x80, 0x01, 0x02, 0x00, 0x00},
			wantErr:    true,
			errContain: "indefinite length",
		},
		// Invalid long form data
		{
			name:    "truncated long form length",
			data:    []byte{0x04, 0x82, 0x01}, // missing second length byte
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			length, cursor, err := parseLength(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseLength() expected error, got nil")
				} else if tt.errContain != "" && !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("parseLength() error = %v, want error containing %q", err, tt.errContain)
				}
				return
			}
			if err != nil {
				t.Errorf("parseLength() unexpected error: %v", err)
				return
			}
			if length != tt.wantLength {
				t.Errorf("parseLength() length = %v, want %v", length, tt.wantLength)
			}
			if cursor != tt.wantCursor {
				t.Errorf("parseLength() cursor = %v, want %v", cursor, tt.wantCursor)
			}
		})
	}
}

// TestIPAddressDecodeValue tests IPAddress parsing via decodeValue with various BER encodings
func TestIPAddressDecodeValue(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		wantIP   string
		wantNull bool
		wantErr  bool
	}{
		// Standard short-form BER encoding (most common)
		{
			name:   "short-form IPv4",
			data:   []byte{0x40, 0x04, 192, 168, 1, 1},
			wantIP: "192.168.1.1",
		},
		{
			name:   "short-form IPv4 loopback",
			data:   []byte{0x40, 0x04, 127, 0, 0, 1},
			wantIP: "127.0.0.1",
		},
		{
			name:   "short-form IPv6",
			data:   []byte{0x40, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			wantIP: "2001:db8::1",
		},
		{
			name:   "short-form IPv6 all bytes set",
			data:   []byte{0x40, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34, 0xab, 0xcd},
			wantIP: "2001:db8:85a3:0:8a2e:370:7334:abcd",
		},
		// Long-form BER encoding
		{
			name:   "long-form IPv4",
			data:   []byte{0x40, 0x81, 0x04, 192, 168, 1, 1},
			wantIP: "192.168.1.1",
		},
		{
			name:   "long-form IPv6",
			data:   []byte{0x40, 0x81, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			wantIP: "2001:db8::1",
		},
		// Edge cases
		{
			name:     "null IPAddress (length 0)",
			data:     []byte{0x40, 0x00},
			wantNull: true,
		},
		// Error cases
		{
			name:    "truncated IPv4 data",
			data:    []byte{0x40, 0x04, 192, 168},
			wantErr: true,
		},
		{
			name:    "truncated IPv6 data",
			data:    []byte{0x40, 0x10, 0x20, 0x01, 0x0d, 0xb8},
			wantErr: true,
		},
		{
			name:    "invalid length (not 0, 4, or 16)",
			data:    []byte{0x40, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			wantErr: true,
		},
		{
			name:    "indefinite length rejected",
			data:    []byte{0x40, 0x80, 192, 168, 1, 1, 0x00, 0x00},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := &GoSNMP{}
			retVal := &variable{}
			err := x.decodeValue(tt.data, retVal)

			if tt.wantErr {
				if err == nil {
					t.Errorf("decodeValue() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("decodeValue() unexpected error: %v", err)
				return
			}
			if tt.wantNull {
				if retVal.Value != nil {
					t.Errorf("decodeValue() = %v, want nil", retVal.Value)
				}
				return
			}
			if retVal.Value != tt.wantIP {
				t.Errorf("decodeValue() = %v, want %v", retVal.Value, tt.wantIP)
			}
			if retVal.Type != IPAddress {
				t.Errorf("decodeValue() type = %v, want IPAddress", retVal.Type)
			}
		})
	}
}

// TestIPAddressParseRawField tests IPAddress parsing via parseRawField.
// Note: parseRawField only supports IPv4, not IPv6 (returns error for length != 4).
func TestIPAddressParseRawField(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		wantIP     string
		wantLength int
		wantNull   bool
		wantErr    bool
	}{
		// Standard short-form
		{
			name:       "short-form IPv4",
			data:       []byte{0x40, 0x04, 192, 168, 1, 1},
			wantIP:     "192.168.1.1",
			wantLength: 6,
		},
		{
			name:       "short-form IPv4 loopback",
			data:       []byte{0x40, 0x04, 127, 0, 0, 1},
			wantIP:     "127.0.0.1",
			wantLength: 6,
		},
		// Long-form BER
		{
			name:       "long-form IPv4",
			data:       []byte{0x40, 0x81, 0x04, 10, 0, 0, 1},
			wantIP:     "10.0.0.1",
			wantLength: 7,
		},
		// Edge cases
		{
			name:       "null IPAddress (length 0)",
			data:       []byte{0x40, 0x00},
			wantNull:   true,
			wantLength: 2,
		},
		// Error cases - parseRawField only supports IPv4
		{
			name:    "IPv6 rejected by parseRawField",
			data:    []byte{0x40, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			wantErr: true,
		},
		{
			name:    "truncated IPv4",
			data:    []byte{0x40, 0x04, 192, 168},
			wantErr: true,
		},
		{
			name:    "indefinite length rejected",
			data:    []byte{0x40, 0x80, 192, 168, 1, 1, 0x00, 0x00},
			wantErr: true,
		},
	}

	logger := NewLogger(log.New(io.Discard, "", 0))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, length, err := parseRawField(logger, tt.data, "test")

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseRawField() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("parseRawField() unexpected error: %v", err)
				return
			}
			if length != tt.wantLength {
				t.Errorf("parseRawField() length = %v, want %v", length, tt.wantLength)
			}
			if tt.wantNull {
				if val != nil {
					t.Errorf("parseRawField() = %v, want nil", val)
				}
				return
			}
			if val != tt.wantIP {
				t.Errorf("parseRawField() = %v, want %v", val, tt.wantIP)
			}
		})
	}
}

func TestMarshalFloat32(t *testing.T) {
	tests := []struct {
		name    string
		input   any
		want    []byte
		wantErr bool
	}{
		{
			name:    "zero",
			input:   float32(0.0),
			want:    []byte{0x00, 0x00, 0x00, 0x00},
			wantErr: false,
		},
		{
			name:    "positive 1.0",
			input:   float32(1.0),
			want:    []byte{0x3f, 0x80, 0x00, 0x00},
			wantErr: false,
		},
		{
			name:    "negative 1.0",
			input:   float32(-1.0),
			want:    []byte{0xbf, 0x80, 0x00, 0x00},
			wantErr: false,
		},
		{
			name:    "pi approx",
			input:   float32(3.14159),
			want:    []byte{0x40, 0x49, 0x0f, 0xd0},
			wantErr: false,
		},
		{
			name:    "wrong type int",
			input:   42,
			want:    nil,
			wantErr: true,
		},
		{
			name:    "wrong type float64",
			input:   float64(1.0),
			want:    nil,
			wantErr: true,
		},
		{
			name:    "wrong type string",
			input:   "1.0",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := marshalFloat32(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("marshalFloat32() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("marshalFloat32() unexpected error: %v", err)
				return
			}
			if !checkByteEquality2(got, tt.want) {
				t.Errorf("marshalFloat32() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMarshalFloat64(t *testing.T) {
	tests := []struct {
		name    string
		input   any
		want    []byte
		wantErr bool
	}{
		{
			name:    "zero",
			input:   float64(0.0),
			want:    []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantErr: false,
		},
		{
			name:    "positive 1.0",
			input:   float64(1.0),
			want:    []byte{0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantErr: false,
		},
		{
			name:    "negative 1.0",
			input:   float64(-1.0),
			want:    []byte{0xbf, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantErr: false,
		},
		{
			name:    "pi approx",
			input:   float64(3.141592653589793),
			want:    []byte{0x40, 0x09, 0x21, 0xfb, 0x54, 0x44, 0x2d, 0x18},
			wantErr: false,
		},
		{
			name:    "wrong type int",
			input:   42,
			want:    nil,
			wantErr: true,
		},
		{
			name:    "wrong type float32",
			input:   float32(1.0),
			want:    nil,
			wantErr: true,
		},
		{
			name:    "wrong type string",
			input:   "1.0",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := marshalFloat64(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("marshalFloat64() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("marshalFloat64() unexpected error: %v", err)
				return
			}
			if !checkByteEquality2(got, tt.want) {
				t.Errorf("marshalFloat64() = %v, want %v", got, tt.want)
			}
		})
	}
}
