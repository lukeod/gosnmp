// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build all || misc
// +build all misc

package gosnmp

import (
	"bytes"
	"crypto"
	_ "crypto/md5"
	_ "crypto/sha1"
	"errors"
	"math"
	"math/big"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

// -----------------------------------------------------------------------------

var testsMarshalLength = []struct {
	length   int
	expected []byte
}{
	{1, []byte{0x01}},
	{129, []byte{0x81, 0x81}},
	{256, []byte{0x82, 0x01, 0x00}},
	{272, []byte{0x82, 0x01, 0x10}},
	{435, []byte{0x82, 0x01, 0xb3}},
}

func TestMarshalLength(t *testing.T) {
	for i, test := range testsMarshalLength {
		testBytes, err := marshalLength(test.length)
		if err != nil {
			t.Errorf("%d: length %d got err %v", i, test.length, err)
		}
		if !reflect.DeepEqual(testBytes, test.expected) {
			t.Errorf("%d: length %d got |%x| expected |%x|",
				i, test.length, testBytes, test.expected)
		}
	}
}

// -----------------------------------------------------------------------------

// TestParseLength tests BER length field parsing including edge cases
// identified from net-snmp's asn1.c implementation.
// References X.690 §8.1.3 for length encoding and RFC 3417 §8 for SNMP restrictions.
func TestParseLength(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		expectedLength int
		expectedCursor int
		wantErr        bool
	}{
		// Short-form encoding per X.690 §8.1.3.4 (length 0-127)
		{
			name:           "short_form_zero",
			data:           []byte{0x04, 0x00}, // type + length 0
			expectedLength: 2,
			expectedCursor: 2,
		},
		{
			name:           "short_form_small",
			data:           []byte{0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}, // type + length 5 + data
			expectedLength: 7,
			expectedCursor: 2,
		},
		{
			name:           "short_form_max",
			data:           append([]byte{0x04, 0x7f}, make([]byte, 127)...), // type + length 127 + data
			expectedLength: 129,
			expectedCursor: 2,
		},
		// Long-form encoding per X.690 §8.1.3.5 (1 length octet, 0x81)
		{
			name:           "long_form_1_octet_128",
			data:           append([]byte{0x04, 0x81, 0x80}, make([]byte, 128)...), // length 128
			expectedLength: 131,
			expectedCursor: 3,
		},
		{
			name:           "long_form_1_octet_255",
			data:           append([]byte{0x04, 0x81, 0xff}, make([]byte, 255)...), // length 255
			expectedLength: 258,
			expectedCursor: 3,
		},
		// Long-form encoding per X.690 §8.1.3.5 (2 length octets, 0x82)
		{
			name:           "long_form_2_octets_256",
			data:           append([]byte{0x04, 0x82, 0x01, 0x00}, make([]byte, 256)...), // length 256
			expectedLength: 260,
			expectedCursor: 4,
		},
		{
			name:           "long_form_2_octets_1000",
			data:           append([]byte{0x04, 0x82, 0x03, 0xe8}, make([]byte, 1000)...), // length 1000
			expectedLength: 1004,
			expectedCursor: 4,
		},
		// Edge case: indefinite length encoding per X.690 §8.1.3.6 (0x80)
		// BER 0x80 means indefinite length. RFC 3417 §8 prohibits this in SNMP:
		// "only the definite form is used; use of the indefinite form encoding is prohibited"
		// net-snmp rejects this with "indefinite length not supported"
		{
			name:    "indefinite_length_0x80",
			data:    []byte{0x30, 0x80, 0x00, 0x00}, // SEQUENCE with 0x80 (indefinite)
			wantErr: true,
		},
		// Edge case: buffer too short for long-form length octets
		{
			name:    "long_form_truncated_length_octets",
			data:    []byte{0x04, 0x82, 0x01}, // claims 2 length octets but only 1 present
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			length, cursor, err := parseLength(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseLength() expected error, got length=%d, cursor=%d", length, cursor)
				}
				return
			}
			if err != nil {
				t.Errorf("parseLength() unexpected error: %v", err)
				return
			}
			if length != tt.expectedLength {
				t.Errorf("parseLength() length = %d, want %d", length, tt.expectedLength)
			}
			if cursor != tt.expectedCursor {
				t.Errorf("parseLength() cursor = %d, want %d", cursor, tt.expectedCursor)
			}
		})
	}
}

// TestParseLengthOverflow tests that parseLength handles length values that
// would overflow or exceed reasonable bounds per X.690 §8.1.3.5. Based on net-snmp's
// asn_parse_length() validation patterns.
func TestParseLengthOverflow(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		// Length that would overflow int when shifted
		// 0x88 = 8 length octets following, each 0xff
		// This would produce a value > max int64
		{
			name:    "overflow_8_octets_max",
			data:    []byte{0x04, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			wantErr: true,
		},
		// 0x88 with values that would overflow during accumulation
		{
			name:    "overflow_during_shift",
			data:    []byte{0x04, 0x88, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			length, cursor, err := parseLength(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseLength() expected error for overflow, got length=%d, cursor=%d", length, cursor)
				}
				return
			}
			if err != nil {
				t.Errorf("parseLength() unexpected error: %v", err)
			}
		})
	}
}

// -----------------------------------------------------------------------------

var testsPartition = []struct {
	currentPosition int
	partitionSize   int
	sliceLength     int
	ok              bool
}{
	{-1, 3, 8, false}, // test out of range
	{8, 3, 8, false},  // test out of range
	{0, 3, 8, false},  // test 0-7/3 per doco
	{1, 3, 8, false},
	{2, 3, 8, true},
	{3, 3, 8, false},
	{4, 3, 8, false},
	{5, 3, 8, true},
	{6, 3, 8, false},
	{7, 3, 8, true},
	{-1, 1, 3, false}, // partition size of one
	{0, 1, 3, true},
	{1, 1, 3, true},
	{2, 1, 3, true},
	{3, 1, 3, false},
}

func TestPartition(t *testing.T) {
	for i, test := range testsPartition {
		ok := Partition(test.currentPosition, test.partitionSize, test.sliceLength)
		if ok != test.ok {
			t.Errorf("#%d: Bad result: %v (expected %v)", i, ok, test.ok)
		}
	}
}

// ---------------------------------------------------------------------

var testsToBigInt = []struct {
	in       interface{}
	expected *big.Int
}{
	{int8(-42), big.NewInt(-42)},
	{int16(42), big.NewInt(42)},
	{int32(-42), big.NewInt(-42)},
	{int64(42), big.NewInt(42)},

	{uint8(42), big.NewInt(42)},
	{uint16(42), big.NewInt(42)},
	{uint32(42), big.NewInt(42)},
	{uint64(42), big.NewInt(42)},

	// edge case, max uint64
	{uint64(math.MaxUint64), new(big.Int).SetUint64(math.MaxUint64)},

	// string: valid number
	{"-123456789", big.NewInt(-123456789)},

	// string: invalid number
	{"foo", new(big.Int)},

	// unhandled type
	{struct{}{}, new(big.Int)},
}

func TestToBigInt(t *testing.T) {
	for i, test := range testsToBigInt {
		result := ToBigInt(test.in)
		if result.Cmp(test.expected) != 0 {
			t.Errorf("#%d, %T: got %v expected %v", i, test.in, result, test.expected)
		}
	}
}

// ---------------------------------------------------------------------

var testsSnmpVersionString = []struct {
	in  SnmpVersion
	out string
}{
	{Version1, "1"},
	{Version2c, "2c"},
	{Version3, "3"},
}

func TestSnmpVersionString(t *testing.T) {
	for i, test := range testsSnmpVersionString {
		result := test.in.String()
		if result != test.out {
			t.Errorf("#%d, got %v expected %v", i, result, test.out)
		}
	}
}

// ---------------------------------------------------------------------

var testSnmpV3MD5HMAC = []struct {
	password string
	engineid string
	outKey   []byte
}{
	{"maplesyrup", string([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}), []byte{0x52, 0x6f, 0x5e, 0xed, 0x9f, 0xcc, 0xe2, 0x6f, 0x89, 0x64, 0xc2, 0x93, 0x07, 0x87, 0xd8, 0x2b}},
}

func TestMD5HMAC(t *testing.T) {
	for i, test := range testSnmpV3MD5HMAC {
		cacheKey := make([]byte, 1+len(test.password))
		cacheKey = append(cacheKey, 'h'+byte(MD5))
		cacheKey = append(cacheKey, []byte(test.password)...)

		result, err := hMAC(crypto.MD5, string(cacheKey), test.password, test.engineid)
		assert.NoError(t, err)
		if !bytes.Equal(result, test.outKey) {
			t.Errorf("#%d, got %v expected %v", i, result, test.outKey)
		}
	}
}

var testSnmpV3SHAHMAC = []struct {
	password string
	engineid string
	outKey   []byte
}{
	{"maplesyrup", string([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}), []byte{0x66, 0x95, 0xfe, 0xbc, 0x92, 0x88, 0xe3, 0x62, 0x82, 0x23, 0x5f, 0xc7, 0x15, 0x1f, 0x12, 0x84, 0x97, 0xb3, 0x8f, 0x3f}},
}

func TestSHAHMAC(t *testing.T) {
	for i, test := range testSnmpV3SHAHMAC {
		cacheKey := make([]byte, 1+len(test.password))
		cacheKey = append(cacheKey, 'h'+byte(SHA))
		cacheKey = append(cacheKey, []byte(test.password)...)

		result, err := hMAC(crypto.SHA1, string(cacheKey), test.password, test.engineid)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(result, test.outKey) {
			t.Errorf("#%d, got %v expected %v", i, result, test.outKey)
		}
	}
}

// ---------------------------------------------------------------------

/*
var testMarshalTimeticks = []struct {
	timeticks uint32
	out       []byte
}{
	{1034156, []byte{0x0f, 0xc7, 0xac}},
}

func TestMarshalTimeticks(t *testing.T) {
	for i, test := range testMarshalTimeticks {
		result, err := marshalTimeticks(test.timeticks)
		if err != nil {
			t.Errorf("%d: expected %v got err %v", i, result, err)
		}
		if !bytes.Equal(result, test.out) {
			t.Errorf("#%d, got %v expected %v", i, result, test.out)
		}
	}
}
*/

// parseBitString parses an ASN.1 bit string from the given byte slice and returns it.
func parseBitString(bytes []byte) (ret BitStringValue, err error) {
	if len(bytes) == 0 {
		err = errors.New("zero length BIT STRING")
		return
	}
	paddingBits := int(bytes[0])
	if paddingBits > 7 ||
		len(bytes) == 1 && paddingBits > 0 ||
		bytes[len(bytes)-1]&((1<<bytes[0])-1) != 0 {
		err = errors.New("invalid padding bits in BIT STRING")
		return
	}
	ret.BitLength = (len(bytes)-1)*8 - paddingBits
	ret.Bytes = bytes[1:]
	return
}

// ---------------------------------------------------------------------
