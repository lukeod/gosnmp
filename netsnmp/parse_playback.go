// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build !netsnmp

package netsnmp

// ParseResult holds the parsed fields from a net-snmp packet parse.
type ParseResult struct {
	Success   bool
	Version   int
	Community string
	PDUType   int
	RequestID int32
	ErrStat   int32
	ErrIndex  int32
	NumVars   int
	VarTypes  []byte
}

// NetsnmpParsePacket is a stub for non-CGO builds.
// Differential fuzz tests require -tags netsnmp.
func NetsnmpParsePacket(data []byte) ParseResult {
	return ParseResult{}
}
