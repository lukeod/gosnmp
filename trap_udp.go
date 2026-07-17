// Copyright 2026 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// reflectorUDPConn is a net.UDPConn wrapper that records the local destination IP of incoming packets and uses it as
// the source address of the corresponding response, so that responses from a multihomed host leave from the address
// the request was sent to (RFC 1122 sections 3.3.4.2 and 4.1.3.5).
//
// Source selection requires ancillary packet-info support from golang.org/x/net. For IPv4 that is available on Linux,
// macOS, Solaris and z/OS; for IPv6 also on the BSDs and AIX. Elsewhere (notably Windows, and IPv4 on the BSDs) the
// wrapper degrades to ordinary kernel source selection. A destination that is not usable as a source (multicast,
// broadcast) also falls back to ordinary kernel source selection.
type reflectorUDPConn struct {
	conn *net.UDPConn
}

func newReflectorUDPConn(conn *net.UDPConn) *reflectorUDPConn {
	// We don't know the address family of conn, so try both and see what sticks. Windows will fail both.
	_ = ipv4.NewPacketConn(conn).SetControlMessage(ipv4.FlagDst, true)
	_ = ipv6.NewPacketConn(conn).SetControlMessage(ipv6.FlagDst, true)
	return &reflectorUDPConn{conn: conn}
}

// readUDPFrom reads a single packet into b and returns the packet length, the sender's address, and a function that
// sends a response to the sender, sourced from the request's destination address when possible.
func (c *reflectorUDPConn) readUDPFrom(b []byte) (int, *net.UDPAddr, func(b []byte) (int, error), error) {
	oob := make([]byte, max(len(ipv4.NewControlMessage(ipv4.FlagDst)), len(ipv6.NewControlMessage(ipv6.FlagDst))))
	n, oobn, _, src, err := c.conn.ReadMsgUDP(b, oob)
	if err != nil {
		return 0, nil, nil, err
	}

	return n, src, c.respondFunc(src, parseDst(oob[:oobn])), nil
}

// parseDst extracts the local destination IP from ancillary data, returning nil when unavailable.
func parseDst(oob []byte) net.IP {
	if len(oob) == 0 {
		return nil
	}

	// Try both families, ControlMessage.Parse quietly skips mismatched family messages, so we're checking for Dst.
	// IfIndex is ignored on purpose, it breaks Src outright on MacOS and is incompatible with asymmetric routing.
	var cm4 ipv4.ControlMessage
	if err := cm4.Parse(oob); err == nil && cm4.Dst != nil {
		return cm4.Dst
	}
	var cm6 ipv6.ControlMessage
	if err := cm6.Parse(oob); err == nil && cm6.Dst != nil {
		return cm6.Dst
	}
	return nil
}

// respondFunc returns a function that sends a packet to src, sourced from dst when dst is usable as a source
// address. Broadcast and multicast destinations are not valid response sources (RFC 1122 section 3.2.1.3 defines the
// specific destination of such packets as a unicast address of the receiving interface), so they get ordinary kernel
// source selection. Directed broadcast addresses cannot be recognized without interface data, so a failed
// source-constrained write is retried without the source constraint rather than dropping the response, mirroring
// Net-SNMP's fallback behavior.
func (c *reflectorUDPConn) respondFunc(src *net.UDPAddr, dst net.IP) func(b []byte) (int, error) {
	plain := func(b []byte) (int, error) { return c.conn.WriteToUDP(b, src) }

	if dst == nil || dst.IsMulticast() || dst.IsUnspecified() || dst.Equal(net.IPv4bcast) {
		return plain
	}

	// On a dual-stack host a wildcard socket will serve both IPv4 & IPv6 in IPv6 mode. A packet directed at a local
	// IPv4 address will produce an ipv6.ControlMessage containing a 16-byte long IPv4 Dst. On the other hand,
	// ControlMessage.Marshal ignores Src with mismatched family, so here we are doing a bit of a repack.
	var oob []byte
	if dst.To4() != nil {
		oob = (&ipv4.ControlMessage{Src: dst}).Marshal()
	} else {
		oob = (&ipv6.ControlMessage{Src: dst}).Marshal()
	}
	if len(oob) == 0 {
		// The platform cannot marshal a source control message (e.g. IPv4 on the BSDs, or Windows).
		return plain
	}

	return func(b []byte) (int, error) {
		n, _, err := c.conn.WriteMsgUDP(b, oob, src)
		if err != nil {
			// dst was not usable as a source after all (e.g. a directed broadcast); retry with kernel
			// source selection rather than dropping the response.
			return plain(b)
		}
		return n, nil
	}
}
