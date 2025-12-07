// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v3"
)

//
// Sending Traps ie GoSNMP acting as an Agent
//

// SendTrap sends a SNMP Trap
//
// pdus[0] can a pdu of Type TimeTicks (with the desired uint32 epoch
// time).  Otherwise a TimeTicks pdu will be prepended, with time set to
// now. This mirrors the behaviour of the Net-SNMP command-line tools.
//
// SendTrap doesn't wait for a return packet from the NMS (Network
// Management Station).
//
// See also Listen() and examples for creating an NMS.
//
// NOTE: the trap code is currently unreliable when working with snmpv3 - pull requests welcome
func (x *GoSNMP) SendTrap(trap SnmpTrap) (result *SnmpPacket, err error) {
	var pdutype PDUType

	switch x.Version {
	case Version2c, Version3:
		// Default to a v2 trap.
		pdutype = SNMPv2Trap

		if len(trap.Variables) == 0 {
			return nil, fmt.Errorf("function SendTrap requires at least 1 PDU")
		}

		if trap.Variables[0].Type == TimeTicks {
			// check is uint32
			if _, ok := trap.Variables[0].Value.(uint32); !ok {
				return nil, fmt.Errorf("function SendTrap TimeTick must be uint32")
			}
		}

		switch x.MsgFlags {
		// as per https://www.rfc-editor.org/rfc/rfc3412.html#section-6.4
		// The reportableFlag MUST always be zero when the message contains
		// a PDU from the Unconfirmed Class such as an SNMPv2-trap PDU
		case 0x4, 0x5, 0x7:
			// .. therefor bitclear the Reportable flag from the MsgFlags
			// that we inherited from validateParameters()
			x.MsgFlags = (x.MsgFlags &^ Reportable)
		}

		// If it's an inform, do that instead.
		if trap.IsInform {
			pdutype = InformRequest
			// Per RFC 3414 Section 4:
			// When sending an SNMPv3 InformRequest, the Reportable flag MUST be set in MsgFlags.
			// This ensures that the authoritative engine will return a Report PDU containing
			// engineBoots and engineTime for time synchronization which is required before
			// authenticated communication can succeed. Without this, the engine may reject
			// the Inform as out-of-time-window or unknown engine.
			x.MsgFlags = (x.MsgFlags | Reportable)
		}

		if trap.Variables[0].Type != TimeTicks {
			now := uint32(time.Now().Unix()) //nolint:gosec
			timetickPDU := SnmpPDU{Name: "1.3.6.1.2.1.1.3.0", Type: TimeTicks, Value: now}
			// prepend timetickPDU
			trap.Variables = append([]SnmpPDU{timetickPDU}, trap.Variables...)
		}

	case Version1:
		pdutype = Trap
		if len(trap.Enterprise) == 0 {
			return nil, fmt.Errorf("function SendTrap for SNMPV1 requires an Enterprise OID")
		}
		if len(trap.AgentAddress) == 0 {
			return nil, fmt.Errorf("function SendTrap for SNMPV1 requires an Agent Address")
		}

	default:
		err = fmt.Errorf("function SendTrap doesn't support %s", x.Version)
		return nil, err
	}

	packetOut := x.mkSnmpPacket(pdutype, trap.Variables, 0, 0)
	if x.Version == Version1 {
		packetOut.Enterprise = trap.Enterprise
		packetOut.AgentAddress = trap.AgentAddress
		packetOut.GenericTrap = trap.GenericTrap
		packetOut.SpecificTrap = trap.SpecificTrap
		packetOut.Timestamp = trap.Timestamp
	}

	// all sends wait for the return packet, except for SNMPv2Trap
	// -> wait is only for informs
	return x.send(packetOut, trap.IsInform)
}

//
// Receiving Traps ie GoSNMP acting as an NMS (Network Management
// Station).
//
// GoSNMP.unmarshal() currently only handles SNMPv2Trap
//

// A TrapListener defines parameters for running a SNMP Trap receiver.
// nil values will be replaced by default values.
type TrapListener struct {
	done      chan bool
	listening chan bool
	sync.Mutex

	// Params is a reference to the TrapListener's "parent" GoSNMP instance.
	Params *GoSNMP

	// OnNewTrap is the legacy handler for incoming Trap and Inform PDUs.
	// It receives *net.UDPAddr which works for UDP listeners.
	//
	// Deprecated: Use OnTrap instead for TLS/DTLS support.
	// OnNewTrap continues to work for backward compatibility with existing code.
	OnNewTrap TrapHandlerFunc

	// OnTrap handles incoming Trap and Inform PDUs from any transport.
	// It receives net.Addr which is *net.UDPAddr for UDP/DTLS or *net.TCPAddr for TCP/TLS.
	// If both OnTrap and OnNewTrap are set, OnTrap takes precedence.
	OnTrap HandlerFunc

	// CloseTimeout is the max wait time for the socket to gracefully signal its closure.
	CloseTimeout time.Duration

	// TLSConfig specifies TLS configuration for TLS trap listeners.
	// Required when listening on "tls://" addresses.
	TLSConfig *tls.Config

	// DTLSConfig specifies DTLS configuration for DTLS trap listeners.
	// Required when listening on "dtls://" addresses.
	DTLSConfig *dtls.Config

	// CertMappings specifies how to map peer certificates to security names.
	// Used with TSM (Transport Security Model) for TLS/DTLS listeners.
	CertMappings []CertMapping

	// These unexported fields are for letting test cases
	// know we are ready.
	conn         *net.UDPConn  // UDP listener (keep for backward compat)
	tcpListener  net.Listener  // TCP listener
	tlsListener  net.Listener  // TLS listener
	dtlsListener net.Listener  // DTLS listener
	proto        string

	// Total number of packets received referencing an unknown snmpEngineID
	usmStatsUnknownEngineIDsCount uint32

	finish int32 // Atomic flag; set to 1 when closing connection

	buffSize uint // SNMP message buffer size
}

// Default timeout value for CloseTimeout of 3 seconds
const defaultCloseTimeout = 3 * time.Second

// TrapHandlerFunc is the legacy callback type for SNMP Trap and Inform packets.
// It receives traps with a *net.UDPAddr, which works for UDP listeners.
//
// Deprecated: Use HandlerFunc and the OnTrap field instead for TLS/DTLS support.
// OnNewTrap with TrapHandlerFunc continues to work for backward compatibility.
type TrapHandlerFunc func(s *SnmpPacket, addr *net.UDPAddr)

// HandlerFunc is the callback type for SNMP Trap and Inform packets that
// supports all transport types (UDP, TCP, TLS, DTLS).
//
// The addr parameter type depends on the transport:
//   - UDP/DTLS: *net.UDPAddr
//   - TCP/TLS: *net.TCPAddr
//
// This callback should not modify the contents of the SnmpPacket nor the
// address passed to it, and it should copy out any values it wishes to use
// instead of retaining references in order to avoid memory fragmentation.
type HandlerFunc func(s *SnmpPacket, addr net.Addr)

// NewTrapListener returns an initialized TrapListener.
//
// NOTE: the trap code is currently unreliable when working with snmpv3 - pull requests welcome
func NewTrapListener() *TrapListener {
	tl := &TrapListener{
		finish:       0,
		buffSize:     4096,
		done:         make(chan bool),
		listening:    make(chan bool, 1), // Buffered because one doesn't have to block on it.
		CloseTimeout: defaultCloseTimeout,
	}

	return tl
}

// WithBufferSize changes the snmp message buffer size of the current TrapListener
//
// NOTE: The buffer size cannot be 0 bytes, the default size is 4096 bytes
func (t *TrapListener) WithBufferSize(i uint) *TrapListener {
	if i < 1 {
		i = 1
	}

	t.buffSize = i
	return t
}

// Listening returns a sentinel channel on which one can block
// until the listener is ready to receive requests.
//
// NOTE: the trap code is currently unreliable when working with snmpv3 - pull requests welcome
func (t *TrapListener) Listening() <-chan bool {
	t.Lock()
	defer t.Unlock()
	return t.listening
}

// Close terminates the listening on TrapListener socket
func (t *TrapListener) Close() {
	if atomic.CompareAndSwapInt32(&t.finish, 0, 1) {
		t.Lock()
		defer t.Unlock()

		// Close whichever listener is active
		var closeErr error
		switch {
		case t.conn != nil:
			closeErr = t.conn.Close()
		case t.tcpListener != nil:
			closeErr = t.tcpListener.Close()
		case t.tlsListener != nil:
			closeErr = t.tlsListener.Close()
		case t.dtlsListener != nil:
			closeErr = t.dtlsListener.Close()
		default:
			return // No listener to close
		}

		if closeErr != nil {
			t.Params.Logger.Printf("failed to Close() the TrapListener socket: %s", closeErr)
		}

		select {
		case <-t.done:
		case <-time.After(t.CloseTimeout): // A timeout can prevent blocking forever
			t.Params.Logger.Printf("timeout while awaiting done signal on TrapListener Close()")
		}
	}
}

// SendUDP sends a given SnmpPacket to the provided address using the currently opened connection.
func (t *TrapListener) SendUDP(packet *SnmpPacket, addr *net.UDPAddr) error {
	ob, err := packet.marshalMsg()
	if err != nil {
		return fmt.Errorf("error marshaling SnmpPacket: %w", err)
	}

	// Send the return packet back.
	count, err := t.conn.WriteTo(ob, addr)
	if err != nil {
		return fmt.Errorf("error sending SnmpPacket: %w", err)
	}

	// This isn't fatal, but should be logged.
	if count != len(ob) {
		t.Params.Logger.Printf("Failed to send all bytes of SnmpPacket!\n")
	}
	return nil
}

func (t *TrapListener) listenUDP(addr string) error {
	// udp

	udpAddr, err := net.ResolveUDPAddr(t.proto, addr)
	if err != nil {
		return err
	}
	t.conn, err = net.ListenUDP(udp, udpAddr)
	if err != nil {
		return err
	}

	defer t.conn.Close()

	// Mark that we are listening now.
	t.listening <- true

	for {
		switch {
		case atomic.LoadInt32(&t.finish) == 1:
			t.done <- true
			return nil

		default:
			buf := make([]byte, t.buffSize)
			rlen, remote, err := t.conn.ReadFromUDP(buf)
			if err != nil {
				if atomic.LoadInt32(&t.finish) == 1 {
					// err most likely comes from reading from a closed connection
					continue
				}
				t.Params.Logger.Printf("TrapListener: error in read %s\n", err)
				continue
			}

			msg := buf[:rlen]
			trap, err := t.Params.UnmarshalTrap(msg, false)
			if err != nil {
				t.Params.Logger.Printf("TrapListener: error in UnmarshalTrap %s\n", err)
				continue
			}
			if trap.Version == Version3 && trap.SecurityModel == UserSecurityModel && t.Params.SecurityModel == UserSecurityModel {
				securityParams, ok := t.Params.SecurityParameters.(*UsmSecurityParameters)
				if !ok {
					t.Params.Logger.Printf("TrapListener: Invalid SecurityParameters types")
				}
				packetSecurityParams, ok := trap.SecurityParameters.(*UsmSecurityParameters)
				if !ok {
					t.Params.Logger.Printf("TrapListener: Invalid SecurityParameters types")
				}
				snmpEngineID := securityParams.AuthoritativeEngineID
				msgAuthoritativeEngineID := packetSecurityParams.AuthoritativeEngineID
				if msgAuthoritativeEngineID != snmpEngineID {
					if len(msgAuthoritativeEngineID) < 5 || len(msgAuthoritativeEngineID) > 32 {
						// RFC3411 section 5. – SnmpEngineID definition.
						// SnmpEngineID is an OCTET STRING which size should be between 5 and 32
						// According to RFC3414 3.2.3b: stop processing and report
						// the listener authoritative engine ID
						atomic.AddUint32(&t.usmStatsUnknownEngineIDsCount, 1)
						err := t.reportAuthoritativeEngineID(trap, snmpEngineID, remote)
						if err != nil {
							t.Params.Logger.Printf("TrapListener: %s\n", err)
						}
						continue
					}
					// RFC3414 3.2.3a: Continue processing
				}
			}
			// Here we assume that the trap handler will not alter the contents
			// of the PDU (per documentation, because Go does not have
			// compile-time const checking).  We don't pass a copy because
			// the SnmpPacket type is somewhat large, but we could without
			// violating any implicit or explicit spec.
			t.dispatchTrap(trap, remote)

			// If it was an Inform request, we need to send a response.
			if trap.PDUType == InformRequest { //nolint:whitespace

				// Reuse the packet, since we're supposed to send it back
				// with the exact same variables unless there's an error.
				// Change the PDUType to the response, though.
				trap.PDUType = GetResponse

				// If the response can be sent, the error-status is
				// supposed to be set to noError and the error-index set to
				// zero.
				trap.Error = NoError
				trap.ErrorIndex = 0

				// TODO: Check that the message marshalled is not too large
				// for the originator to accept and if so, send a tooBig
				// error PDU per RFC3416 section 4.2.7.  This maximum size,
				// however, does not have a well-defined mechanism in the
				// RFC other than using the path MTU (which is difficult to
				// determine), so it's left to future implementations.
				err := t.SendUDP(trap, remote)
				if err != nil {
					t.Params.Logger.Printf("TrapListener: %s\n", err)
				}
			}
		}
	}
}

func (t *TrapListener) reportAuthoritativeEngineID(trap *SnmpPacket, snmpEngineID string, addr *net.UDPAddr) error {
	newSecurityParams, ok := trap.SecurityParameters.Copy().(*UsmSecurityParameters)
	if !ok {
		return errors.New("unable to cast SecurityParams to UsmSecurityParameters")
	}
	newSecurityParams.AuthoritativeEngineID = snmpEngineID
	reportPacket := trap
	reportPacket.PDUType = Report
	reportPacket.MsgFlags &= AuthPriv
	reportPacket.SecurityParameters = newSecurityParams
	reportPacket.Variables = []SnmpPDU{
		{
			Name:  usmStatsUnknownEngineIDs,
			Value: int(atomic.LoadUint32(&t.usmStatsUnknownEngineIDsCount)),
			Type:  Integer,
		},
	}
	return t.SendUDP(reportPacket, addr)
}

func (t *TrapListener) handleTCPRequest(conn net.Conn) {
	// Make a buffer to hold incoming data.
	buf := make([]byte, 4096)
	// Read the incoming connection into the buffer.
	reqLen, err := conn.Read(buf)
	if err != nil {
		t.Params.Logger.Printf("TrapListener: error in read %s\n", err)
		return
	}

	msg := buf[:reqLen]
	traps, err := t.Params.UnmarshalTrap(msg, false)
	if err != nil {
		t.Params.Logger.Printf("TrapListener: error in unmarshal %s\n", err)
		return
	}
	t.dispatchTrap(traps, conn.RemoteAddr())
	// Close the connection when you're done with it.
	conn.Close()
}

func (t *TrapListener) listenTCP(addr string) error {
	tcpAddr, err := net.ResolveTCPAddr(t.proto, addr)
	if err != nil {
		return err
	}

	l, err := net.ListenTCP(tcp, tcpAddr)
	if err != nil {
		return err
	}

	defer l.Close()

	// Mark that we are listening now.
	t.listening <- true

	for {
		switch {
		case atomic.LoadInt32(&t.finish) == 1:
			t.done <- true
			return nil
		default:

			// Listen for an incoming connection.
			conn, err := l.Accept()
			if err != nil {
				if atomic.LoadInt32(&t.finish) == 1 {
					t.done <- true
					return nil
				}
				t.Params.Logger.Printf("TrapListener: error accepting TCP connection: %s\n", err)
				continue
			}
			// Handle connections in a new goroutine.
			go t.handleTCPRequest(conn)
		}
	}
}

// Listen listens on the UDP address addr and calls the OnNewTrap
// function specified in *TrapListener for every trap received.
//
// NOTE: the trap code is currently unreliable when working with snmpv3 - pull requests welcome
func (t *TrapListener) Listen(addr string) error {
	if t.Params == nil {
		t.Params = Default
	}

	// TODO TODO returning an error cause the following to hang/break
	// TestSendTrapBasic
	// TestSendTrapWithoutWaitingOnListen
	// TestSendV1Trap
	_ = t.Params.validateParameters()

	// Set default handler if neither is set
	if t.OnTrap == nil && t.OnNewTrap == nil {
		t.OnTrap = t.debugTrapHandler
	}

	splitted := strings.SplitN(addr, "://", 2)
	t.proto = udp
	if len(splitted) > 1 {
		t.proto = splitted[0]
		addr = splitted[1]
	}

	switch t.proto {
	case tcp:
		return t.listenTCP(addr)
	case udp:
		return t.listenUDP(addr)
	case "tls":
		return t.listenTLS(addr)
	case "dtls":
		return t.listenDTLS(addr)
	default:
		return fmt.Errorf("not implemented network protocol: %s [use: tcp/udp/tls/dtls]", t.proto)
	}
}

// debugTrapHandler is the default handler that logs received traps.
func (t *TrapListener) debugTrapHandler(s *SnmpPacket, addr net.Addr) {
	t.Params.Logger.Printf("got trapdata from %+v: %+v\n", addr, s)
}

// dispatchTrap sends the trap to the appropriate handler.
// It prefers OnTrap (new API) over OnNewTrap (legacy API).
// For TCP/TLS transports with only OnNewTrap set, it synthesizes a *net.UDPAddr.
func (t *TrapListener) dispatchTrap(p *SnmpPacket, addr net.Addr) {
	// Prefer new generic handler
	if t.OnTrap != nil {
		t.OnTrap(p, addr)
		return
	}

	// Fallback to legacy handler
	if t.OnNewTrap != nil {
		// Fast path for UDP/DTLS - direct pass-through
		if udpAddr, ok := addr.(*net.UDPAddr); ok {
			t.OnNewTrap(p, udpAddr)
			return
		}

		// Synthesize UDPAddr for TCP/TLS (best-effort backward compat)
		if tcpAddr, ok := addr.(*net.TCPAddr); ok {
			t.Params.Logger.Printf("TrapListener: synthesizing UDPAddr from TCPAddr for legacy OnNewTrap handler\n")
			t.OnNewTrap(p, &net.UDPAddr{IP: tcpAddr.IP, Port: tcpAddr.Port, Zone: tcpAddr.Zone})
			return
		}

		// Unknown address type - synthesize empty UDPAddr
		t.Params.Logger.Printf("TrapListener: unknown address type %T, using empty UDPAddr\n", addr)
		t.OnNewTrap(p, &net.UDPAddr{})
	}
}

// UnmarshalTrap unpacks the SNMP Trap.
func (x *GoSNMP) UnmarshalTrap(trap []byte, useResponseSecurityParameters bool) (result *SnmpPacket, err error) {
	// Get only the version from the header of the trap
	version, _, err := x.unmarshalVersionFromHeader(trap, new(SnmpPacket))
	if err != nil {
		x.Logger.Printf("UnmarshalTrap version unmarshal: %s\n", err)
		return nil, err
	}
	// If there are multiple users configured and the SNMP trap is v3, see which user has valid credentials
	// by iterating through the list matching the identifier and seeing which credentials are authentic / can be used to decrypt
	if x.TrapSecurityParametersTable != nil && version == Version3 {
		identifier, err := x.getTrapIdentifier(trap)
		if err != nil {
			x.Logger.Printf("UnmarshalTrap V3 get trap identifier: %s\n", err)
			return nil, err
		}
		secParamsList, err := x.TrapSecurityParametersTable.Get(identifier)
		if err != nil {
			x.Logger.Printf("UnmarshalTrap V3 get security parameters from table: %s\n", err)
			return nil, err
		}
		for _, secParams := range secParamsList {
			// Copy the trap and pass the security parameters to try to unmarshal with
			cpTrap := make([]byte, len(trap))
			copy(cpTrap, trap)
			if result, err = x.unmarshalTrapBase(cpTrap, secParams.Copy(), true); err == nil {
				return result, nil
			}
		}
		return nil, fmt.Errorf("no credentials successfully unmarshaled trap: %w", err)
	}
	return x.unmarshalTrapBase(trap, nil, useResponseSecurityParameters)
}

func (x *GoSNMP) getTrapIdentifier(trap []byte) (string, error) {
	// Initialize a packet with no auth/priv to unmarshal ID/key for security parameters to use
	packet := new(SnmpPacket)
	_, err := x.unmarshalHeader(trap, packet)
	// Return err if no identifier was able to be parsed after unmarshaling
	if err != nil && packet.SecurityParameters.getIdentifier() == "" {
		return "", err
	}
	return packet.SecurityParameters.getIdentifier(), nil
}

func (x *GoSNMP) unmarshalTrapBase(trap []byte, sp SnmpV3SecurityParameters, useResponseSecurityParameters bool) (*SnmpPacket, error) {
	result := new(SnmpPacket)

	if x.SecurityParameters != nil && sp == nil {
		err := x.SecurityParameters.InitSecurityKeys()
		if err != nil {
			return nil, err
		}
		result.SecurityParameters = x.SecurityParameters.Copy()
	} else {
		result.SecurityParameters = sp
	}

	cursor, err := x.unmarshalHeader(trap, result)
	if err != nil {
		x.Logger.Printf("UnmarshalTrap: %s\n", err)
		return nil, err
	}

	if result.Version == Version3 {
		if result.SecurityModel == UserSecurityModel {
			err = x.testAuthentication(trap, result, useResponseSecurityParameters)
			if err != nil {
				x.Logger.Printf("UnmarshalTrap v3 auth: %s\n", err)
				return nil, err
			}
		}

		trap, cursor, err = x.decryptPacket(trap, cursor, result)
		if err != nil {
			x.Logger.Printf("UnmarshalTrap v3 decrypt: %s\n", err)
			return nil, err
		}
	}
	err = x.unmarshalPayload(trap, cursor, result)
	if err != nil {
		x.Logger.Printf("UnmarshalTrap: %s\n", err)
		return nil, err
	}
	return result, nil
}

// listenTLS listens for SNMP traps over TLS.
func (t *TrapListener) listenTLS(addr string) error {
	if t.TLSConfig == nil {
		return errors.New("TLSConfig required for TLS trap listener")
	}

	// Require client certs for TSM
	t.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert

	// Enforce RFC 9456 minimum
	if t.TLSConfig.MinVersion != 0 && t.TLSConfig.MinVersion < tls.VersionTLS12 {
		return errors.New("RFC 9456 requires TLS 1.2 minimum")
	}
	if t.TLSConfig.MinVersion == 0 {
		t.TLSConfig.MinVersion = tls.VersionTLS12
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}

	tcpListener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}

	t.tlsListener = tls.NewListener(tcpListener, t.TLSConfig)
	t.listening <- true

	for {
		if atomic.LoadInt32(&t.finish) == 1 {
			t.done <- true
			return nil
		}

		conn, err := t.tlsListener.Accept()
		if err != nil {
			if atomic.LoadInt32(&t.finish) == 1 {
				t.done <- true
				return nil
			}
			continue
		}
		go t.handleTLSConnection(conn.(*tls.Conn))
	}
}

// handleTLSConnection handles a single TLS connection with trap data.
func (t *TrapListener) handleTLSConnection(conn *tls.Conn) {
	defer conn.Close()

	// Perform TLS handshake explicitly to access peer certs
	if err := conn.Handshake(); err != nil {
		t.Params.Logger.Printf("TLS handshake failed: %s\n", err)
		return
	}

	buf := make([]byte, t.buffSize)
	n, err := conn.Read(buf)
	if err != nil {
		t.Params.Logger.Printf("TLS read error: %s\n", err)
		return
	}

	trap, err := t.Params.UnmarshalTrap(buf[:n], false)
	if err != nil {
		t.Params.Logger.Printf("TLS unmarshal error: %s\n", err)
		return
	}

	// Inject TSM identity from TLS peer cert
	if trap.SecurityModel == TransportSecurityModel {
		t.injectTsmIdentityFromTLS(conn, trap)
	}

	t.dispatchTrap(trap, conn.RemoteAddr())

	// Handle Inform response
	if trap.PDUType == InformRequest {
		t.sendTLSInformResponse(conn, trap)
	}
}

// injectTsmIdentityFromTLS extracts security name from TLS peer certificate.
func (t *TrapListener) injectTsmIdentityFromTLS(conn *tls.Conn, trap *SnmpPacket) {
	tsmParams, ok := trap.SecurityParameters.(*TsmSecurityParameters)
	if !ok {
		return
	}

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return
	}

	if len(t.CertMappings) > 0 {
		secName, err := ExtractSecurityName(state.PeerCertificates[0], t.CertMappings)
		if err != nil {
			t.Params.Logger.Printf("TLS: failed to extract securityName: %v\n", err)
			return
		}
		tsmParams.SecurityName = secName
	}
}

// sendTLSInformResponse sends a response to an Inform request over TLS.
func (t *TrapListener) sendTLSInformResponse(conn *tls.Conn, trap *SnmpPacket) {
	trap.PDUType = GetResponse
	trap.Error = NoError
	trap.ErrorIndex = 0

	respBytes, err := trap.marshalMsg()
	if err != nil {
		t.Params.Logger.Printf("TLS: failed to marshal Inform response: %s\n", err)
		return
	}

	if _, err := conn.Write(respBytes); err != nil {
		t.Params.Logger.Printf("TLS: failed to send Inform response: %s\n", err)
	}
}

// listenDTLS listens for SNMP traps over DTLS.
func (t *TrapListener) listenDTLS(addr string) error {
	if t.DTLSConfig == nil {
		return errors.New("DTLSConfig required for DTLS trap listener")
	}

	// Require client certs for TSM
	t.DTLSConfig.ClientAuth = dtls.RequireAndVerifyClientCert

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	listener, err := dtls.Listen("udp", udpAddr, t.DTLSConfig)
	if err != nil {
		return err
	}
	t.dtlsListener = listener
	t.listening <- true

	for {
		if atomic.LoadInt32(&t.finish) == 1 {
			t.done <- true
			return nil
		}

		conn, err := listener.Accept()
		if err != nil {
			if atomic.LoadInt32(&t.finish) == 1 {
				t.done <- true
				return nil
			}
			continue
		}
		go t.handleDTLSConnection(conn.(*dtls.Conn))
	}
}

// handleDTLSConnection handles a single DTLS connection with trap data.
func (t *TrapListener) handleDTLSConnection(conn *dtls.Conn) {
	defer conn.Close()

	buf := make([]byte, t.buffSize)
	n, err := conn.Read(buf)
	if err != nil {
		t.Params.Logger.Printf("DTLS read error: %s\n", err)
		return
	}

	trap, err := t.Params.UnmarshalTrap(buf[:n], false)
	if err != nil {
		t.Params.Logger.Printf("DTLS unmarshal error: %s\n", err)
		return
	}

	// Inject TSM identity from DTLS peer cert
	if trap.SecurityModel == TransportSecurityModel {
		t.injectTsmIdentityFromDTLS(conn, trap)
	}

	t.dispatchTrap(trap, conn.RemoteAddr())

	// Handle Inform response
	if trap.PDUType == InformRequest {
		t.sendDTLSInformResponse(conn, trap)
	}
}

// injectTsmIdentityFromDTLS extracts security name from DTLS peer certificate.
func (t *TrapListener) injectTsmIdentityFromDTLS(conn *dtls.Conn, trap *SnmpPacket) {
	tsmParams, ok := trap.SecurityParameters.(*TsmSecurityParameters)
	if !ok {
		return
	}

	state, ok := conn.ConnectionState()
	if !ok || len(state.PeerCertificates) == 0 {
		return
	}

	// pion/dtls returns raw DER, must parse
	cert, err := x509.ParseCertificate(state.PeerCertificates[0])
	if err != nil {
		t.Params.Logger.Printf("DTLS: failed to parse peer cert: %v\n", err)
		return
	}

	if len(t.CertMappings) > 0 {
		secName, err := ExtractSecurityName(cert, t.CertMappings)
		if err != nil {
			t.Params.Logger.Printf("DTLS: failed to extract securityName: %v\n", err)
			return
		}
		tsmParams.SecurityName = secName
	}
}

// sendDTLSInformResponse sends a response to an Inform request over DTLS.
func (t *TrapListener) sendDTLSInformResponse(conn *dtls.Conn, trap *SnmpPacket) {
	trap.PDUType = GetResponse
	trap.Error = NoError
	trap.ErrorIndex = 0

	respBytes, err := trap.marshalMsg()
	if err != nil {
		t.Params.Logger.Printf("DTLS: failed to marshal Inform response: %s\n", err)
		return
	}

	if _, err := conn.Write(respBytes); err != nil {
		t.Params.Logger.Printf("DTLS: failed to send Inform response: %s\n", err)
	}
}
