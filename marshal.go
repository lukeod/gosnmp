// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

//
// Remaining globals and definitions located here.
// See http://www.rane.com/note161.html for a succint description of the SNMP
// protocol.
//

// SnmpVersion 1, 2c and 3 implemented
type SnmpVersion uint8

// SnmpVersion 1, 2c and 3 implemented
const (
	Version1  SnmpVersion = 0x0
	Version2c SnmpVersion = 0x1
	Version3  SnmpVersion = 0x3
)

// SnmpPacket struct represents the entire SNMP Message or Sequence at the
// application layer.
type SnmpPacket struct {
	Version            SnmpVersion
	MsgFlags           SnmpV3MsgFlags
	SecurityModel      SnmpV3SecurityModel
	SecurityParameters SnmpV3SecurityParameters // interface
	ContextEngineID    string
	ContextName        string
	Community          string
	PDUType            PDUType
	MsgID              uint32
	RequestID          uint32
	MsgMaxSize         uint32
	Error              SNMPError
	ErrorIndex         uint8
	NonRepeaters       uint8
	MaxRepetitions     uint32
	Variables          []SnmpPDU
	Logger             Logger

	// v1 traps have a very different format from v2c and v3 traps.
	//
	// These fields are set via the SnmpTrap parameter to SendTrap().
	SnmpTrap
}

// SnmpTrap is used to define a SNMP trap, and is passed into SendTrap
type SnmpTrap struct {
	Variables []SnmpPDU

	// If true, the trap is an InformRequest, not a trap. This has no effect on
	// v1 traps, as Inform is not part of the v1 protocol.
	IsInform bool

	// These fields are required for SNMPV1 Trap Headers
	Enterprise   string
	AgentAddress string
	GenericTrap  int
	SpecificTrap int
	Timestamp    uint
}

// VarBind struct represents an SNMP Varbind.
type VarBind struct {
	Name  asn1.ObjectIdentifier
	Value asn1.RawValue
}

// PDUType describes which SNMP Protocol Data Unit is being sent.
type PDUType byte

// The currently supported PDUType's
const (
	Sequence       PDUType = 0x30
	GetRequest     PDUType = 0xa0
	GetNextRequest PDUType = 0xa1
	GetResponse    PDUType = 0xa2
	SetRequest     PDUType = 0xa3
	Trap           PDUType = 0xa4 // v1
	GetBulkRequest PDUType = 0xa5
	InformRequest  PDUType = 0xa6
	SNMPv2Trap     PDUType = 0xa7 // v2c, v3
	Report         PDUType = 0xa8 // v3
)

//go:generate stringer -type=PDUType

// SNMPv3: User-based Security Model Report PDUs and
// error types as per https://tools.ietf.org/html/rfc3414
const (
	usmStatsUnsupportedSecLevels = ".1.3.6.1.6.3.15.1.1.1.0"
	usmStatsNotInTimeWindows     = ".1.3.6.1.6.3.15.1.1.2.0"
	usmStatsUnknownUserNames     = ".1.3.6.1.6.3.15.1.1.3.0"
	usmStatsUnknownEngineIDs     = ".1.3.6.1.6.3.15.1.1.4.0"
	usmStatsWrongDigests         = ".1.3.6.1.6.3.15.1.1.5.0"
	usmStatsDecryptionErrors     = ".1.3.6.1.6.3.15.1.1.6.0"
	snmpUnknownSecurityModels    = ".1.3.6.1.6.3.11.2.1.1.0"
	snmpInvalidMsgs              = ".1.3.6.1.6.3.11.2.1.2.0"
	snmpUnknownPDUHandlers       = ".1.3.6.1.6.3.11.2.1.3.0"
)

var (
	ErrDecryption            = errors.New("decryption error")
	ErrInvalidMsgs           = errors.New("invalid messages")
	ErrNotInTimeWindow       = errors.New("not in time window")
	ErrUnknownEngineID       = errors.New("unknown engine id")
	ErrUnknownPDUHandlers    = errors.New("unknown pdu handlers")
	ErrUnknownReportPDU      = errors.New("unknown report pdu")
	ErrUnknownSecurityLevel  = errors.New("unknown security level")
	ErrUnknownSecurityModels = errors.New("unknown security models")
	ErrUnknownUsername       = errors.New("unknown username")
	ErrWrongDigest           = errors.New("wrong digest")
)

const rxBufSize = 65535 // max size of IPv4 & IPv6 packet

// Logger is an interface used for debugging. Both Print and
// Printf have the same interfaces as Package Log in the std library. The
// Logger interface is small to give you flexibility in how you do
// your debugging.
//

// Logger
// For verbose logging to stdout:
// gosnmp_logger = NewLogger(log.New(os.Stdout, "", 0))
type LoggerInterface interface {
	Print(v ...any)
	Printf(format string, v ...any)
}

type Logger struct {
	logger LoggerInterface
}

func NewLogger(logger LoggerInterface) Logger {
	return Logger{
		logger: logger,
	}
}

func (packet *SnmpPacket) SafeString() string {
	sp := ""
	if packet.SecurityParameters != nil {
		sp = packet.SecurityParameters.SafeString()
	}
	return fmt.Sprintf("Version:%s, MsgFlags:%s, SecurityModel:%s, SecurityParameters:%s, ContextEngineID:%s, ContextName:%s, Community:%s, PDUType:%s, MsgID:%d, RequestID:%d, MsgMaxSize:%d, Error:%s, ErrorIndex:%d, NonRepeaters:%d, MaxRepetitions:%d, Variables:%v",
		packet.Version,
		packet.MsgFlags,
		packet.SecurityModel,
		sp,
		packet.ContextEngineID,
		packet.ContextName,
		packet.Community,
		packet.PDUType,
		packet.MsgID,
		packet.RequestID,
		packet.MsgMaxSize,
		packet.Error,
		packet.ErrorIndex,
		packet.NonRepeaters,
		packet.MaxRepetitions,
		packet.Variables,
	)
}

// sendOneRequest sends/receives one SNMP request, handling retries.
func (x *GoSNMP) sendOneRequest(packetOut *SnmpPacket,
	wait bool) (result *SnmpPacket, err error) {
	allReqIDs := make([]uint32, 0, x.Retries+1)
	timeout := x.Timeout
	withContextDeadline := false
	var lastErr error
	var lastResult *SnmpPacket

	for attempt := 0; attempt <= x.Retries; attempt++ {
		if attempt > 0 {
			if x.OnRetry != nil {
				x.OnRetry(x)
			}
			x.Logger.Printf("Retry number %d. Last error was: %v", attempt, lastErr)
			if withContextDeadline && isTimeoutError(lastErr) {
				return lastResult, context.DeadlineExceeded
			}
			if x.ExponentialTimeout {
				timeout *= 2
			}
			withContextDeadline = false
		}

		if x.Context.Err() != nil {
			return lastResult, x.Context.Err()
		}

		reqDeadline := time.Now().Add(timeout)
		if contextDeadline, ok := x.Context.Deadline(); ok {
			if contextDeadline.Before(reqDeadline) {
				reqDeadline = contextDeadline
				withContextDeadline = true
			}
		}

		reqID := atomic.AddUint32(&x.requestID, 1) & 0x7FFFFFFF
		allReqIDs = append(allReqIDs, reqID)
		packetOut.RequestID = reqID

		result, err = x.doRequestAttempt(packetOut, allReqIDs, reqDeadline, wait)
		if err == nil {
			if x.OnFinish != nil {
				x.OnFinish(x)
			}
			return result, nil
		}

		if isV3ErrorNonRetriable(err) {
			return result, err
		}

		lastErr = err
		if result != nil {
			lastResult = result
		}
	}

	// Return the last error, replacing with "request timeout" only if it was a timeout
	if lastErr != nil && isTimeoutError(lastErr) {
		return lastResult, fmt.Errorf("request timeout (after %d retries)", x.Retries)
	}
	if lastErr != nil {
		return lastResult, lastErr
	}
	return lastResult, fmt.Errorf("request timeout (after %d retries)", x.Retries)
}

// generic "sender" that negotiate any version of snmp request
//

func (x *GoSNMP) send(packetOut *SnmpPacket, wait bool) (result *SnmpPacket, err error) {
	defer func() {
		if e := recover(); e != nil {
			var buf = make([]byte, 8192)
			runtime.Stack(buf, true)

			err = fmt.Errorf("recover: %v Stack:%v", e, string(buf))
		}
	}()

	if x.Conn == nil {
		return nil, fmt.Errorf("&GoSNMP.Conn is missing. Provide a connection or use Connect()")
	}

	if x.Retries < 0 {
		x.Retries = 0
	}
	x.Logger.Print("SEND INIT")
	if packetOut.Version == Version3 {
		x.Logger.Print("SEND INIT NEGOTIATE SECURITY PARAMS")
		if err = x.negotiateInitialSecurityParameters(packetOut); err != nil {
			return &SnmpPacket{}, err
		}
		x.Logger.Print("SEND END NEGOTIATE SECURITY PARAMS")
	}

	result, err = x.sendOneRequest(packetOut, wait)
	if err != nil {
		x.Logger.Printf("SEND Error: %s", err)
		return result, err
	}

	// Engine ID discovery: agent told us our engine ID is unknown.
	// Update our parameters with the discovered ID and retry.
	if result.Version == Version3 && result.PDUType == Report && len(result.Variables) >= 1 {
		if result.Variables[0].Name == usmStatsUnknownEngineIDs {
			x.Logger.Print("SEND handling unknown engine id REPORT")
			if err = x.updatePktSecurityParameters(packetOut); err != nil {
				x.Logger.Printf("ERROR updatePktSecurityParameters error: %s", err)
				return nil, err
			}
			result, err = x.sendOneRequest(packetOut, wait)
			if err != nil {
				x.Logger.Printf("ERROR unknown engine id retransmit error: %s", err)
				return result, ErrUnknownEngineID
			}
		}
	}

	// Cache security parameters for future requests. Failure is non-fatal because
	// this request already succeeded - caching just optimizes subsequent requests.
	if result.Version == Version3 && result.SecurityParameters != nil {
		x.Logger.Printf("SEND STORE SECURITY PARAMS: %s", result.SecurityParameters.SafeString())
		if err := x.storeSecurityParameters(result); err != nil {
			x.Logger.Printf("storeSecurityParameters failed (continuing): %v", err)
		}
	}

	return result, nil
}

// SNMPv3 Request Flow
//
// Requests go through: send() -> sendOneRequest() -> doRequestAttempt()
//
// There are two levels of retry:
//
//  1. sendOneRequest() handles the outer retry loop (timeouts, up to Retries attempts)
//  2. doRequestAttempt() handles inline resend for clock sync (notInTimeWindows REPORT)
//
// The inline resend exists because clock drift is recoverable mid-request: we adopt
// the agent's time from the REPORT and immediately retry. This is transparent to the
// caller per RFC 3414 section 4.
//
// unknownEngineIDs is handled differently - it returns to send() for retry because
// engine ID discovery is typically an initial setup phase, not mid-session recovery.

// responseOutcome indicates how to proceed after processing a received packet.
type responseOutcome int

const (
	outcomeSuccess      responseOutcome = iota // Return result to caller
	outcomeResend                              // Recoverable REPORT, resend once
	outcomeContinueWait                        // Wrong request ID, keep waiting
	outcomeRetry                               // Start new attempt (timeout, etc.)
	outcomeFatal                               // Non-recoverable error
)

// isValidRequestID checks if the result's request ID matches any of the sent request IDs.
// ID 0 is always valid per RFC 3412 section 7.1 step 3(c): the request-id in a Report
// PDU is set to the original request's ID if extractable, otherwise 0.
func isValidRequestID(resultID uint32, allReqIDs []uint32) bool {
	if resultID == 0 {
		return true
	}
	return slices.Contains(allReqIDs, resultID)
}

// isV3ErrorNonRetriable returns true for SNMPv3 errors that should not trigger
// outer-level retries. This includes both inherently fatal errors (wrong credentials)
// and recoverable errors that have already failed their inline resend attempt.
func isV3ErrorNonRetriable(err error) bool {
	return errors.Is(err, ErrNotInTimeWindow) ||
		errors.Is(err, ErrUnknownEngineID) ||
		errors.Is(err, ErrWrongDigest) ||
		errors.Is(err, ErrUnknownSecurityLevel) ||
		errors.Is(err, ErrUnknownUsername) ||
		errors.Is(err, ErrDecryption) ||
		errors.Is(err, ErrUnknownSecurityModels) ||
		errors.Is(err, ErrInvalidMsgs) ||
		errors.Is(err, ErrUnknownPDUHandlers) ||
		errors.Is(err, ErrUnknownReportPDU)
}

// isTimeoutError returns true if the error represents a timeout condition.
func isTimeoutError(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return errors.Is(err, os.ErrDeadlineExceeded)
}

// sendPacket sends the outgoing packet bytes to the network.
func (x *GoSNMP) sendPacket(outBuf []byte, deadline time.Time) error {
	if err := x.Conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	if uconn, ok := x.Conn.(net.PacketConn); ok && x.uaddr != nil {
		if _, err := uconn.WriteTo(outBuf, x.uaddr); err != nil {
			return fmt.Errorf("udp write: %w", err)
		}
		return nil
	}
	if _, err := x.Conn.Write(outBuf); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// peekV3PDUType extracts the PDU type (Report, GetResponse, etc.) from a V3 message
// without fully parsing it. Used to detect REPORTs before authentication, since
// REPORTs may be sent with noAuthNoPriv per RFC 3414 section 11.4.
// Returns ok=false if the payload is encrypted or malformed.
func peekV3PDUType(resp []byte, cursor int, log Logger) (PDUType, bool) {
	if cursor >= len(resp) {
		return 0, false
	}
	switch PDUType(resp[cursor]) {
	case PDUType(OctetString):
		return 0, false // encrypted - cannot peek
	case Sequence:
		// plaintext - continue parsing
	default:
		return 0, false
	}

	// Navigate through ScopedPDU structure to reach PDU type byte:
	// SEQUENCE -> contextEngineID -> contextName -> PDU
	_, hdrLen, err := parseLength(resp[cursor:])
	if err != nil {
		log.Printf("peekV3PDUType: parse SEQUENCE err: %v", err)
		return 0, false
	}
	cursor += hdrLen
	if cursor >= len(resp) {
		return 0, false
	}

	_, consumed, err := parseRawField(log, resp[cursor:], "contextEngineID")
	if err != nil {
		log.Printf("peekV3PDUType: parse contextEngineID err: %v", err)
		return 0, false
	}
	cursor += consumed
	if cursor >= len(resp) {
		return 0, false
	}

	_, consumed, err = parseRawField(log, resp[cursor:], "contextName")
	if err != nil {
		log.Printf("peekV3PDUType: parse contextName err: %v", err)
		return 0, false
	}
	cursor += consumed
	if cursor >= len(resp) {
		return 0, false
	}

	return PDUType(resp[cursor]), true
}

// handleReportPDU classifies a REPORT PDU and determines how to proceed.
// REPORTs are SNMPv3 error responses that tell us why a request failed (e.g., clock
// out of sync, unknown engine ID, bad credentials). Some are recoverable via resend.
func (x *GoSNMP) handleReportPDU(result, packetOut *SnmpPacket,
	alreadyResent bool) (*SnmpPacket, responseOutcome, error) {
	// Cache security parameters from REPORT for future requests. Failure is non-fatal
	// because the current request already has the parameters it needs in the result.
	if err := x.storeSecurityParameters(result); err != nil {
		x.Logger.Printf("storeSecurityParameters failed (continuing): %v", err)
	}

	if len(result.Variables) < 1 {
		x.Logger.Printf("ERROR: malformed REPORT with no variables")
		return result, outcomeFatal, fmt.Errorf("malformed REPORT: no variables")
	}

	oid := result.Variables[0].Name

	switch oid {
	case usmStatsNotInTimeWindows:
		// Client clock is out of sync with agent. The REPORT contains the agent's
		// current time, which we adopt and immediately resend. Per RFC 3414 section 4,
		// this sync "happens automatically". The REPORT may be sent without authentication
		// (noAuthNoPriv) per RFC 3414 section 11.4 and RFC 3412 section 7.1 step 3(d).
		x.Logger.Print("WARNING detected out-of-time-window ERROR")

		if alreadyResent {
			return result, outcomeFatal, ErrNotInTimeWindow
		}

		if err := x.updatePktSecurityParameters(packetOut); err != nil {
			x.Logger.Printf("ERROR updatePktSecurityParameters error: %s", err)
			return result, outcomeFatal, err
		}
		if x.SecurityParameters != nil {
			packetOut.SecurityParameters = x.SecurityParameters.Copy()
		}

		return result, outcomeResend, ErrNotInTimeWindow

	case usmStatsUnknownEngineIDs:
		// Agent doesn't recognize our engine ID (typically first contact).
		// Return to send() for retry - handled differently from notInTimeWindows
		// because engine ID discovery is a distinct setup phase.
		x.Logger.Print("WARNING detected unknown engine id ERROR")
		return result, outcomeSuccess, nil

	case usmStatsWrongDigests:
		return result, outcomeFatal, ErrWrongDigest

	case usmStatsUnsupportedSecLevels:
		return result, outcomeFatal, ErrUnknownSecurityLevel

	case usmStatsUnknownUserNames:
		return result, outcomeFatal, ErrUnknownUsername

	case usmStatsDecryptionErrors:
		return result, outcomeFatal, ErrDecryption

	case snmpUnknownSecurityModels:
		return result, outcomeFatal, ErrUnknownSecurityModels

	case snmpInvalidMsgs:
		return result, outcomeFatal, ErrInvalidMsgs

	case snmpUnknownPDUHandlers:
		return result, outcomeFatal, ErrUnknownPDUHandlers

	default:
		return result, outcomeFatal, ErrUnknownReportPDU
	}
}

// receiveAndProcessResponse receives one packet and determines how to proceed.
func (x *GoSNMP) receiveAndProcessResponse(packetOut *SnmpPacket, allReqIDs []uint32,
	alreadyResent bool) (*SnmpPacket, responseOutcome, error) {
	resp, err := x.receive()
	if err != nil {
		if err == io.EOF && strings.HasPrefix(x.Transport, tcp) {
			x.Logger.Printf("EOF on TCP, reconnecting")
			if reconnErr := x.netConnect(); reconnErr != nil {
				return nil, outcomeFatal, reconnErr
			}
			return nil, outcomeRetry, err
		}
		return nil, outcomeRetry, err
	}

	if x.OnRecv != nil {
		x.OnRecv(x)
	}
	x.Logger.Printf("GET RESPONSE OK: %+v", resp)

	result := &SnmpPacket{Logger: x.Logger}
	result.MsgFlags = packetOut.MsgFlags
	if packetOut.SecurityParameters != nil {
		result.SecurityParameters = packetOut.SecurityParameters.Copy()
	}

	cursor, err := x.unmarshalHeader(resp, result)
	if err != nil {
		x.Logger.Printf("ERROR on unmarshal header: %s", err)
		return nil, outcomeRetry, err
	}

	if x.Version == Version3 {
		// REPORTs may be sent with noAuthNoPriv security level per RFC 3414 section 11.4.
		// We must skip auth verification for these or we'd reject valid REPORTs.
		skipAuth := false
		if result.MsgFlags == NoAuthNoPriv {
			if pduType, ok := peekV3PDUType(resp, cursor, x.Logger); ok && pduType == Report {
				skipAuth = true
			}
		}

		if !skipAuth {
			useResponseSP := false
			if usp, ok := x.SecurityParameters.(*UsmSecurityParameters); ok {
				useResponseSP = usp.AuthoritativeEngineID == ""
			}
			if authErr := x.testAuthentication(resp, result, useResponseSP); authErr != nil {
				x.Logger.Printf("ERROR on Test Authentication on v3: %s", authErr)
				return nil, outcomeRetry, authErr
			}
		}

		resp, cursor, err = x.decryptPacket(resp, cursor, result)
		if err != nil {
			x.Logger.Printf("ERROR on decryptPacket on v3: %s", err)
			return nil, outcomeRetry, err
		}
	}

	if err := x.unmarshalPayload(resp, cursor, result); err != nil {
		x.Logger.Printf("ERROR on UnmarshalPayload: %s", err)
		return nil, outcomeRetry, err
	}

	// Handle REPORT PDUs first (before empty check, as REPORTs have different validation)
	if result.Version == Version3 && result.PDUType == Report {
		return x.handleReportPDU(result, packetOut, alreadyResent)
	}

	if result.Error == NoError && len(result.Variables) < 1 {
		x.Logger.Printf("ERROR: empty result")
		return nil, outcomeRetry, fmt.Errorf("empty response")
	}

	if !isValidRequestID(result.RequestID, allReqIDs) {
		x.Logger.Print("ERROR out of order")
		return nil, outcomeContinueWait, nil
	}

	return result, outcomeSuccess, nil
}

// receiveUntilComplete receives packets until a complete response is received,
// a resend is needed, or an error occurs.
func (x *GoSNMP) receiveUntilComplete(packetOut *SnmpPacket, allReqIDs []uint32,
	alreadyResent bool) (result *SnmpPacket, needsResend bool, err error) {
	for {
		x.Logger.Print("WAITING RESPONSE...")

		result, outcome, err := x.receiveAndProcessResponse(packetOut, allReqIDs, alreadyResent)

		switch outcome {
		case outcomeSuccess:
			return result, false, nil
		case outcomeResend:
			return result, true, err
		case outcomeContinueWait:
			continue
		case outcomeRetry, outcomeFatal:
			return result, false, err
		default:
			return nil, false, fmt.Errorf("unexpected response outcome: %d", outcome)
		}
	}
}

// doRequestAttempt performs a single request attempt. If the agent responds with
// a recoverable REPORT (e.g., clock out of sync), we resend once with corrected
// parameters. This inline resend is separate from the outer retry loop in sendOneRequest.
func (x *GoSNMP) doRequestAttempt(packetOut *SnmpPacket, allReqIDs []uint32,
	deadline time.Time, wait bool) (*SnmpPacket, error) {
	alreadyResent := false           // prevents infinite resend loop (max one inline resend)
	var lastReportResult *SnmpPacket // preserved so caller can inspect REPORT on failure

	for {
		if x.Version == Version3 {
			packetOut.MsgID = atomic.AddUint32(&x.msgID, 1) & 0x7FFFFFFF
			if err := x.initPacket(packetOut); err != nil {
				return nil, err
			}
			packetOut.SecurityParameters.Log()
		}

		outBuf, err := packetOut.marshalMsg()
		if err != nil {
			return nil, fmt.Errorf("marshal: %w", err)
		}

		if x.PreSend != nil {
			x.PreSend(x)
		}
		x.Logger.Printf("SENDING PACKET: %s", packetOut.SafeString())

		if sendErr := x.sendPacket(outBuf, deadline); sendErr != nil {
			// Return last REPORT result if available
			if lastReportResult != nil {
				return lastReportResult, sendErr
			}
			return nil, sendErr
		}

		if x.OnSent != nil {
			x.OnSent(x)
		}

		if !wait {
			return &SnmpPacket{}, nil
		}

		// Receive until complete or resend needed
		result, needsResend, err := x.receiveUntilComplete(packetOut, allReqIDs, alreadyResent)

		if !needsResend {
			// If we have a last REPORT result and this attempt failed, return the REPORT
			if result == nil && lastReportResult != nil && err != nil {
				return lastReportResult, err
			}
			return result, err
		}

		if alreadyResent {
			return result, err
		}

		if result != nil && result.PDUType == Report {
			lastReportResult = result
		}
		alreadyResent = true
	}
}

// -- Marshalling Logic --------------------------------------------------------

// MarshalMsg marshalls a snmp packet, ready for sending across the wire
func (packet *SnmpPacket) MarshalMsg() ([]byte, error) {
	return packet.marshalMsg()
}

// marshal an SNMP message
func (packet *SnmpPacket) marshalMsg() ([]byte, error) {
	var err error
	buf := new(bytes.Buffer)

	// version
	buf.Write([]byte{2, 1, byte(packet.Version)})

	if packet.Version == Version3 {
		buf, err = packet.marshalV3(buf)
		if err != nil {
			return nil, err
		}
	} else {
		// community
		buf.Write([]byte{4, uint8(len(packet.Community))}) //nolint:gosec
		buf.WriteString(packet.Community)
		// pdu
		pdu, err2 := packet.marshalPDU()
		if err2 != nil {
			return nil, err2
		}
		buf.Write(pdu)
	}

	// build up resulting msg - sequence, length then the tail (buf)
	msg := new(bytes.Buffer)
	msg.WriteByte(byte(Sequence))

	bufLengthBytes, err2 := marshalLength(buf.Len())
	if err2 != nil {
		return nil, err2
	}
	msg.Write(bufLengthBytes)
	_, err = buf.WriteTo(msg)
	if err != nil {
		return nil, err
	}

	authenticatedMessage, err := packet.authenticate(msg.Bytes())
	if err != nil {
		return nil, err
	}

	return authenticatedMessage, nil
}

func (packet *SnmpPacket) marshalSNMPV1TrapHeader() ([]byte, error) {
	buf := new(bytes.Buffer)

	// marshal OID
	oidBytes, err := marshalObjectIdentifier(packet.Enterprise)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal OID: %w", err)
	}
	if err = marshalTLV(buf, byte(ObjectIdentifier), oidBytes); err != nil {
		return nil, err
	}

	// marshal AgentAddress (ip address)
	ip := net.ParseIP(packet.AgentAddress)
	ipAddressBytes := ipv4toBytes(ip)
	buf.Write([]byte{byte(IPAddress), byte(len(ipAddressBytes))})
	buf.Write(ipAddressBytes)

	// marshal GenericTrap. Could just cast GenericTrap to a single byte as IDs greater than 6 are unknown,
	// but do it properly. See issue 182.
	var genericTrapBytes []byte
	genericTrapBytes, err = marshalInt32(packet.GenericTrap)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal SNMPv1 GenericTrap: %w", err)
	}
	buf.Write([]byte{byte(Integer), byte(len(genericTrapBytes))})
	buf.Write(genericTrapBytes)

	// marshal SpecificTrap
	var specificTrapBytes []byte
	specificTrapBytes, err = marshalInt32(packet.SpecificTrap)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal SNMPv1 SpecificTrap: %w", err)
	}
	buf.Write([]byte{byte(Integer), byte(len(specificTrapBytes))})
	buf.Write(specificTrapBytes)

	// marshal timeTicks
	timeTickBytes, err := marshalUint32(packet.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("unable to Timestamp: %w", err)
	}
	buf.Write([]byte{byte(TimeTicks), byte(len(timeTickBytes))})
	buf.Write(timeTickBytes)

	return buf.Bytes(), nil
}

// marshal a PDU
func (packet *SnmpPacket) marshalPDU() ([]byte, error) {
	buf := new(bytes.Buffer)

	switch packet.PDUType {
	case GetBulkRequest:
		// requestid
		err := shrinkAndWriteUint(buf, int(packet.RequestID))
		if err != nil {
			return nil, err
		}

		// non repeaters
		nonRepeaters, err := marshalUint32(packet.NonRepeaters)
		if err != nil {
			return nil, fmt.Errorf("marshalPDU: unable to marshal NonRepeaters to uint32: %w", err)
		}

		buf.Write([]byte{2, byte(len(nonRepeaters))})
		if err = binary.Write(buf, binary.BigEndian, nonRepeaters); err != nil {
			return nil, fmt.Errorf("marshalPDU: unable to marshal NonRepeaters: %w", err)
		}

		// max repetitions
		maxRepetitions, err := marshalUint32(packet.MaxRepetitions)
		if err != nil {
			return nil, fmt.Errorf("marshalPDU: unable to marshal maxRepetitions to uint32: %w", err)
		}

		buf.Write([]byte{2, byte(len(maxRepetitions))})
		if err = binary.Write(buf, binary.BigEndian, maxRepetitions); err != nil {
			return nil, fmt.Errorf("marshalPDU: unable to marshal maxRepetitions: %w", err)
		}

	case Trap:
		// write SNMP V1 Trap Header fields
		snmpV1TrapHeader, err := packet.marshalSNMPV1TrapHeader()
		if err != nil {
			return nil, err
		}

		buf.Write(snmpV1TrapHeader)

	default:
		// requestid
		err := shrinkAndWriteUint(buf, int(packet.RequestID))
		if err != nil {
			return nil, err
		}

		// error status
		errorStatus, err := marshalUint32(packet.Error)
		if err != nil {
			return nil, fmt.Errorf("marshalPDU: unable to marshal errorStatus to uint32: %w", err)
		}

		buf.Write([]byte{2, byte(len(errorStatus))})
		if err = binary.Write(buf, binary.BigEndian, errorStatus); err != nil {
			return nil, fmt.Errorf("marshalPDU: unable to marshal errorStatus: %w", err)
		}

		// error index
		errorIndex, err := marshalUint32(packet.ErrorIndex)
		if err != nil {
			return nil, fmt.Errorf("marshalPDU: unable to marshal errorIndex to uint32: %w", err)
		}

		buf.Write([]byte{2, byte(len(errorIndex))})
		if err = binary.Write(buf, binary.BigEndian, errorIndex); err != nil {
			return nil, fmt.Errorf("marshalPDU: unable to marshal errorIndex: %w", err)
		}
	}

	// build varbind list
	vbl, err := packet.marshalVBL()
	if err != nil {
		return nil, fmt.Errorf("marshalPDU: unable to marshal varbind list: %w", err)
	}
	buf.Write(vbl)

	// build up resulting pdu
	pdu := new(bytes.Buffer)
	// calculate pdu length
	bufLengthBytes, err := marshalLength(buf.Len())
	if err != nil {
		return nil, fmt.Errorf("marshalPDU: unable to marshal pdu length: %w", err)
	}
	// write request type
	pdu.WriteByte(byte(packet.PDUType))
	// write pdu length
	pdu.Write(bufLengthBytes)
	// write the tail (buf)
	if _, err = buf.WriteTo(pdu); err != nil {
		return nil, fmt.Errorf("marshalPDU: unable to marshal pdu: %w", err)
	}

	return pdu.Bytes(), nil
}

// marshal a varbind list
func (packet *SnmpPacket) marshalVBL() ([]byte, error) {
	vblBuf := new(bytes.Buffer)
	for _, pdu := range packet.Variables {
		// The copy of the 'for' variable "pdu" can be deleted (Go 1.22+)
		vb, err := marshalVarbind(&pdu)
		if err != nil {
			return nil, err
		}
		vblBuf.Write(vb)
	}

	vblBytes := vblBuf.Bytes()
	vblLengthBytes, err := marshalLength(len(vblBytes))
	if err != nil {
		return nil, err
	}

	// FIX does bytes.Buffer give better performance than byte slices?
	result := []byte{byte(Sequence)}
	result = append(result, vblLengthBytes...)
	result = append(result, vblBytes...)
	return result, nil
}

// marshalVarbind encodes an SNMP variable binding (varbind) as BER.
// Returns a Sequence TLV containing the OID and its associated value:
//
//	Sequence {
//	  ObjectIdentifier (pdu.Name)
//	  <Value TLV>      (pdu.Type + pdu.Value)
//	}
func marshalVarbind(pdu *SnmpPDU) ([]byte, error) {
	oid, err := marshalObjectIdentifier(pdu.Name)
	if err != nil {
		return nil, err
	}
	pduBuf := new(bytes.Buffer)
	tmpBuf := new(bytes.Buffer)

	// Marshal the PDU type into the appropriate BER
	switch pdu.Type {
	case Null:
		if err = marshalTLV(tmpBuf, byte(ObjectIdentifier), oid); err != nil {
			return nil, err
		}
		tmpBuf.WriteByte(byte(Null))
		tmpBuf.WriteByte(byte(EndOfContents))

		if err = marshalTLV(pduBuf, byte(Sequence), tmpBuf.Bytes()); err != nil {
			return nil, err
		}

	case Integer:
		if err = marshalTLV(tmpBuf, byte(ObjectIdentifier), oid); err != nil {
			return nil, err
		}

		// Number
		var intBytes []byte
		switch value := pdu.Value.(type) {
		case byte:
			intBytes = []byte{byte(pdu.Value.(int))}
		case int:
			if intBytes, err = marshalInt32(value); err != nil {
				return nil, fmt.Errorf("error mashalling PDU Integer: %w", err)
			}
		default:
			return nil, fmt.Errorf("unable to marshal PDU Integer; not byte or int")
		}
		if err = marshalTLV(tmpBuf, byte(pdu.Type), intBytes); err != nil {
			return nil, err
		}
		if err = marshalTLV(pduBuf, byte(Sequence), tmpBuf.Bytes()); err != nil {
			return nil, err
		}

	case Counter32, Gauge32, TimeTicks, Uinteger32:
		if err = marshalTLV(tmpBuf, byte(ObjectIdentifier), oid); err != nil {
			return nil, err
		}

		// Number
		var intBytes []byte
		switch value := pdu.Value.(type) {
		case uint32:
			if intBytes, err = marshalUint32(value); err != nil {
				return nil, fmt.Errorf("error marshalling PDU Uinteger32 type from uint32: %w", err)
			}
		case uint:
			if intBytes, err = marshalUint32(value); err != nil {
				return nil, fmt.Errorf("error marshalling PDU Uinteger32 type from uint: %w", err)
			}
		default:
			return nil, fmt.Errorf("unable to marshal pdu.Type %v; unknown pdu.Value %v[type=%T]", pdu.Type, pdu.Value, pdu.Value)
		}
		if err = marshalTLV(tmpBuf, byte(pdu.Type), intBytes); err != nil {
			return nil, err
		}
		if err = marshalTLV(pduBuf, byte(Sequence), tmpBuf.Bytes()); err != nil {
			return nil, err
		}

	case OctetString, BitString, Opaque:
		if err = marshalTLV(tmpBuf, byte(ObjectIdentifier), oid); err != nil {
			return nil, err
		}

		// OctetString
		var octetStringBytes []byte
		switch value := pdu.Value.(type) {
		case []byte:
			octetStringBytes = value
		case string:
			octetStringBytes = []byte(value)
		default:
			return nil, fmt.Errorf("unable to marshal PDU OctetString; not []byte or string")
		}
		if err = marshalTLV(tmpBuf, byte(pdu.Type), octetStringBytes); err != nil {
			return nil, err
		}
		if err = marshalTLV(pduBuf, byte(Sequence), tmpBuf.Bytes()); err != nil {
			return nil, err
		}

	case ObjectIdentifier:
		if err = marshalTLV(tmpBuf, byte(ObjectIdentifier), oid); err != nil {
			return nil, err
		}
		value := pdu.Value.(string)
		oidBytes, encErr := marshalObjectIdentifier(value)
		if encErr != nil {
			return nil, fmt.Errorf("error marshalling ObjectIdentifier: %w", encErr)
		}
		if err = marshalTLV(tmpBuf, byte(pdu.Type), oidBytes); err != nil {
			return nil, err
		}
		if err = marshalTLV(pduBuf, byte(Sequence), tmpBuf.Bytes()); err != nil {
			return nil, err
		}

	case IPAddress:
		if err = marshalTLV(tmpBuf, byte(ObjectIdentifier), oid); err != nil {
			return nil, err
		}
		// OctetString
		var ipAddressBytes []byte
		switch value := pdu.Value.(type) {
		case []byte:
			ipAddressBytes = value
		case string:
			ip := net.ParseIP(value)
			ipAddressBytes = ipv4toBytes(ip)
		default:
			return nil, fmt.Errorf("unable to marshal PDU IPAddress; not []byte or string")
		}
		if err = marshalTLV(tmpBuf, byte(pdu.Type), ipAddressBytes); err != nil {
			return nil, err
		}
		if err = marshalTLV(pduBuf, byte(Sequence), tmpBuf.Bytes()); err != nil {
			return nil, err
		}

	case OpaqueFloat, OpaqueDouble:
		converters := map[Asn1BER]func(any) ([]byte, error){
			OpaqueFloat:  marshalFloat32,
			OpaqueDouble: marshalFloat64,
		}

		intBuf := new(bytes.Buffer)
		intBuf.WriteByte(byte(AsnExtensionTag))
		intBuf.WriteByte(byte(pdu.Type))
		intBytes, encErr := converters[pdu.Type](pdu.Value)
		if encErr != nil {
			return nil, fmt.Errorf("error converting PDU value type %v to %v: %w", pdu.Value, pdu.Type, encErr)
		}
		intLength, encErr := marshalLength(len(intBytes))
		if encErr != nil {
			return nil, fmt.Errorf("error marshalling Float type length: %w", encErr)
		}
		intBuf.Write(intLength)
		intBuf.Write(intBytes)

		opaqueLength, encErr := marshalLength(len(intBuf.Bytes()))
		if encErr != nil {
			return nil, fmt.Errorf("error marshalling Opaque length: %w", encErr)
		}
		if err = marshalTLV(tmpBuf, byte(ObjectIdentifier), oid); err != nil {
			return nil, err
		}
		tmpBuf.WriteByte(byte(Opaque))
		tmpBuf.Write(opaqueLength)
		tmpBuf.Write(intBuf.Bytes())

		if err = marshalTLV(pduBuf, byte(Sequence), tmpBuf.Bytes()); err != nil {
			return nil, err
		}

	case Counter64:
		if err = marshalTLV(tmpBuf, byte(ObjectIdentifier), oid); err != nil {
			return nil, err
		}
		intBytes, encErr := marshalUint64(pdu.Value)
		if encErr != nil {
			return nil, fmt.Errorf("error marshalling Counter64: %w", encErr)
		}
		if err = marshalTLV(tmpBuf, byte(pdu.Type), intBytes); err != nil {
			return nil, err
		}
		if err = marshalTLV(pduBuf, byte(Sequence), tmpBuf.Bytes()); err != nil {
			return nil, err
		}

	case NoSuchInstance, NoSuchObject, EndOfMibView:
		if err = marshalTLV(tmpBuf, byte(ObjectIdentifier), oid); err != nil {
			return nil, err
		}
		tmpBuf.WriteByte(byte(pdu.Type))
		tmpBuf.WriteByte(byte(EndOfContents))

		if err = marshalTLV(pduBuf, byte(Sequence), tmpBuf.Bytes()); err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unable to marshal PDU: unknown BER type %q", pdu.Type)
	}

	return pduBuf.Bytes(), nil
}

// -- Unmarshalling Logic ------------------------------------------------------

func (x *GoSNMP) unmarshalVersionFromHeader(packet []byte, response *SnmpPacket) (SnmpVersion, int, error) {
	if len(packet) < 2 {
		return 0, 0, fmt.Errorf("cannot unmarshal empty packet")
	}
	if response == nil {
		return 0, 0, fmt.Errorf("cannot unmarshal response into nil packet reference")
	}

	response.Variables = make([]SnmpPDU, 0, 5)

	// Start parsing the packet
	cursor := 0

	// First bytes should be 0x30
	if PDUType(packet[0]) != Sequence {
		return 0, 0, fmt.Errorf("invalid packet header")
	}

	length, cursor, err := parseLength(packet)
	if err != nil {
		return 0, 0, err
	}
	if len(packet) != length {
		return 0, 0, fmt.Errorf("error verifying packet sanity: Got %d Expected: %d", len(packet), length)
	}
	x.Logger.Printf("Packet sanity verified, we got all the bytes (%d)", length)

	// Parse SNMP Version
	rawVersion, count, err := parseRawField(x.Logger, packet[cursor:], "version")
	if err != nil {
		return 0, 0, fmt.Errorf("error parsing SNMP packet version: %w", err)
	}

	cursor += count
	if cursor >= len(packet) {
		return 0, 0, fmt.Errorf("error parsing SNMP packet, packet length %d cursor %d", len(packet), cursor)
	}

	if version, ok := rawVersion.(int); ok {
		x.Logger.Printf("Parsed version %d", version)
		return SnmpVersion(version), cursor, nil //nolint:gosec
	}
	return 0, cursor, err
}

func (x *GoSNMP) unmarshalHeader(packet []byte, response *SnmpPacket) (int, error) {
	version, cursor, err := x.unmarshalVersionFromHeader(packet, response)
	if err != nil {
		return 0, err
	}
	response.Version = version

	if response.Version == Version3 {
		oldcursor := cursor
		cursor, err = x.unmarshalV3Header(packet, cursor, response)
		if err != nil {
			return 0, err
		}
		x.Logger.Printf("UnmarshalV3Header done. [with SecurityParameters]. Header Size %d. Last 4 Bytes=[%v]", cursor-oldcursor, packet[cursor-4:cursor])
	} else {
		// Parse community
		rawCommunity, count, err := parseRawField(x.Logger, packet[cursor:], "community")
		if err != nil {
			return 0, fmt.Errorf("error parsing community string: %w", err)
		}
		cursor += count
		if cursor > len(packet) {
			return 0, fmt.Errorf("error parsing SNMP packet, packet length %d cursor %d", len(packet), cursor)
		}

		if community, ok := rawCommunity.(string); ok {
			response.Community = community
			x.Logger.Printf("Parsed community %s", community)
		}
	}
	return cursor, nil
}

func (x *GoSNMP) unmarshalPayload(packet []byte, cursor int, response *SnmpPacket) error {
	if len(packet) == 0 {
		return errors.New("cannot unmarshal nil or empty payload packet")
	}
	if cursor >= len(packet) {
		return fmt.Errorf("cannot unmarshal payload, packet length %d cursor %d", len(packet), cursor)
	}
	if response == nil {
		return errors.New("cannot unmarshal payload response into nil packet reference")
	}

	// Parse SNMP packet type
	requestType := PDUType(packet[cursor])
	x.Logger.Printf("UnmarshalPayload Meet PDUType %#x. Offset %v", requestType, cursor)
	switch requestType {
	// known, supported types
	case GetResponse, GetNextRequest, GetBulkRequest, Report, SNMPv2Trap, GetRequest, SetRequest, InformRequest:
		response.PDUType = requestType
		if err := x.unmarshalResponse(packet[cursor:], response); err != nil {
			return fmt.Errorf("error in unmarshalResponse: %w", err)
		}
		// If it's an InformRequest, mark the trap.
		response.IsInform = (requestType == InformRequest)
	case Trap:
		response.PDUType = requestType
		if err := x.unmarshalTrapV1(packet[cursor:], response); err != nil {
			return fmt.Errorf("error in unmarshalTrapV1: %w", err)
		}
	default:
		x.Logger.Printf("UnmarshalPayload Meet Unknown PDUType %#x. Offset %v", requestType, cursor)
		return fmt.Errorf("unknown PDUType %#x", requestType)
	}
	return nil
}

func (x *GoSNMP) unmarshalResponse(packet []byte, response *SnmpPacket) error {
	cursor := 0

	getResponseLength, cursor, err := parseLength(packet)
	if err != nil {
		return err
	}
	if len(packet) != getResponseLength {
		return fmt.Errorf("error verifying Response sanity: Got %d Expected: %d", len(packet), getResponseLength)
	}
	x.Logger.Printf("getResponseLength: %d", getResponseLength)

	// Parse Request-ID
	rawRequestID, count, err := parseRawField(x.Logger, packet[cursor:], "request id")
	if err != nil {
		return fmt.Errorf("error parsing SNMP packet request ID: %w", err)
	}
	cursor += count
	if cursor > len(packet) {
		return fmt.Errorf("error parsing SNMP packet, packet length %d cursor %d", len(packet), cursor)
	}

	if requestid, ok := rawRequestID.(int); ok {
		response.RequestID = uint32(requestid) //nolint:gosec
		x.Logger.Printf("requestID: %d", response.RequestID)
	}

	if response.PDUType == GetBulkRequest {
		// Parse Non Repeaters
		rawNonRepeaters, count, err := parseRawField(x.Logger, packet[cursor:], "non repeaters")
		if err != nil {
			return fmt.Errorf("error parsing SNMP packet non repeaters: %w", err)
		}
		cursor += count
		if cursor > len(packet) {
			return fmt.Errorf("error parsing SNMP packet, packet length %d cursor %d", len(packet), cursor)
		}

		if nonRepeaters, ok := rawNonRepeaters.(int); ok {
			response.NonRepeaters = uint8(nonRepeaters) //nolint:gosec
		}

		// Parse Max Repetitions
		rawMaxRepetitions, count, err := parseRawField(x.Logger, packet[cursor:], "max repetitions")
		if err != nil {
			return fmt.Errorf("error parsing SNMP packet max repetitions: %w", err)
		}
		cursor += count
		if cursor > len(packet) {
			return fmt.Errorf("error parsing SNMP packet, packet length %d cursor %d", len(packet), cursor)
		}

		if maxRepetitions, ok := rawMaxRepetitions.(int); ok {
			response.MaxRepetitions = uint32(maxRepetitions & 0x7FFFFFFF) //nolint:gosec
		}
	} else {
		// Parse Error-Status
		rawError, count, err := parseRawField(x.Logger, packet[cursor:], "error-status")
		if err != nil {
			return fmt.Errorf("error parsing SNMP packet error: %w", err)
		}
		cursor += count
		if cursor > len(packet) {
			return fmt.Errorf("error parsing SNMP packet, packet length %d cursor %d", len(packet), cursor)
		}

		if errorStatus, ok := rawError.(int); ok {
			response.Error = SNMPError(errorStatus)                //nolint:gosec
			x.Logger.Printf("errorStatus: %d", uint8(errorStatus)) //nolint:gosec
		}

		// Parse Error-Index
		rawErrorIndex, count, err := parseRawField(x.Logger, packet[cursor:], "error index")
		if err != nil {
			return fmt.Errorf("error parsing SNMP packet error index: %w", err)
		}
		cursor += count
		if cursor > len(packet) {
			return fmt.Errorf("error parsing SNMP packet, packet length %d cursor %d", len(packet), cursor)
		}

		if errorindex, ok := rawErrorIndex.(int); ok {
			response.ErrorIndex = uint8(errorindex)               //nolint:gosec
			x.Logger.Printf("error-index: %d", uint8(errorindex)) //nolint:gosec
		}
	}

	return x.unmarshalVBL(packet[cursor:], response)
}

func (x *GoSNMP) unmarshalTrapV1(packet []byte, response *SnmpPacket) error {
	cursor := 0

	getResponseLength, cursor, err := parseLength(packet)
	if err != nil {
		return err
	}
	if len(packet) != getResponseLength {
		return fmt.Errorf("error verifying Response sanity: Got %d Expected: %d", len(packet), getResponseLength)
	}
	x.Logger.Printf("getResponseLength: %d", getResponseLength)

	// Parse Enterprise
	rawEnterprise, count, err := parseRawField(x.Logger, packet[cursor:], "enterprise")
	if err != nil {
		return fmt.Errorf("error parsing SNMP packet error: %w", err)
	}

	cursor += count
	if cursor > len(packet) {
		return fmt.Errorf("error parsing SNMP packet, packet length %d cursor %d", len(packet), cursor)
	}

	if Enterprise, ok := rawEnterprise.(string); ok {
		response.Enterprise = Enterprise
		x.Logger.Printf("Enterprise: %+v", Enterprise)
	}

	// Parse AgentAddress
	rawAgentAddress, count, err := parseRawField(x.Logger, packet[cursor:], "agent-address")
	if err != nil {
		return fmt.Errorf("error parsing SNMP packet error: %w", err)
	}
	cursor += count
	if cursor > len(packet) {
		return fmt.Errorf("error parsing SNMP packet, packet length %d cursor %d", len(packet), cursor)
	}

	if AgentAddress, ok := rawAgentAddress.(string); ok {
		response.AgentAddress = AgentAddress
		x.Logger.Printf("AgentAddress: %s", AgentAddress)
	}

	// Parse GenericTrap
	rawGenericTrap, count, err := parseRawField(x.Logger, packet[cursor:], "generic-trap")
	if err != nil {
		return fmt.Errorf("error parsing SNMP packet error: %w", err)
	}
	cursor += count
	if cursor > len(packet) {
		return fmt.Errorf("error parsing SNMP packet, packet length %d cursor %d", len(packet), cursor)
	}

	if GenericTrap, ok := rawGenericTrap.(int); ok {
		response.GenericTrap = GenericTrap
		x.Logger.Printf("GenericTrap: %d", GenericTrap)
	}

	// Parse SpecificTrap
	rawSpecificTrap, count, err := parseRawField(x.Logger, packet[cursor:], "specific-trap")
	if err != nil {
		return fmt.Errorf("error parsing SNMP packet error: %w", err)
	}
	cursor += count
	if cursor > len(packet) {
		return fmt.Errorf("error parsing SNMP packet, packet length %d cursor %d", len(packet), cursor)
	}

	if SpecificTrap, ok := rawSpecificTrap.(int); ok {
		response.SpecificTrap = SpecificTrap
		x.Logger.Printf("SpecificTrap: %d", SpecificTrap)
	}

	// Parse TimeStamp
	rawTimestamp, count, err := parseRawField(x.Logger, packet[cursor:], "time-stamp")
	if err != nil {
		return fmt.Errorf("error parsing SNMP packet error: %w", err)
	}
	cursor += count
	if cursor > len(packet) {
		return fmt.Errorf("error parsing SNMP packet, packet length %d cursor %d", len(packet), cursor)
	}

	if Timestamp, ok := rawTimestamp.(uint); ok {
		response.Timestamp = Timestamp
		x.Logger.Printf("Timestamp: %d", Timestamp)
	}

	return x.unmarshalVBL(packet[cursor:], response)
}

// unmarshal a Varbind list
func (x *GoSNMP) unmarshalVBL(packet []byte, response *SnmpPacket) error {
	var cursor, cursorInc int
	var vblLength int

	if len(packet) == 0 || cursor > len(packet) {
		return fmt.Errorf("truncated packet when unmarshalling a VBL, got length %d cursor %d", len(packet), cursor)
	}

	if packet[cursor] != 0x30 {
		return fmt.Errorf("expected a sequence when unmarshalling a VBL, got %x", packet[cursor])
	}

	vblLength, cursor, err := parseLength(packet)
	if err != nil {
		return err
	}
	if vblLength == 0 || vblLength > len(packet) {
		return fmt.Errorf("truncated packet when unmarshalling a VBL, packet length %d cursor %d", len(packet), cursor)
	}

	if len(packet) != vblLength {
		return fmt.Errorf("error verifying: packet length %d vbl length %d", len(packet), vblLength)
	}
	x.Logger.Printf("vblLength: %d", vblLength)

	// check for an empty response
	if vblLength == 2 && packet[1] == 0x00 {
		return nil
	}

	// Loop & parse Varbinds
	for cursor < vblLength {
		if packet[cursor] != 0x30 {
			return fmt.Errorf("expected a sequence when unmarshalling a VB, got %x", packet[cursor])
		}

		_, cursorInc, err = parseLength(packet[cursor:])
		if err != nil {
			return err
		}
		cursor += cursorInc
		if cursor > len(packet) {
			return fmt.Errorf("error parsing OID Value: packet %d cursor %d", len(packet), cursor)
		}

		// Parse OID
		rawOid, oidLength, err := parseRawField(x.Logger, packet[cursor:], "OID")
		if err != nil {
			return fmt.Errorf("error parsing OID Value: %w", err)
		}
		cursor += oidLength
		if cursor > len(packet) {
			return fmt.Errorf("error parsing OID Value: truncated, packet length %d cursor %d", len(packet), cursor)
		}
		oid, ok := rawOid.(string)
		if !ok {
			return fmt.Errorf("unable to type assert rawOid |%v| to string", rawOid)
		}
		x.Logger.Printf("OID: %s", oid)
		// Parse Value
		var decodedVal variable
		if err = x.decodeValue(packet[cursor:], &decodedVal); err != nil {
			return fmt.Errorf("error decoding value: %w", err)
		}

		valueLength, _, err := parseLength(packet[cursor:])
		if err != nil {
			return err
		}
		cursor += valueLength
		if cursor > len(packet) {
			return fmt.Errorf("error decoding OID Value: truncated, packet length %d cursor %d", len(packet), cursor)
		}

		response.Variables = append(response.Variables, SnmpPDU{Name: oid, Type: decodedVal.Type, Value: decodedVal.Value})
	}
	return nil
}

// receive response from network and read into a byte array
func (x *GoSNMP) receive() ([]byte, error) {
	var n int
	var err error
	// If we are using UDP and unconnected socket, read the packet and
	// disregard the source address.
	if uconn, ok := x.Conn.(net.PacketConn); ok {
		n, _, err = uconn.ReadFrom(x.rxBuf[:])
	} else {
		n, err = x.Conn.Read(x.rxBuf[:])
	}
	if err == io.EOF {
		return nil, err
	} else if err != nil {
		return nil, fmt.Errorf("error reading from socket: %w", err)
	}

	if n == rxBufSize {
		// This should never happen unless we're using something like a unix domain socket.
		return nil, fmt.Errorf("response buffer too small")
	}

	resp := make([]byte, n)
	copy(resp, x.rxBuf[:n])
	return resp, nil
}

func shrinkAndWriteUint(buf io.Writer, in int) error {
	out, err := asn1.Marshal(in)
	if err != nil {
		return err
	}
	_, err = buf.Write(out)
	return err
}
