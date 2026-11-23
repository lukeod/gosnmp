// Copyright 2026 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build all || marshal

package gosnmp

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/require"
)

// The tests below pin externally visible v3 send-path behavior that is
// intended to stay stable: engine-ID discovery, the authenticated
// notInTimeWindows resend, per-attempt msgID/request-id freshness, and
// retry/callback/timeout accounting. Later behavior changes are expected to
// keep these green.

var v3HarnessEngineID = string([]byte{0x80, 0x00, 0x1f, 0x88, 0x04, 'h', 'a', 'r', 'n', 'e', 's', 's'})

const (
	v3HarnessUser           = "harnessUser"
	v3HarnessAuthKey        = "harnessAuthKey1"
	v3HarnessPrivKey        = "harnessPrivKey1"
	v3HarnessBoots   uint32 = 7
	v3HarnessTime    uint32 = 424242

	v3HarnessSysDescrOID   = ".1.3.6.1.2.1.1.1.0"
	v3HarnessSysDescrValue = "harness sysDescr"
)

func v3HarnessCredsAuthNoPriv() v3TestAgentCreds {
	return v3TestAgentCreds{username: v3HarnessUser, authProto: SHA, authPass: v3HarnessAuthKey}
}

func v3HarnessCredsAuthPriv() v3TestAgentCreds {
	c := v3HarnessCredsAuthNoPriv()
	c.privProto = AES
	c.privPass = v3HarnessPrivKey
	return c
}

// newV3HarnessClient builds a v3 client for the given agent credentials. The
// engine ID is left empty, so the first request triggers discovery unless the
// caller pre-seeds the returned security parameters.
func newV3HarnessClient(port uint16, flags SnmpV3MsgFlags, creds v3TestAgentCreds) (*GoSNMP, *UsmSecurityParameters) {
	sp := &UsmSecurityParameters{
		UserName:                 creds.username,
		AuthenticationProtocol:   creds.authProto,
		AuthenticationPassphrase: creds.authPass,
		PrivacyProtocol:          creds.privProto,
		PrivacyPassphrase:        creds.privPass,
	}
	gs := newTestGoSNMPv3(flags, sp)
	gs.Target = "127.0.0.1"
	gs.Port = port
	gs.Timeout = 500 * time.Millisecond
	gs.Retries = 0
	gs.ExponentialTimeout = false
	return gs, sp
}

// v3HarnessSeedSession sets up an established session for the agent's local context.
func v3HarnessSeedSession(gs *GoSNMP, sp *UsmSecurityParameters, boots, engineTime uint32) {
	gs.ContextEngineID = v3HarnessEngineID
	sp.AuthoritativeEngineID = v3HarnessEngineID
	sp.AuthoritativeEngineBoots = boots
	sp.AuthoritativeEngineTime = engineTime
}

func v3HarnessConnect(t *testing.T, gs *GoSNMP) {
	t.Helper()
	require.NoError(t, gs.Connect())
	t.Cleanup(func() { gs.Conn.Close() })
}

// v3AgentDrop ignores the request so the client retries or times out.
func v3AgentDrop(*v3TestAgentRequest) [][]byte { return nil }

// v3AgentSysDescr answers any request with a single-varbind GetResponse.
func v3AgentSysDescr(a *v3TestAgent) v3TestAgentStep {
	return func(req *v3TestAgentRequest) [][]byte {
		return a.reply(req, v3TestAgentReply{pduType: GetResponse, vars: []SnmpPDU{{
			Name:  v3HarnessSysDescrOID,
			Value: v3HarnessSysDescrValue,
			Type:  OctetString,
		}}})
	}
}

// v3AgentFixtureReport replays a complete libsnmp-generated REPORT. It checks
// the fixed identifiers before replying so a missing or misplaced seed fails
// at the harness boundary instead of becoming an opaque client timeout.
func v3AgentFixtureReport(a *v3TestAgent, fixture v3HarnessFixture) v3TestAgentStep {
	return func(req *v3TestAgentRequest) [][]byte {
		if req.Packet.MsgID != fixture.msgID || req.Packet.RequestID != fixture.requestID {
			a.sendErr(fmt.Errorf("%s fixture identifiers: got msgID %d/request-id %d, want %d/%d",
				fixture.name, req.Packet.MsgID, req.Packet.RequestID, fixture.msgID, fixture.requestID))
			return nil
		}
		packet, err := fixture.decode()
		if err != nil {
			a.sendErr(err)
			return nil
		}
		return [][]byte{packet}
	}
}

// v3AgentUnknownEngineIDsReport answers with a standard noAuthNoPriv
// discovery REPORT carrying the agent fixture's engine ID, boots, and time.
func v3AgentUnknownEngineIDsReport(a *v3TestAgent) v3TestAgentStep {
	return v3AgentFixtureReport(a, v3UnknownEngineIDsReportFixture)
}

// v3AgentNotInTimeWindowsReport answers with the RFC 3414 3.2 step 7(a)
// authNoPriv REPORT carrying the agent fixture's current boots/time.
func v3AgentNotInTimeWindowsReport(a *v3TestAgent) v3TestAgentStep {
	return v3AgentFixtureReport(a, v3NotInTimeWindowsReportFixture)
}

func v3ReqSecParams(t *testing.T, req *v3TestAgentRequest) *UsmSecurityParameters {
	t.Helper()
	usp, ok := req.Packet.SecurityParameters.(*UsmSecurityParameters)
	require.True(t, ok)
	return usp
}

// requireEngineTimeNear asserts an engine-time value against a small forward
// window instead of exact equality, so the assertions stay valid if the
// static engine-time snapshot ever becomes an advancing estimate.
func requireEngineTimeNear(t *testing.T, want, got uint32) {
	t.Helper()
	require.GreaterOrEqual(t, got, want)
	require.LessOrEqual(t, got, want+2)
}

// requireRequestCount asserts the number of requests the agent received. For
// timeout-terminated tests the last datagram may still be in flight when the
// client gives up, so wait for the count before pinning it exactly.
func requireRequestCount(t *testing.T, agent *v3TestAgent, want int) {
	t.Helper()
	require.Eventually(t, func() bool { return agent.requestCount() >= want },
		time.Second, 5*time.Millisecond)
	require.Equal(t, want, agent.requestCount())
}

func requireSysDescrResult(t *testing.T, result *SnmpPacket) {
	t.Helper()
	require.NotNil(t, result)
	require.Len(t, result.Variables, 1)
	require.Equal(t, v3HarnessSysDescrOID, result.Variables[0].Name)
	require.Equal(t, []byte(v3HarnessSysDescrValue), result.Variables[0].Value)
}

// TestV3HarnessColdStartGetAuthNoPriv checks that a blank discovery probe
// ignores a signed Report it cannot verify, learns the engine ID from the
// discovery Report that follows, and completes an authenticated GET.
func TestV3HarnessColdStartGetAuthNoPriv(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	discoveryReport := v3AgentUnknownEngineIDsReport(agent)
	agent.steps = []v3TestAgentStep{
		func(req *v3TestAgentRequest) [][]byte {
			signed := agent.reply(req, v3TestAgentReply{
				pduType: Report,
				vars:    []SnmpPDU{{Name: usmStatsUnsupportedSecLevels, Type: Counter32, Value: uint32(1)}},
			})
			return append(signed, discoveryReport(req)...)
		},
		v3AgentSysDescr(agent),
	}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	var received int
	gs.OnRecv = func(*GoSNMP) { received++ }
	v3HarnessConnect(t, gs)
	v3UnknownEngineIDsReportFixture.seedIDs(gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)

	// The engine ID from the discovery REPORT is adopted into the session.
	// The agent checks the GET's HMAC and accepts it without a timeliness
	// check. This two-exchange script leaves its boots/time unasserted.
	require.Equal(t, v3HarnessEngineID, sp.AuthoritativeEngineID)

	require.Equal(t, 3, received)
	require.Equal(t, 2, agent.requestCount())
	probe, get := agent.request(0), agent.request(1)

	// The discovery probe is a blank noAuthNoPriv GetRequest.
	require.Equal(t, Reportable|NoAuthNoPriv, probe.Packet.MsgFlags)
	require.Empty(t, v3ReqSecParams(t, probe).AuthoritativeEngineID)
	require.Empty(t, probe.Packet.Variables)

	// The real request is authenticated under the adopted engine ID.
	require.Equal(t, Reportable|AuthNoPriv, get.Packet.MsgFlags)
	getUsp := v3ReqSecParams(t, get)
	require.Equal(t, v3HarnessEngineID, getUsp.AuthoritativeEngineID)
	require.Equal(t, v3HarnessUser, getUsp.UserName)
}

// TestV3HarnessColdStartGetAuthPriv is the cold-start flow at authPriv: the
// agent decrypts the incoming request and the client accepts an encrypted
// response.
func TestV3HarnessColdStartGetAuthPriv(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthPriv())
	agent.steps = []v3TestAgentStep{
		v3AgentUnknownEngineIDsReport(agent),
		v3AgentSysDescr(agent),
	}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthPriv, agent.creds)
	v3HarnessConnect(t, gs)
	v3UnknownEngineIDsReportFixture.seedIDs(gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)

	require.Equal(t, v3HarnessEngineID, sp.AuthoritativeEngineID)
	require.Equal(t, 2, agent.requestCount())
	require.Equal(t, Reportable|AuthPriv, agent.request(1).Packet.MsgFlags)
	// The agent's parse step decrypted the scoped PDU back to the plain OID.
	require.Len(t, agent.request(1).Packet.Variables, 1)
	require.Equal(t, v3HarnessSysDescrOID, agent.request(1).Packet.Variables[0].Name)
}

// TestV3HarnessNotInTimeWindowResend pins the RFC-conforming
// recovery: a session with stale boots/time receives an authenticated
// notInTimeWindows REPORT and retransmits once with the reported values.
func TestV3HarnessNotInTimeWindowResend(t *testing.T) {
	const staleBoots, staleTime uint32 = 1, 100

	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{
		v3AgentNotInTimeWindowsReport(agent),
		v3AgentSysDescr(agent),
	}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	// Pre-seed an established session with stale engine time.
	v3HarnessSeedSession(gs, sp, staleBoots, staleTime)
	var retries, finished int
	gs.OnRetry = func(*GoSNMP) { retries++ }
	gs.OnFinish = func(*GoSNMP) { finished++ }
	v3HarnessConnect(t, gs)
	v3NotInTimeWindowsReportFixture.seedIDs(gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)

	require.Equal(t, 2, agent.requestCount())
	first, second := agent.request(0), agent.request(1)

	// First attempt carries the stale tuple; the corrected send carries the
	// REPORT's boots/time and fresh identifiers.
	require.Equal(t, staleBoots, v3ReqSecParams(t, first).AuthoritativeEngineBoots)
	requireEngineTimeNear(t, staleTime, v3ReqSecParams(t, first).AuthoritativeEngineTime)
	require.Equal(t, v3HarnessBoots, v3ReqSecParams(t, second).AuthoritativeEngineBoots)
	requireEngineTimeNear(t, v3HarnessTime, v3ReqSecParams(t, second).AuthoritativeEngineTime)
	require.NotEqual(t, first.Packet.MsgID, second.Packet.MsgID)
	require.NotEqual(t, first.Packet.RequestID, second.Packet.RequestID)

	// Session state now holds the reported tuple (the REPORT was
	// authenticated with greater boots, so this stays valid under high-water
	// timeliness rules).
	require.Equal(t, v3HarnessBoots, sp.AuthoritativeEngineBoots)
	requireEngineTimeNear(t, v3HarnessTime, sp.AuthoritativeEngineTime)

	// The retry budget is untouched; each of the two sendOneRequest calls
	// (original and corrected) invokes OnFinish once.
	require.Equal(t, 0, retries)
	require.Equal(t, 2, finished)
}

// TestV3HarnessImmediateSuccessAccounting pins callback counts for a plain
// one-exchange Get on an established session.
func TestV3HarnessImmediateSuccessAccounting(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{v3AgentSysDescr(agent)}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	v3HarnessSeedSession(gs, sp, v3HarnessBoots, v3HarnessTime)
	contextEngineID := v3HarnessEngineID + "-context"
	gs.ContextEngineID = contextEngineID
	gs.ContextName = "harness-context"
	var retries, finished int
	gs.OnRetry = func(*GoSNMP) { retries++ }
	gs.OnFinish = func(*GoSNMP) { finished++ }
	v3HarnessConnect(t, gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)
	require.Equal(t, 1, agent.requestCount())
	request := agent.request(0).Packet
	require.Equal(t, contextEngineID, request.ContextEngineID)
	require.Equal(t, request.ContextEngineID, result.ContextEngineID)
	require.Equal(t, "harness-context", request.ContextName)
	require.Equal(t, request.ContextName, result.ContextName)
	require.Equal(t, 0, retries)
	require.Equal(t, 1, finished)
}

// TestV3HarnessRejectsUnauthenticatedDiscoveryShapedResponse checks that an
// authNoPriv client does not accept a noAuthNoPriv response just because it
// has the empty user, engine ID and varbind list of an engine discovery
// message, and that such a response does not reset the session's engine state.
func TestV3HarnessRejectsUnauthenticatedDiscoveryShapedResponse(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	sysDescr := v3AgentSysDescr(agent)
	agent.steps = []v3TestAgentStep{func(req *v3TestAgentRequest) [][]byte {
		forged := &SnmpPacket{
			Version:            Version3,
			MsgFlags:           NoAuthNoPriv,
			SecurityModel:      UserSecurityModel,
			SecurityParameters: &UsmSecurityParameters{Logger: agent.logger},
			PDUType:            GetResponse,
			MsgID:              req.Packet.MsgID,
			RequestID:          req.Packet.RequestID,
			ContextEngineID:    req.Packet.ContextEngineID,
			ContextName:        req.Packet.ContextName,
			Error:              TooBig,
			Logger:             agent.logger,
		}
		out, err := forged.MarshalMsg()
		if err != nil {
			agent.sendErr(fmt.Errorf("marshaling forged reply: %w", err))
			return nil
		}
		return append([][]byte{out}, sysDescr(req)...)
	}}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	v3HarnessSeedSession(gs, sp, v3HarnessBoots, v3HarnessTime)
	v3HarnessConnect(t, gs)

	requireV3ReplyDiscarded(t, gs, sp, agent)
}

// forgeV3Reply builds an unauthenticated reply with request-id 0, which the
// client accepts for any request, so an attacker need not see the request.
func forgeV3Reply(t *testing.T, logger Logger, engineID string, pduType PDUType, vars []SnmpPDU) []byte {
	t.Helper()
	forged := &SnmpPacket{
		Version:            Version3,
		MsgFlags:           NoAuthNoPriv,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: &UsmSecurityParameters{AuthoritativeEngineID: engineID, Logger: logger},
		PDUType:            pduType,
		MsgID:              1,
		Variables:          vars,
		Logger:             logger,
	}
	out, err := forged.MarshalMsg()
	require.NoError(t, err)
	return out
}

// TestV3HarnessRejectsDiscoveryReportWithoutEngineID checks that a forged
// discovery REPORT with an empty engine ID fails discovery, rather than
// leaving the engine ID empty so that later responses are trusted on their
// own msgFlags.
func TestV3HarnessRejectsDiscoveryReportWithoutEngineID(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	report := forgeV3Reply(t, agent.logger, "", Report, []SnmpPDU{{Name: usmStatsUnknownEngineIDs, Type: Counter32, Value: uint32(1)}})
	forged := forgeV3Reply(t, agent.logger, "", GetResponse, []SnmpPDU{{Name: v3HarnessSysDescrOID, Type: OctetString, Value: "FORGED"}})
	agent.steps = []v3TestAgentStep{
		func(*v3TestAgentRequest) [][]byte { return [][]byte{report} },
		func(*v3TestAgentRequest) [][]byte { return [][]byte{forged} },
	}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	v3HarnessConnect(t, gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.ErrorContains(t, err, "invalid authoritative engine ID")
	require.Empty(t, result.Variables)
	require.Empty(t, sp.AuthoritativeEngineID)
	require.Equal(t, 1, agent.requestCount())
}

// TestV3HarnessDiscoveryIgnoresUnauthenticatedResponse checks that while the
// engine ID is unknown, an unauthenticated reply other than a REPORT is
// discarded, so a forged GetResponse cannot set the engine ID and the
// genuine discovery REPORT behind it is still used.
func TestV3HarnessDiscoveryIgnoresUnauthenticatedResponse(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	forged := forgeV3Reply(t, agent.logger, "\x80\x00\x00\x00\x04forged", GetResponse,
		[]SnmpPDU{{Name: v3HarnessSysDescrOID, Type: OctetString, Value: "FORGED"}})
	report := v3AgentUnknownEngineIDsReport(agent)
	agent.steps = []v3TestAgentStep{
		func(req *v3TestAgentRequest) [][]byte { return append([][]byte{forged}, report(req)...) },
		v3AgentSysDescr(agent),
	}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	v3HarnessConnect(t, gs)
	v3UnknownEngineIDsReportFixture.seedIDs(gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)
	require.Equal(t, v3HarnessEngineID, sp.AuthoritativeEngineID)
}

// TestV3HarnessTimeoutAllAttemptsDropped pins retry accounting when
// every attempt is dropped: Retries+1 requests on the wire, each with fresh
// msgID and request-id, ending in a timeout error.
func TestV3HarnessTimeoutAllAttemptsDropped(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{v3AgentDrop, v3AgentDrop, v3AgentDrop}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	v3HarnessSeedSession(gs, sp, v3HarnessBoots, v3HarnessTime)
	gs.Timeout = 150 * time.Millisecond
	gs.Retries = 2
	var retries int
	gs.OnRetry = func(*GoSNMP) { retries++ }
	v3HarnessConnect(t, gs)

	_, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "timeout"), "got error: %v", err)

	requireRequestCount(t, agent, 3)
	msgIDs := map[uint32]bool{}
	reqIDs := map[uint32]bool{}
	for i := range 3 {
		req := agent.request(i)
		msgIDs[req.Packet.MsgID] = true
		reqIDs[req.Packet.RequestID] = true
	}
	require.Len(t, msgIDs, 3, "each attempt must use a fresh msgID")
	require.Len(t, reqIDs, 3, "each attempt must use a fresh request-id")
	// OnRetry fires on every loop pass after the first send, including the
	// final pass that gives up: Retries+1 times in total.
	require.Equal(t, 3, retries)
}

// TestV3HarnessRetriesZeroTimeout pins single-attempt behavior: one request
// on the wire and a timeout error.
func TestV3HarnessRetriesZeroTimeout(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{v3AgentDrop}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	v3HarnessSeedSession(gs, sp, v3HarnessBoots, v3HarnessTime)
	gs.Timeout = 150 * time.Millisecond
	v3HarnessConnect(t, gs)

	_, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "timeout"), "got error: %v", err)
	requireRequestCount(t, agent, 1)
}

// TestV3HarnessDropFirstAttemptThenRespond pins recovery within the
// retry budget: the first attempt is dropped, the retry is answered.
func TestV3HarnessDropFirstAttemptThenRespond(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{v3AgentDrop, v3AgentSysDescr(agent)}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	v3HarnessSeedSession(gs, sp, v3HarnessBoots, v3HarnessTime)
	gs.Timeout = 150 * time.Millisecond
	gs.Retries = 1
	v3HarnessConnect(t, gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)
	require.Equal(t, 2, agent.requestCount())
	require.NotEqual(t, agent.request(0).Packet.MsgID, agent.request(1).Packet.MsgID)
	require.NotEqual(t, agent.request(0).Packet.RequestID, agent.request(1).Packet.RequestID)
}

// TestV3HarnessTCPGet runs the cold-start discovery and Get flow over TCP.
func TestV3HarnessTCPGet(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{
		v3AgentUnknownEngineIDsReport(agent),
		v3AgentSysDescr(agent),
	}
	port := agent.startTCP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	gs.Transport = "tcp"
	v3HarnessConnect(t, gs)
	v3UnknownEngineIDsReportFixture.seedIDs(gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)
	require.Equal(t, v3HarnessEngineID, sp.AuthoritativeEngineID)
	require.Equal(t, 2, agent.requestCount())
}

// TestV3HarnessTCPFraming exercises readBERMessage against fragmented and
// coalesced stream reads: two back-to-back messages delivered one byte per
// Read must each come back intact, and malformed framing must error.
func TestV3HarnessTCPFraming(t *testing.T) {
	short := []byte{0x30, 0x03, 0x01, 0x02, 0x03}
	long := append([]byte{0x30, 0x82, 0x01, 0x00}, bytes.Repeat([]byte{0xab}, 256)...)

	r := bufio.NewReader(iotest.OneByteReader(bytes.NewReader(append(bytes.Clone(short), long...))))
	msg, err := readBERMessage(r)
	require.NoError(t, err)
	require.Equal(t, short, msg)
	msg, err = readBERMessage(r)
	require.NoError(t, err)
	require.Equal(t, long, msg)
	_, err = readBERMessage(r)
	require.ErrorIs(t, err, io.EOF)

	for name, in := range map[string][]byte{
		"wrong tag":           {0x04, 0x01, 0x00},
		"indefinite length":   {0x30, 0x80, 0x01, 0x02},
		"oversize length":     {0x30, 0x83, 0xff, 0xff, 0xff},
		"truncated after tag": {0x30},
		"truncated length":    {0x30, 0x82, 0x01},
		"truncated payload":   {0x30, 0x05, 0x01, 0x02},
		"missing payload":     {0x30, 0x05},
	} {
		_, err = readBERMessage(bufio.NewReader(bytes.NewReader(in)))
		require.Error(t, err, name)
		// Truncation inside a message must not read as a clean close.
		require.NotErrorIs(t, err, io.EOF, name)
	}
}

// The tests below check that an established session takes the security
// level of an incoming message from the message's own msgFlags (RFC 3412
// section 7.2 step 5), verifies every message that claims authentication, and
// accepts ordinary responses only at the request's level (step 12). An
// authenticated request keeps waiting after an unsigned Report or a Report
// without varbinds. A verified authNoPriv time-window Report can trigger
// recovery for an authPriv request (RFC 3414 section 3.2 step 7(a)).

// setV3MsgFlags returns a copy of a marshaled v3 message with its msgFlags
// octet replaced, for flag combinations the marshaling code won't produce.
// The msgFlags field is the one-octet OCTET STRING followed by the USM
// msgSecurityModel INTEGER in msgGlobalData. It is called from agent steps,
// which run on the agent's goroutine, so it reports with t.Errorf rather
// than stopping the test there.
func setV3MsgFlags(t *testing.T, msg []byte, flags SnmpV3MsgFlags) []byte {
	t.Helper()
	out := append([]byte(nil), msg...)
	for i := 0; i+6 <= len(out); i++ {
		if out[i] == byte(OctetString) && out[i+1] == 1 &&
			bytes.Equal(out[i+3:i+6], []byte{byte(Integer), 1, byte(UserSecurityModel)}) {
			out[i+2] = byte(flags)
			return out
		}
	}
	t.Errorf("msgFlags not found in marshaled message")
	return msg
}

// v3SeclevelReportThenSysDescr sends the Report and the ordinary response
// to the same request. Only the Report uses the supplied boots and time.
func v3SeclevelReportThenSysDescr(a *v3TestAgent, r v3TestAgentReply, boots, engineTime uint32) v3TestAgentStep {
	r.pduType = Report
	r.boots = &boots
	r.engineTime = &engineTime
	sysDescr := v3AgentSysDescr(a)
	return func(req *v3TestAgentRequest) [][]byte {
		return append(a.reply(req, r), sysDescr(req)...)
	}
}

// requireV3SeclevelStateKept checks the established session's engine and clock.
func requireV3SeclevelStateKept(t *testing.T, sp *UsmSecurityParameters) {
	t.Helper()
	require.Equal(t, v3HarnessEngineID, sp.AuthoritativeEngineID)
	require.Equal(t, v3HarnessBoots, sp.AuthoritativeEngineBoots)
	requireEngineTimeNear(t, v3HarnessTime, sp.AuthoritativeEngineTime)
}

// Check engine state before processing the second reply. A successful
// GET stores the reply's engine parameters and could mask an earlier update.
func requireV3ReplyDiscarded(t *testing.T, gs *GoSNMP, sp *UsmSecurityParameters, agent *v3TestAgent) {
	t.Helper()
	received := 0
	gs.OnRecv = func(*GoSNMP) {
		received++
		if received == 2 {
			requireV3SeclevelStateKept(t, sp)
		}
	}

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)
	require.Equal(t, 2, received)
	require.Equal(t, 1, agent.requestCount())
	requireV3SeclevelStateKept(t, sp)
}

// TestV3SeclevelUnauthenticatedReportIsDiscarded checks that a noAuthNoPriv
// Report can't end an authenticated request, whatever it reports: it is
// discarded, the reply that follows completes the same attempt, and the
// Report's engine boots and time are not stored.
func TestV3SeclevelUnauthenticatedReportIsDiscarded(t *testing.T) {
	noAuth := NoAuthNoPriv
	for _, tc := range []struct {
		name  string
		level SnmpV3MsgFlags
		creds v3TestAgentCreds
		oid   string
	}{
		{"notInTimeWindows authNoPriv", AuthNoPriv, v3HarnessCredsAuthNoPriv(), usmStatsNotInTimeWindows},
		{"notInTimeWindows authPriv", AuthPriv, v3HarnessCredsAuthPriv(), usmStatsNotInTimeWindows},
		{"unknownUserNames", AuthNoPriv, v3HarnessCredsAuthNoPriv(), usmStatsUnknownUserNames},
		{"unknownEngineIDs", AuthNoPriv, v3HarnessCredsAuthNoPriv(), usmStatsUnknownEngineIDs},
		{"unknown OID", AuthNoPriv, v3HarnessCredsAuthNoPriv(), ".1.3.6.1.4.1.99999.1.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, tc.creds)
			agent.steps = []v3TestAgentStep{v3SeclevelReportThenSysDescr(agent, v3TestAgentReply{
				vars:     []SnmpPDU{{Name: tc.oid, Type: Counter32, Value: uint32(1)}},
				msgFlags: &noAuth,
			}, 99, 5)}
			port := agent.startUDP(t)

			gs, sp := newV3HarnessClient(port, tc.level, agent.creds)
			v3HarnessSeedSession(gs, sp, v3HarnessBoots, v3HarnessTime)
			v3HarnessConnect(t, gs)

			requireV3ReplyDiscarded(t, gs, sp, agent)
		})
	}
}

// TestV3SeclevelDiscardsReportWithLocalizedKey checks that a Report naming
// another engine, which a session holding only a localized key can't process,
// is discarded instead of ending the GET, whether it is unsigned or claims
// authentication.
func TestV3SeclevelDiscardsReportWithLocalizedKey(t *testing.T) {
	for _, flags := range []SnmpV3MsgFlags{NoAuthNoPriv, AuthNoPriv} {
		t.Run(flags.String(), func(t *testing.T) {
			agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
			other := newV3TestAgent(t, v3HarnessEngineID+"-new", 99, 5, agent.creds)
			ids := &SnmpPacket{MsgID: 17, RequestID: 23}
			report := other.reply(&v3TestAgentRequest{Packet: ids}, v3TestAgentReply{
				pduType:  Report,
				vars:     []SnmpPDU{{Name: usmStatsUnknownEngineIDs, Type: Counter32, Value: uint32(1)}},
				msgFlags: &flags,
			})
			require.Len(t, report, 1)

			// Parsing with the passphrase verifies the signed Report's digest
			// using the key localized to the engine named on the wire.
			packet, err := agent.parse(report[0])
			require.NoError(t, err)
			require.Equal(t, flags, packet.MsgFlags)
			require.Equal(t, other.engineID, packet.SecurityParameters.(*UsmSecurityParameters).AuthoritativeEngineID)

			sysDescr := v3AgentSysDescr(agent)
			agent.steps = []v3TestAgentStep{func(req *v3TestAgentRequest) [][]byte {
				return append(report, sysDescr(req)...)
			}}
			port := agent.startUDP(t)

			gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
			v3HarnessSeedSession(gs, sp, v3HarnessBoots, v3HarnessTime)
			require.NoError(t, sp.InitSecurityKeys())
			sp.AuthenticationPassphrase = ""
			v3HarnessConnect(t, gs)
			gs.SetMsgID(ids.MsgID - 1)
			gs.SetRequestID(ids.RequestID - 1)

			requireV3ReplyDiscarded(t, gs, sp, agent)
			request := agent.request(0).Packet
			require.Equal(t, request.MsgID, packet.MsgID)
			require.Equal(t, request.RequestID, packet.RequestID)
		})
	}
}

// TestV3SeclevelDiscardsTamperedSignedReply checks that a signed reply whose
// digest no longer matches is discarded, and that the genuine reply that
// follows completes the same GET, at both authenticated levels.
func TestV3SeclevelDiscardsTamperedSignedReply(t *testing.T) {
	for _, tc := range []struct {
		level SnmpV3MsgFlags
		creds v3TestAgentCreds
	}{
		{AuthNoPriv, v3HarnessCredsAuthNoPriv()},
		{AuthPriv, v3HarnessCredsAuthPriv()},
	} {
		t.Run(tc.level.String(), func(t *testing.T) {
			agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, tc.creds)
			sysDescr := v3AgentSysDescr(agent)
			agent.steps = []v3TestAgentStep{func(req *v3TestAgentRequest) [][]byte {
				out := sysDescr(req)
				if len(out) != 1 {
					return out
				}
				// The last byte belongs to the sysDescr value or its ciphertext.
				tampered := append([]byte(nil), out[0]...)
				tampered[len(tampered)-1] ^= 0xff
				return [][]byte{tampered, out[0]}
			}}
			port := agent.startUDP(t)

			gs, sp := newV3HarnessClient(port, tc.level, agent.creds)
			v3HarnessSeedSession(gs, sp, v3HarnessBoots, v3HarnessTime)
			v3HarnessConnect(t, gs)

			var received int
			gs.OnRecv = func(*GoSNMP) { received++ }
			result, err := gs.Get([]string{v3HarnessSysDescrOID})
			require.NoError(t, err)
			requireSysDescrResult(t, result)
			require.Equal(t, 2, received)
			require.Equal(t, 1, agent.requestCount())
		})
	}
}

// TestV3SeclevelEmptyReportIsDiscarded checks that a Report without varbinds
// leaves the GET waiting for its ordinary response. A signed Report uses
// the current clock because USM processes timeliness before the scoped PDU.
func TestV3SeclevelEmptyReportIsDiscarded(t *testing.T) {
	for _, tc := range []struct {
		requestLevel SnmpV3MsgFlags
		reportLevel  SnmpV3MsgFlags
		creds        v3TestAgentCreds
	}{
		{AuthNoPriv, NoAuthNoPriv, v3HarnessCredsAuthNoPriv()},
		{AuthPriv, NoAuthNoPriv, v3HarnessCredsAuthPriv()},
		{AuthNoPriv, AuthNoPriv, v3HarnessCredsAuthNoPriv()},
		{AuthPriv, AuthPriv, v3HarnessCredsAuthPriv()},
	} {
		t.Run(tc.reportLevel.String()+" Report on "+tc.requestLevel.String(), func(t *testing.T) {
			agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, tc.creds)
			boots, engineTime := v3HarnessBoots, v3HarnessTime
			if tc.reportLevel == NoAuthNoPriv {
				boots, engineTime = 99, 5
			}
			report := v3TestAgentReply{msgFlags: &tc.reportLevel}
			agent.steps = []v3TestAgentStep{v3SeclevelReportThenSysDescr(agent, report, boots, engineTime)}
			port := agent.startUDP(t)

			gs, sp := newV3HarnessClient(port, tc.requestLevel, agent.creds)
			v3HarnessSeedSession(gs, sp, v3HarnessBoots, v3HarnessTime)
			v3HarnessConnect(t, gs)

			requireV3ReplyDiscarded(t, gs, sp, agent)
		})
	}
}

// TestV3SeclevelVerifiesClaimedAuthentication checks that a noAuthNoPriv
// session verifies a message whose msgFlags claim authentication instead of
// trusting it. An authNoPriv usmStatsNotInTimeWindows Report is not acted on
// when it is signed with another key, or when the session has no key at all
// to check it with.
func TestV3SeclevelVerifiesClaimedAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name        string
		clientCreds v3TestAgentCreds
		wantErr     string
	}{
		{
			name:        "wrong key",
			clientCreds: v3TestAgentCreds{username: v3HarnessUser, authProto: SHA, authPass: "not-the-agents-key"},
			wantErr:     "incoming packet is not authentic",
		},
		{
			name:        "no authentication protocol",
			clientCreds: v3TestAgentCreds{username: v3HarnessUser},
			wantErr:     "authentication parameters are not configured",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
			ids := &SnmpPacket{MsgID: 17, RequestID: 23}
			boots, engineTime := uint32(99), uint32(5)
			report := agent.reply(&v3TestAgentRequest{Packet: ids}, v3TestAgentReply{
				pduType:    Report,
				vars:       []SnmpPDU{{Name: usmStatsNotInTimeWindows, Type: Counter32, Value: uint32(1)}},
				boots:      &boots,
				engineTime: &engineTime,
			})
			require.Len(t, report, 1)
			sysDescr := v3AgentSysDescr(agent)
			agent.steps = []v3TestAgentStep{func(req *v3TestAgentRequest) [][]byte {
				return append(report, sysDescr(req)...)
			}}
			port := agent.startUDP(t)

			gs, sp := newV3HarnessClient(port, NoAuthNoPriv, tc.clientCreds)
			v3HarnessSeedSession(gs, sp, v3HarnessBoots, v3HarnessTime)
			v3HarnessConnect(t, gs)
			gs.SetMsgID(ids.MsgID - 1)
			gs.SetRequestID(ids.RequestID - 1)

			// Header decoding clears the digest field. Preserve the Report for the GET.
			require.NoError(t, sp.InitSecurityKeys())
			msg := bytes.Clone(report[0])
			result := &SnmpPacket{SecurityParameters: sp.Copy(), Logger: gs.Logger}
			_, err := gs.unmarshalHeader(msg, result)
			if tc.clientCreds.authProto > NoAuth {
				require.NoError(t, err)
				err = gs.verifyReceivedAuthentication(msg, result)
			}
			require.ErrorContains(t, err, tc.wantErr)

			// Only the Report claims authentication during the GET.
			credentials := &wrappedUSM{UsmSecurityParameters: sp}
			gs.SecurityParameters = credentials
			requireV3ReplyDiscarded(t, gs, sp, agent)
			request := agent.request(0).Packet
			require.Equal(t, ids.MsgID, request.MsgID)
			require.Equal(t, ids.RequestID, request.RequestID)
			require.Equal(t, tc.clientCreds.authProto > NoAuth, credentials.checkedDigest,
				"digest verification during the GET")
		})
	}
}

func TestV3HeaderRejectsUnsignedReportBeforeUSM(t *testing.T) {
	msg, err := v3UnknownEngineIDsReportFixture.decode()
	require.NoError(t, err)

	gs, sp := newV3HarnessClient(0, AuthNoPriv, v3HarnessCredsAuthNoPriv())
	knownEngineID := v3HarnessEngineID + "-other"
	sp.AuthoritativeEngineID = knownEngineID
	require.NoError(t, sp.InitSecurityKeys())
	sp.AuthenticationPassphrase = ""

	result := &SnmpPacket{SecurityParameters: sp, Logger: gs.Logger}
	_, err = gs.unmarshalHeaderWithAuthRequirement(msg, result, true)
	require.ErrorIs(t, err, errUnauthenticatedResponse)
	require.Equal(t, knownEngineID, sp.AuthoritativeEngineID)
}

// TestV3HeaderRejectsMalformedMsgFlags checks that msgFlags must be a
// one-octet OCTET STRING, rather than leaving the security level unset.
func TestV3HeaderRejectsMalformedMsgFlags(t *testing.T) {
	header := func(msgFlags ...byte) []byte {
		body := []byte{
			byte(Integer), 1, 1, // msgID
			byte(Integer), 2, 0x05, 0xdc, // msgMaxSize
		}
		body = append(body, msgFlags...)
		body = append(body, byte(Integer), 1, byte(UserSecurityModel), byte(OctetString), 0)
		return append([]byte{byte(Sequence), byte(len(body))}, body...)
	}
	gs := newTestGoSNMPv3(NoAuthNoPriv, &UsmSecurityParameters{})

	for _, msgFlags := range [][]byte{
		{byte(OctetString), 0},
		{byte(OctetString), 2, byte(AuthNoPriv), 0},
		{byte(OctetString), 0x80}, // indefinite BER length
		{byte(Integer), 1, byte(AuthNoPriv)},
	} {
		result := &SnmpPacket{MsgFlags: AuthPriv, Logger: gs.Logger}
		_, err := gs.unmarshalV3Header(header(msgFlags...), 0, result, false)
		require.ErrorIs(t, err, errInvalidMsgFlags, "msgFlags %x", msgFlags)
	}

	_, err := gs.unmarshalV3Header(header(byte(OctetString), 1, byte(AuthPriv&^AuthNoPriv)), 0, &SnmpPacket{Logger: gs.Logger}, false)
	require.ErrorIs(t, err, errInvalidMsgFlags)
	require.ErrorContains(t, err, "privacy without authentication")

	// A complete message with a valid msgFlags octet parses without error,
	// and its flags replace whatever the packet held before.
	valid := &SnmpPacket{
		Version:            Version3,
		MsgFlags:           NoAuthNoPriv,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: &UsmSecurityParameters{UserName: v3HarnessUser, AuthoritativeEngineID: v3HarnessEngineID},
		PDUType:            GetResponse,
		MsgID:              1,
		RequestID:          1,
		Variables:          []SnmpPDU{{Name: v3HarnessSysDescrOID, Type: OctetString, Value: v3HarnessSysDescrValue}},
	}
	msg, err := valid.MarshalMsg()
	require.NoError(t, err)
	result := &SnmpPacket{MsgFlags: AuthPriv, SecurityParameters: &UsmSecurityParameters{}, Logger: gs.Logger}
	_, err = gs.unmarshalHeader(msg, result)
	require.NoError(t, err)
	require.Equal(t, NoAuthNoPriv, result.MsgFlags)
}

func TestV3SeclevelRejectsMismatchedResponseLevel(t *testing.T) {
	for _, tc := range []struct {
		requestLevel  SnmpV3MsgFlags
		responseLevel SnmpV3MsgFlags
	}{
		{AuthPriv, AuthNoPriv},
		{AuthNoPriv, AuthPriv},
	} {
		t.Run(tc.responseLevel.String()+" response to "+tc.requestLevel.String(), func(t *testing.T) {
			agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthPriv())
			sysDescr := v3AgentSysDescr(agent)
			agent.steps = []v3TestAgentStep{func(req *v3TestAgentRequest) [][]byte {
				first := agent.reply(req, v3TestAgentReply{
					pduType:  GetResponse,
					vars:     []SnmpPDU{{Name: v3HarnessSysDescrOID, Type: OctetString, Value: "mismatched level"}},
					msgFlags: &tc.responseLevel,
				})
				return append(first, sysDescr(req)...)
			}}
			port := agent.startUDP(t)

			gs, sp := newV3HarnessClient(port, tc.requestLevel, agent.creds)
			v3HarnessSeedSession(gs, sp, v3HarnessBoots, v3HarnessTime)
			v3HarnessConnect(t, gs)

			var received int
			gs.OnRecv = func(*GoSNMP) { received++ }
			result, err := gs.Get([]string{v3HarnessSysDescrOID})
			require.NoError(t, err)
			requireSysDescrResult(t, result)
			require.Equal(t, 2, received)
			require.Equal(t, 1, agent.requestCount())
		})
	}
}

// A reply with privacy but no authentication is discarded. The next reply
// completes the original GET.
func TestV3SeclevelRejectsPrivWithoutAuth(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3TestAgentCreds{username: v3HarnessUser})
	sysDescr := v3AgentSysDescr(agent)
	agent.steps = []v3TestAgentStep{func(req *v3TestAgentRequest) [][]byte {
		first := agent.reply(req, v3TestAgentReply{
			pduType: GetResponse,
			vars:    []SnmpPDU{{Name: v3HarnessSysDescrOID, Type: OctetString, Value: "invalid flags reply"}},
		})
		if len(first) == 0 {
			return nil
		}
		first[0] = setV3MsgFlags(t, first[0], AuthPriv&^AuthNoPriv)
		return append(first, sysDescr(req)...)
	}}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, NoAuthNoPriv, agent.creds)
	v3HarnessSeedSession(gs, sp, v3HarnessBoots, v3HarnessTime)
	v3HarnessConnect(t, gs)

	var received int
	gs.OnRecv = func(*GoSNMP) { received++ }
	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)
	require.Equal(t, 2, received)
	require.Equal(t, 1, agent.requestCount())
}

type wrappedUSM struct {
	*UsmSecurityParameters
	checkedDigest bool
}

func (w *wrappedUSM) isAuthentic(message []byte, packet *SnmpPacket) (bool, error) {
	w.checkedDigest = true
	return w.UsmSecurityParameters.isAuthentic(message, packet)
}

// TestV3SeclevelVerifiesThroughTheInterface checks that an authenticated
// reply is verified through the SnmpV3SecurityParameters interface, so a type
// that embeds *UsmSecurityParameters still works.
func TestV3SeclevelVerifiesThroughTheInterface(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{v3AgentSysDescr(agent)}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	v3HarnessSeedSession(gs, sp, v3HarnessBoots, v3HarnessTime)
	credentials := &wrappedUSM{UsmSecurityParameters: sp}
	gs.SecurityParameters = credentials
	v3HarnessConnect(t, gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)
	require.True(t, credentials.checkedDigest, "the session wrapper must verify the reply")
	require.Equal(t, 1, agent.requestCount())
}

// TestV3SeclevelAuthPrivHonoursAuthenticatedReport checks that an
// authenticated Report below an authPriv request's level is still acted on,
// as RFC 3414 section 3.2 step 7(a) sends usmStatsNotInTimeWindows authNoPriv.
func TestV3SeclevelAuthPrivHonoursAuthenticatedReport(t *testing.T) {
	const staleBoots, staleTime uint32 = 1, 100
	authNoPriv := AuthNoPriv
	zero := uint32(0) // USM checks timeliness before decrypting the request-id.
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthPriv())
	agent.steps = []v3TestAgentStep{
		func(req *v3TestAgentRequest) [][]byte {
			return agent.reply(req, v3TestAgentReply{
				pduType:   Report,
				vars:      []SnmpPDU{{Name: usmStatsNotInTimeWindows, Type: Counter32, Value: uint32(1)}},
				msgFlags:  &authNoPriv,
				requestID: &zero,
			})
		},
		v3AgentSysDescr(agent),
	}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthPriv, agent.creds)
	v3HarnessSeedSession(gs, sp, staleBoots, staleTime)
	v3HarnessConnect(t, gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)
	require.Equal(t, 2, agent.requestCount())
	resend := agent.request(1)
	require.Equal(t, GetRequest, resend.Packet.PDUType)
	require.Equal(t, AuthPriv, resend.Packet.MsgFlags&AuthPriv)
	require.Equal(t, v3HarnessBoots, v3ReqSecParams(t, resend).AuthoritativeEngineBoots)
}

func TestV3SeclevelScopedPDUPrivacy(t *testing.T) {
	for _, level := range []SnmpV3MsgFlags{AuthNoPriv, AuthPriv} {
		t.Run(level.String(), func(t *testing.T) {
			gs, sp := newV3HarnessClient(0, level, v3HarnessCredsAuthPriv())
			v3HarnessSeedSession(gs, sp, v3HarnessBoots, v3HarnessTime)
			require.NoError(t, sp.InitSecurityKeys())
			msg, err := gs.SnmpEncodePacket(GetRequest, []SnmpPDU{{Name: v3HarnessSysDescrOID, Type: Null}}, 0, 0)
			require.NoError(t, err)

			result := &SnmpPacket{SecurityParameters: sp.Copy(), Logger: gs.Logger}
			cursor, err := gs.unmarshalHeader(msg, result)
			require.NoError(t, err)
			require.Equal(t, level, result.MsgFlags&AuthPriv)

			// Decryption can overwrite the ciphertext. Keep the original for
			// the second call, which changes only the decoded privacy bit.
			_, _, err = gs.decryptPacket(bytes.Clone(msg), cursor, result)
			require.NoError(t, err)

			result.MsgFlags ^= AuthPriv &^ AuthNoPriv
			_, _, err = gs.decryptPacket(msg, cursor, result)
			require.ErrorContains(t, err, "scopedPDU encryption does not match msgFlags")
		})
	}
}
