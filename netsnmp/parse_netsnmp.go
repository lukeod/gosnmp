// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build netsnmp

package netsnmp

/*
#cgo LDFLAGS: -lnetsnmp
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#define MAX_PARSE_VARS 64

typedef struct {
	int     success;          // 0 = parsed ok, -1 = error
	long    version;
	char    community[256];
	size_t  community_len;
	int     pdu_type;
	long    reqid;
	long    errstat;
	long    errindex;
	int     num_vars;
	u_char  var_types[MAX_PARSE_VARS];
} parse_result_t;

static int initialized = 0;

// Parse a raw SNMP v1/v2c packet using net-snmp.
// Returns 0 on success, -1 on parse failure.
static int parse_snmp_packet(const u_char *data, size_t length, parse_result_t *result) {
	u_char community[COMMUNITY_MAX_LEN];
	size_t community_length = COMMUNITY_MAX_LEN;
	long version = 0;
	u_char *pdu_data;
	size_t pdu_length;
	netsnmp_pdu *pdu;
	netsnmp_variable_list *vp;
	int rc;

	if (!initialized) {
		// Suppress MIB loading warnings - we only need the parser
		setenv("MIBS", "", 1);
		init_snmp("gosnmp_fuzz");
		initialized = 1;
	}

	memset(result, 0, sizeof(*result));
	result->success = -1;

	if (length < 2 || length > 65535) {
		return -1;
	}

	// Make a mutable copy since net-snmp may modify the buffer
	u_char *buf = (u_char *)malloc(length);
	if (!buf) return -1;
	memcpy(buf, data, length);
	pdu_length = length;

	// Parse the community string header (v1/v2c)
	pdu_data = snmp_comstr_parse(buf, &pdu_length,
	                              community, &community_length,
	                              &version);
	if (pdu_data == NULL) {
		free(buf);
		return -1;
	}

	// Only handle v1/v2c
	if (version != SNMP_VERSION_1 && version != SNMP_VERSION_2c) {
		free(buf);
		return -1;
	}

	pdu = snmp_pdu_create(0);
	if (!pdu) {
		free(buf);
		return -1;
	}

	rc = snmp_pdu_parse(pdu, pdu_data, &pdu_length);
	if (rc < 0) {
		snmp_free_pdu(pdu);
		free(buf);
		return -1;
	}

	// Success - extract results
	result->success = 0;
	result->version = version;
	if (community_length > 0 && community_length < sizeof(result->community)) {
		memcpy(result->community, community, community_length);
	}
	result->community_len = community_length;
	result->pdu_type = pdu->command;
	result->reqid = pdu->reqid;
	result->errstat = pdu->errstat;
	result->errindex = pdu->errindex;

	// Count and type-tag varbinds
	int n = 0;
	for (vp = pdu->variables; vp && n < MAX_PARSE_VARS; vp = vp->next_variable) {
		result->var_types[n] = vp->type;
		n++;
	}
	result->num_vars = n;

	snmp_free_pdu(pdu);
	free(buf);
	return 0;
}
*/
import "C"
import "unsafe"

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

// NetsnmpParsePacket parses raw SNMP packet bytes using net-snmp's C library.
func NetsnmpParsePacket(data []byte) ParseResult {
	if len(data) == 0 {
		return ParseResult{}
	}

	var cresult C.parse_result_t
	cdata := C.CBytes(data)
	defer C.free(cdata)

	C.parse_snmp_packet((*C.u_char)(cdata), C.size_t(len(data)), &cresult)

	result := ParseResult{
		Success:   cresult.success == 0,
		Version:   int(cresult.version),
		Community: C.GoStringN(&cresult.community[0], C.int(cresult.community_len)),
		PDUType:   int(cresult.pdu_type),
		RequestID: int32(cresult.reqid),
		ErrStat:   int32(cresult.errstat),
		ErrIndex:  int32(cresult.errindex),
		NumVars:   int(cresult.num_vars),
	}
	if result.NumVars > 0 {
		result.VarTypes = C.GoBytes(unsafe.Pointer(&cresult.var_types[0]), C.int(cresult.num_vars))
	}
	return result
}
