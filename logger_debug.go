// Copyright 2021 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build !gosnmp_nodebug

package gosnmp

func (l *Logger) Print(v ...any) {
	if l.logger != nil {
		l.logger.Print(v...)
	}
}

func (l *Logger) Printf(format string, v ...any) {
	if l.logger != nil {
		l.logger.Printf(format, v...)
	}
}

// Enabled returns true if logging is enabled (i.e., a logger has been set).
// Use this to guard expensive log argument evaluation.
func (l *Logger) Enabled() bool {
	return l.logger != nil
}
