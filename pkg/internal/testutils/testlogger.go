/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testutils

import (
	"bytes"
	"fmt"
	"log"
)

// implements logger.Logger (to be used with connlist-analyzer)
type TestLogger struct {
	l      *log.Logger
	buffer *bytes.Buffer
}

// NewTestLogger returns a new TestLogger that writes to a buffer for testing
func NewTestLogger() *TestLogger {
	var buf bytes.Buffer
	return &TestLogger{
		l:      log.New(&buf, "", 0),
		buffer: &buf,
	}
}

// GetLoggerMessages  returns logged messages as a string
func (tl *TestLogger) GetLoggerMessages() string {
	return tl.buffer.String()
}

// implementing the interface funcs:

// Debugf writes a debug message to the log
func (tl *TestLogger) Debugf(format string, o ...interface{}) {
	tl.l.Printf(format, o...)
}

// Infof writes an informative message to the log
func (tl *TestLogger) Infof(format string, o ...interface{}) {
	tl.l.Printf(format, o...)
}

// Warnf writes a warning message to the log
func (tl *TestLogger) Warnf(format string, o ...interface{}) {
	tl.l.Println(format)
}

// Errorf writes an error message to the log
func (tl *TestLogger) Errorf(err error, format string, o ...interface{}) {
	tl.l.Printf("%s: %v", fmt.Sprintf(format, o...), err)
}
