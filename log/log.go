// Copyright (C) 2025 CISPA Helmholtz Center for Information Security
// Author: Kevin Morio <kevin.morio@cispa.de>
//
// This file is part of go-annotate.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the MIT License as published by
// the Open Source Initiative.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// MIT License for more details.
//
// You should have received a copy of the MIT License
// along with this program. If not, see <https://opensource.org/licenses/MIT>.

package log

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/fxamacker/cbor/v2"
)

type Format int

const (
	FormatJSON Format = iota
	FormatCBOR
	FormatText
	FormatDebug

	PairFunctionName = "pair"
	separator        = "_"
	EnterSuffix      = "Enter"
	LeaveSuffix      = "Leave"
	CallDepth        = 5
)

var (
	// Global instance for backward compatibility.
	defaultLogger *Logger
	setupOnce     sync.Once
)

type Logger struct {
	counter     uint64         // Instance-specific counter
	writer      io.Writer      // Writer for file mode
	format      Format         // Log format
	eventBuffer chan *FuncCall // Buffered channel for events
	sentCount   uint64         // Counter for debugging socket sends
}

// Log is the central logging function. It sends the event to the buffered
// channel. Uses non-blocking sends to prevent WireGuard worker deadlocks.
func (l *Logger) Log(fn *FuncCall) {
	// Always use non-blocking sends to prevent WireGuard workers from hanging
	select {
	case l.eventBuffer <- fn:
		// Event successfully queued
	default:
		// Channel is full - determine context for error message
		logTarget := os.Getenv("GO_ANNOTATE_LOG_TARGET")
		if logTarget != "" && isSocketAddress(logTarget) {
			log.Printf("Critical: Socket event buffer full (network issue?), dropping event: %s", fn.Name)
		} else {
			log.Printf("Warning: Event buffer full, dropping event: %s", fn.Name)
		}
	}
}

// argBufferPool reuses slices for formatted arguments to reduce allocations.
var argBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]string, 0, 8) // Pre-allocate for typical argument counts
	},
}

func (l *Logger) LogEnter(id uint64, name string, args []any) {
	// Get reusable slice from pool
	formattedArgs := argBufferPool.Get().([]string)
	formattedArgs = formattedArgs[:0] // Reset length but keep capacity

	// Pre-allocate capacity if needed
	needed := len(args) + 1
	if cap(formattedArgs) < needed {
		formattedArgs = make([]string, 0, needed)
	}

	// Format ID first
	formattedArgs = append(formattedArgs, strconv.FormatUint(id, 10))

	// Format arguments
	for _, arg := range args {
		formattedArgs = append(formattedArgs, format(arg))
	}

	// Create function call - reuse the formatted args slice
	funcCall := &FuncCall{
		Name:    name + separator + EnterSuffix,
		Args:    append([]string(nil), formattedArgs...), // Copy to avoid pool interference
		Results: nil,
		Time:    time.Now(),
	}

	// Return slice to pool
	argBufferPool.Put(formattedArgs[:0])

	l.Log(funcCall)
}

func (l *Logger) LogLeave(id uint64, name string, args []any, results []any) {
	// Get reusable slices from pool
	formattedArgs := argBufferPool.Get().([]string)
	formattedArgs = formattedArgs[:0]

	formattedResults := argBufferPool.Get().([]string)
	formattedResults = formattedResults[:0]

	// Pre-allocate capacity if needed
	neededArgs := len(args) + 1
	if cap(formattedArgs) < neededArgs {
		formattedArgs = make([]string, 0, neededArgs)
	}

	neededResults := len(results)
	if cap(formattedResults) < neededResults {
		formattedResults = make([]string, 0, neededResults)
	}

	// Format ID first
	formattedArgs = append(formattedArgs, strconv.FormatUint(id, 10))

	// Format arguments
	for _, arg := range args {
		formattedArgs = append(formattedArgs, format(arg))
	}

	// Format results
	for _, result := range results {
		formattedResults = append(formattedResults, format(result))
	}

	// Create function call - copy slices to avoid pool interference
	funcCall := &FuncCall{
		Name:    name + separator + LeaveSuffix,
		Args:    append([]string(nil), formattedArgs...),
		Results: append([]string(nil), formattedResults...),
		Time:    time.Now(),
	}

	// Return slices to pool
	argBufferPool.Put(formattedArgs[:0])
	argBufferPool.Put(formattedResults[:0])

	l.Log(funcCall)
}

// NewLogger creates a new Logger instance with the specified format.
// This allows for instance-based logging instead of relying on global state.
func NewLogger(format Format) *Logger {
	// Buffer size is optimized for socket mode to handle network delays
	bufferSize := 10000

	// Check if we're in socket mode by examining the log target destination
	logTarget := os.Getenv("GO_ANNOTATE_LOG_TARGET")
	if logTarget != "" && isSocketAddress(logTarget) {
		bufferSize = 100000 // Larger buffer for socket mode to handle network delays
	}

	return &Logger{
		format:      format,
		eventBuffer: make(chan *FuncCall, bufferSize),
	}
}

// init is called once when the package is imported. It sets up the logger
// based on environment variables.
func init() {
	setupOnce.Do(func() {
		var logFormat Format
		switch os.Getenv("GO_ANNOTATE_LOG_FORMAT") {
		case "json":
			logFormat = FormatJSON
		case "cbor":
			logFormat = FormatCBOR
		case "text":
			logFormat = FormatText
		case "debug":
			logFormat = FormatDebug
		}

		// Create the global logger instance
		defaultLogger = NewLogger(logFormat)

		// Get log target destination (file path or socket address)
		logTarget := os.Getenv("GO_ANNOTATE_LOG_TARGET")
		if logTarget == "" {
			log.Println("Warning: GO_ANNOTATE_LOG_TARGET not set. Logging is disabled.")
			// Drain the channel to prevent blocking producer applications
			go func() {
				for event := range defaultLogger.eventBuffer {
					_ = event // Discard events when logging is disabled
				}
			}()
			return
		}

		// --- AUTO-DETECT SOCKET vs FILE MODE ---
		if isSocketAddress(logTarget) {
			// **SOCKET MODE** - detected host:port pattern
			log.Printf("Logger initialized in SOCKET mode to %s", logTarget)
			go defaultLogger.manageConnectionAndSend() // Start the network worker
		} else {
			// **FILE MODE** - detected file path pattern
			log.Printf("Logger initialized in FILE mode to %s", logTarget)

			logFile, err := os.OpenFile(logTarget, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o666)
			if err != nil {
				log.Fatalf("Fatal: Could not open log file %s: %v", logTarget, err)
			}
			defaultLogger.writer = logFile
			go defaultLogger.processLogQueueToFile(logFile) // Start the file worker
		}
	})
}

// processLogQueueToFile is the background worker for FILE mode.
func (l *Logger) processLogQueueToFile(file *os.File) {
	defer file.Close()
	for fn := range l.eventBuffer {
		bytes := formatEvent(fn, l.format)
		if _, err := file.Write(bytes); err != nil {
			// A write failure to a local file is usually a critical error.
			log.Printf("Fatal: Failed to write to log file: %v", err)
		}
	}
}

// manageConnectionAndSend is the background worker for SOCKET mode.
func (l *Logger) manageConnectionAndSend() {
	logAddr := os.Getenv("GO_ANNOTATE_LOG_TARGET") // e.g., "localhost:8080" or "/tmp/log.sock"
	if logAddr == "" {
		log.Println("Warning: GO_ANNOTATE_LOG_TARGET (socket address) not set. Network logging is disabled.")
		for event := range l.eventBuffer {
			_ = event // Discard events when socket address is not set
		} // Drain the channel
		return
	}

	// Determine if it's a TCP or Unix socket based on the address format
	networkType := "tcp"
	if strings.Contains(logAddr, "/") || strings.Contains(logAddr, "\\") {
		networkType = "unix"
	}

	retryBase, maxRetry := time.Second, 30*time.Second
	currentRetry := retryBase

	// Buffer to hold events during connection failures
	var eventBacklog []*FuncCall

	for {
		conn, err := net.DialTimeout(networkType, logAddr, 5*time.Second)
		if err != nil {
			log.Printf("Log connection to %s failed: %v. Retrying in %v\n", logAddr, err, currentRetry)

			// During connection failure, buffer ALL incoming events to prevent loss
			timeout := time.After(currentRetry)
			drainCount := 0
		drainLoop:
			for {
				select {
				case fn := <-l.eventBuffer:
					eventBacklog = append(eventBacklog, fn)
					drainCount++
					// Limit backlog size to prevent memory issues
					if len(eventBacklog) > 10000 {
						eventBacklog = eventBacklog[2000:] // Keep most recent 8000 events
						log.Printf("Event backlog overflow: dropped %d old events, keeping %d", 2000, len(eventBacklog))
					}
				case <-timeout:
					if drainCount > 0 {
						log.Printf("Buffered %d events during connection failure", drainCount)
					}
					break drainLoop // Exit drain loop and retry connection
				}
			}

			currentRetry *= 2
			if currentRetry > maxRetry {
				currentRetry = maxRetry
			}
			continue
		}

		log.Printf("Log connection to %s established. Backlog size: %d\n", logAddr, len(eventBacklog))
		currentRetry = retryBase // Reset retry delay on successful connection

		// Set TCP keep-alive if it's a TCP connection
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			if err := tcpConn.SetKeepAlive(true); err != nil {
				log.Printf("Failed to set keep-alive: %v", err)
			}
			if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
				log.Printf("Failed to set keep-alive period: %v", err)
			}
		}

		// Send any backlogged events first - CRITICAL for event ordering
		for i, fn := range eventBacklog {
			bytes := formatEvent(fn, l.format)
			if bytes == nil {
				continue
			}
			if _, err := conn.Write(bytes); err != nil {
				log.Printf("Failed to write backlogged event %d to log socket: %v. Reconnecting...\n", i, err)
				conn.Close()
				// Keep remaining events in backlog for next connection
				eventBacklog = eventBacklog[i:]
				goto reconnect
			}
			atomic.AddUint64(&l.sentCount, 1)
		}
		eventBacklog = nil // Clear the backlog after successful send
		log.Printf("Successfully sent all backlogged events to %s", logAddr)

		// Main event sending loop - process events in strict order
	sendingLoop:
		for fn := range l.eventBuffer {
			bytes := formatEvent(fn, l.format)
			if bytes == nil {
				continue
			}

			if _, err := conn.Write(bytes); err != nil {
				log.Printf("Failed to write to log socket: %v. Reconnecting...\n", err)
				// Put the failed event into backlog for retry
				eventBacklog = append(eventBacklog, fn)
				break sendingLoop // Exit inner loop to trigger reconnection
			}

			sent := atomic.AddUint64(&l.sentCount, 1)
			if sent%1000 == 0 {
				log.Printf("Sent %d events to socket", sent)
			}
		}

	reconnect:
		conn.Close()
	}
}

// marshalBufferPool reuses byte buffers for JSON/CBOR marshaling.
var marshalBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, 512) // Start with 512 bytes for typical events
	},
}

// formatEvent marshals a FuncCall into bytes based on the configured format.
// Optimized to reduce allocations in the hot path.
func formatEvent(fn *FuncCall, format Format) []byte {
	var bytes []byte
	var err error

	switch format {
	case FormatText:
		// Simple text format - minimal allocation
		str := fn.String()
		bytes = make([]byte, len(str)+1)
		copy(bytes, str)
		bytes[len(str)] = '\n'

	case FormatJSON:
		// Get buffer from pool for JSON marshaling
		buf := marshalBufferPool.Get().([]byte)
		buf = buf[:0]

		// Create timed event
		timedEvent := fn.toTimedEvent()

		// Marshal to JSON
		jsonBytes, err := json.Marshal(timedEvent)
		if err == nil {
			// Copy to our buffer and add newline
			needed := len(jsonBytes) + 1
			if cap(buf) < needed {
				buf = make([]byte, 0, needed+128) // Add some extra capacity
			}
			buf = append(buf, jsonBytes...)
			buf = append(buf, '\n')

			// Create result slice
			bytes = make([]byte, len(buf))
			copy(bytes, buf)
		}

		// Return buffer to pool
		marshalBufferPool.Put(buf)

	case FormatCBOR:
		// CBOR marshaling - reuse buffer
		timedEvent := fn.toTimedEvent()
		bytes, err = cbor.Marshal(timedEvent)

	case FormatDebug:
		// Debug format with better formatting
		debugStr := fmt.Sprintf("%#v\n", fn)
		bytes = []byte(debugStr)
	}

	if err != nil {
		log.Printf("Error formatting log event: %v", err)
		return nil
	}
	return bytes
}

// --- Data Structures and Formatting Helpers (Unchanged) ---

// IsCalledFrom, CallTrace, FuncCall, TimedEvent, WeakTerm, and their methods
// remain the same as your original file.

func (f *FuncCall) String() string {
	if len(f.Results) == 0 {
		return fmt.Sprintf("%s(%s)", f.Name, strings.Join(f.Args, ", "))
	}
	return fmt.Sprintf("%s(%s) = (%s)", f.Name, strings.Join(f.Args, ", "), strings.Join(f.Results, ", "))
}

type FuncCall struct {
	Name    string    `json:"name" cbor:"name"`
	Args    []string  `json:"args" cbor:"args"`
	Results []string  `json:"results" cbor:"results"`
	Time    time.Time `json:"time" cbor:"time"`
}

type TimedEvent struct {
	Time  int64     `json:"time" cbor:"time"`
	Event *WeakTerm `json:"event" cbor:"event"`
}

type WeakTerm struct {
	Name  string     `json:"name,omitempty" cbor:"name,omitempty"`
	Type  string     `json:"type,omitempty" cbor:"type,omitempty"`
	Value string     `json:"value,omitempty" cbor:"value,omitempty"`
	Args  []WeakTerm `json:"args,omitempty" cbor:"args,omitempty"`
}

// weakTermPool reuses WeakTerm slices for event creation.
var weakTermPool = sync.Pool{
	New: func() interface{} {
		return make([]WeakTerm, 0, 8)
	},
}

func (f *FuncCall) toTimedEvent() *TimedEvent {
	// Get reusable slices from pool
	args := weakTermPool.Get().([]WeakTerm)
	args = args[:0]

	results := weakTermPool.Get().([]WeakTerm)
	results = results[:0]

	// Pre-allocate capacity if needed
	if cap(args) < len(f.Args) {
		args = make([]WeakTerm, 0, len(f.Args))
	}
	if cap(results) < len(f.Results) {
		results = make([]WeakTerm, 0, len(f.Results))
	}

	// Build args terms - reuse WeakTerm structs
	for _, argStr := range f.Args {
		args = append(args, WeakTerm{
			Type:  "constant",
			Value: argStr,
		})
	}

	// Build results terms - reuse WeakTerm structs
	for _, resultStr := range f.Results {
		results = append(results, WeakTerm{
			Type:  "constant",
			Value: resultStr,
		})
	}

	// Create the timed event structure
	timedEvent := &TimedEvent{
		Time: f.Time.UnixNano(),
		Event: &WeakTerm{
			Name: PairFunctionName,
			Type: "function",
			Args: []WeakTerm{
				// First element: function with arguments
				{
					Name: f.Name,
					Type: "function",
					Args: append([]WeakTerm(nil), args...), // Copy to avoid pool interference
				},
				// Second element: tuple of return values
				{
					Name: PairFunctionName,
					Type: "function",
					Args: append([]WeakTerm(nil), results...), // Copy to avoid pool interference
				},
			},
		},
	}

	// Return slices to pool
	weakTermPool.Put(args)
	weakTermPool.Put(results)

	return timedEvent
}

// formatBuffer is a reusable buffer pool for string building to reduce allocations.
var formatBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, 64) // Start with 64 bytes capacity
	},
}

// format converts any value to its string representation optimized for performance.
// This is a hot path function called for every logged argument and result.
func format(i any) string {
	if i == nil {
		return ""
	}

	switch v := i.(type) {
	// Fast path for integers - use strconv directly
	case int:
		return strconv.FormatInt(int64(v), 10)
	case int8:
		return strconv.FormatInt(int64(v), 10)
	case int16:
		return strconv.FormatInt(int64(v), 10)
	case int32:
		return strconv.FormatInt(int64(v), 10)
	case int64:
		return strconv.FormatInt(v, 10)
	case uint:
		return strconv.FormatUint(uint64(v), 10)
	case uint8:
		return strconv.FormatUint(uint64(v), 10)
	case uint16:
		return strconv.FormatUint(uint64(v), 10)
	case uint32:
		return strconv.FormatUint(uint64(v), 10)
	case uint64:
		return strconv.FormatUint(v, 10)

	// Fast path for floats - use strconv directly
	case float32:
		return strconv.FormatFloat(float64(v), 'f', 6, 32)
	case float64:
		return strconv.FormatFloat(v, 'f', 6, 64)

	// Optimized byte slice formatting with buffer reuse
	case []byte:
		if len(v) == 0 {
			return "0x"
		}
		buf := formatBufferPool.Get().([]byte)
		buf = buf[:0] // Reset length but keep capacity
		buf = append(buf, "0x"...)
		buf = appendHex(buf, v)
		result := string(buf)
		formatBufferPool.Put(buf)
		return result

	// Optimized nested byte slice formatting
	case [][]byte:
		if len(v) == 0 {
			return "0x"
		}
		buf := formatBufferPool.Get().([]byte)
		buf = buf[:0]
		buf = append(buf, "0x"...)
		for i, b := range v {
			if i > 0 {
				buf = append(buf, '|')
			}
			buf = appendHex(buf, b)
		}
		result := string(buf)
		formatBufferPool.Put(buf)
		return result

	// Fixed-size array optimizations
	case [8]uint32:
		buf := formatBufferPool.Get().([]byte)
		buf = buf[:0]
		buf = append(buf, "0x"...)
		// Direct unsafe conversion is already optimal
		buf = appendHex(buf, (*(*[32]byte)(unsafe.Pointer(&v)))[:])
		result := string(buf)
		formatBufferPool.Put(buf)
		return result

	case [32]uint8:
		buf := formatBufferPool.Get().([]byte)
		buf = buf[:0]
		buf = append(buf, "0x"...)
		buf = appendHex(buf, v[:])
		result := string(buf)
		formatBufferPool.Put(buf)
		return result

	case *[32]uint8:
		if v == nil {
			return "<nil>"
		}
		buf := formatBufferPool.Get().([]byte)
		buf = buf[:0]
		buf = append(buf, "0x"...)
		buf = appendHex(buf, v[:])
		result := string(buf)
		formatBufferPool.Put(buf)
		return result

	// String formatting - already quoted efficiently by Go's fmt
	case string:
		return fmt.Sprintf("%q", v)

	// Boolean fast path - avoid string allocation
	case bool:
		if v {
			return "1"
		}
		return "0"

	// Error handling for common types
	case error:
		return fmt.Sprintf("%q", v.Error())

	// Default case for other types
	default:
		rv := reflect.ValueOf(i)
		switch rv.Kind() {
		case reflect.Ptr:
			if rv.IsNil() {
				return "<nil>"
			}
			return fmt.Sprintf("%p", i)
		case reflect.Slice, reflect.Array:
			// Handle generic slices/arrays by their length and type
			return fmt.Sprintf("[%d]%s", rv.Len(), rv.Type().Elem().String())
		case reflect.Map:
			return fmt.Sprintf("map[%d]", rv.Len())
		case reflect.Chan:
			return fmt.Sprintf("chan(%s)", rv.Type().Elem().String())
		case reflect.Func:
			return fmt.Sprintf("func(%s)", rv.Type().String())
		default:
			// Last resort - use reflection to get a string representation
			return fmt.Sprintf("%v", i)
		}
	}
}

// appendHex appends hex-encoded bytes to buffer efficiently.
func appendHex(dst, src []byte) []byte {
	if len(src) == 0 {
		return dst
	}
	// Pre-allocate space to avoid repeated allocations
	n := len(src) * 2
	if cap(dst)-len(dst) < n {
		// Grow buffer if needed
		newDst := make([]byte, len(dst), len(dst)+n+64)
		copy(newDst, dst)
		dst = newDst
	}
	return hex.AppendEncode(dst, src)
}

// ID generates a unique ID for function call tracking.
// Uses the default logger's counter for backward compatibility.
func ID() uint64 {
	if defaultLogger != nil {
		return atomic.AddUint64(&defaultLogger.counter, 1)
	}
	// Fallback if called before initialization
	return 0
}

// ID method for instance-based usage.
func (l *Logger) ID() uint64 {
	return atomic.AddUint64(&l.counter, 1)
}

// IsCalledFrom returns true if the function call stack contains the search string.
func IsCalledFrom(s string) bool {
	pcs := make([]uintptr, CallDepth)
	n := runtime.Callers(2, pcs)
	frames := runtime.CallersFrames(pcs[:n])

	found := false
	for {
		frame, more := frames.Next()
		if strings.Contains(frame.Function, s) {
			found = true
		}
		if !more {
			break
		}
	}

	return found
}

func (l *Logger) CallTrace() {
	var s string

	pc, file, line, ok := runtime.Caller(3) // Change the depth as needed
	if ok {
		funcName := runtime.FuncForPC(pc).Name()
		// Clean up the function name
		funcName = strings.TrimPrefix(funcName, "main.")
		s = fmt.Sprintf("Called from %s, file %s, line %d\n", funcName, file, line)
	} else {
		s = "Called from unknown location\n"
	}
	l.Log(&FuncCall{
		Name: "TRACE",
		Args: []string{s},
		Time: time.Now(),
	})
}

// Global convenience functions for backward compatibility
// These delegate to the default logger instance

// LogEnter logs a function entry using the global logger.
func LogEnter(id uint64, name string, args []any) {
	if defaultLogger != nil {
		defaultLogger.LogEnter(id, name, args)
	}
}

// LogLeave logs a function exit using the global logger.
func LogLeave(id uint64, name string, args []any, results []any) {
	if defaultLogger != nil {
		defaultLogger.LogLeave(id, name, args, results)
	}
}

// Log logs a function call using the global logger.
func Log(fn *FuncCall) {
	if defaultLogger != nil {
		defaultLogger.Log(fn)
	}
}

// CallTrace logs a call trace using the global logger.
func CallTrace() {
	if defaultLogger != nil {
		defaultLogger.CallTrace()
	}
}

// isSocketAddress determines if the given address is a network socket (host:port)
// rather than a file path. Returns true for TCP addresses, false for file paths.
func isSocketAddress(addr string) bool {
	// Check for typical socket patterns:
	// - Contains ":" and no "/" or "\" (TCP address like "localhost:8080")
	// - Unix socket paths contain "/" or "\"
	return strings.Contains(addr, ":") && !strings.Contains(addr, "/") && !strings.Contains(addr, "\\")
}
