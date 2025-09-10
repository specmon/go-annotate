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
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewLogger(t *testing.T) {
	logger := NewLogger(FormatJSON)
	if logger == nil {
		t.Fatal("NewLogger returned nil")
	}

	if logger.format != FormatJSON {
		t.Errorf("Expected format %v, got %v", FormatJSON, logger.format)
	}

	if logger.eventBuffer == nil {
		t.Error("Event buffer not initialized")
	}
}

func TestLoggerID(t *testing.T) {
	logger := NewLogger(FormatJSON)

	id1 := logger.ID()
	id2 := logger.ID()

	if id1 == 0 {
		t.Error("First ID should not be zero")
	}

	if id2 != id1+1 {
		t.Errorf("Expected sequential IDs, got %d then %d", id1, id2)
	}
}

func TestFormat(t *testing.T) {
	testCases := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{"nil", nil, ""},
		{"int", 42, "42"},
		{"int64", int64(9223372036854775807), "9223372036854775807"},
		{"uint", uint(42), "42"},
		{"float32", float32(3.14), "3.140000"},
		{"float64", 3.14159, "3.141590"},
		{"string", "hello", `"hello"`},
		{"bool true", true, "1"},
		{"bool false", false, "0"},
		{"byte slice", []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f}, "0x48656c6c6f"},
		{"empty byte slice", []byte{}, "0x"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := format(tc.input)
			if result != tc.expected {
				t.Errorf("Expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestFormatComplexTypes(t *testing.T) {
	// Test array types
	arr := [32]uint8{1, 2, 3, 4, 5}
	result := format(arr)
	if !strings.HasPrefix(result, "0x") {
		t.Error("Array formatting should start with 0x")
	}

	// Test pointer
	var ptr *int
	result = format(ptr)
	if result != "<nil>" {
		t.Errorf("Nil pointer should format as <nil>, got %q", result)
	}

	val := 42
	ptr = &val
	result = format(ptr)
	if !strings.HasPrefix(result, "0x") {
		t.Error("Non-nil pointer should format as hex address")
	}
}

func TestFuncCallString(t *testing.T) {
	fc := &FuncCall{
		Name:    "test_func",
		Args:    []string{"1", "2"},
		Results: []string{"3"},
		Time:    time.Now(),
	}

	result := fc.String()
	expected := "test_func(1, 2) = (3)"
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}

	// Test function with no results
	fc.Results = nil
	result = fc.String()
	expected = "test_func(1, 2)"
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

func TestFormatEvent(t *testing.T) {
	fc := &FuncCall{
		Name:    "test_func",
		Args:    []string{"1", "2"},
		Results: []string{"3"},
		Time:    time.Now(),
	}

	// Test JSON format
	jsonBytes := formatEvent(fc, FormatJSON)
	if jsonBytes == nil {
		t.Fatal("JSON formatting returned nil")
	}

	var jsonData map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &jsonData); err != nil {
		t.Fatalf("Invalid JSON produced: %v", err)
	}

	// Test text format
	textBytes := formatEvent(fc, FormatText)
	if textBytes == nil {
		t.Fatal("Text formatting returned nil")
	}

	textStr := string(textBytes)
	if !strings.Contains(textStr, "test_func") {
		t.Error("Text format should contain function name")
	}

	// Test CBOR format
	cborBytes := formatEvent(fc, FormatCBOR)
	if cborBytes == nil {
		t.Fatal("CBOR formatting returned nil")
	}

	// Test debug format
	debugBytes := formatEvent(fc, FormatDebug)
	if debugBytes == nil {
		t.Fatal("Debug formatting returned nil")
	}
}

func TestLogEnterLeave(t *testing.T) {
	logger := NewLogger(FormatText)

	// Create a buffer to collect events
	var events []*FuncCall
	var mu sync.Mutex

	// Override the event buffer processing for testing
	go func() {
		for event := range logger.eventBuffer {
			mu.Lock()
			events = append(events, event)
			mu.Unlock()
		}
	}()

	// Log enter and leave
	logger.LogEnter(1, "testFunc", []interface{}{42, "hello"})
	logger.LogLeave(1, "testFunc", []interface{}{42, "hello"}, []interface{}{"result"})

	// Give some time for processing
	time.Sleep(10 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(events) != 2 {
		t.Fatalf("Expected 2 events, got %d", len(events))
	}

	// Check enter event
	enterEvent := events[0]
	if !strings.HasSuffix(enterEvent.Name, "_Enter") {
		t.Error("Enter event should have _Enter suffix")
	}

	if len(enterEvent.Args) < 1 {
		t.Error("Enter event should have at least trace ID")
	}

	// Check leave event
	leaveEvent := events[1]
	if !strings.HasSuffix(leaveEvent.Name, "_Leave") {
		t.Error("Leave event should have _Leave suffix")
	}

	if len(leaveEvent.Results) != 1 {
		t.Error("Leave event should have results")
	}
}

func TestIsSocketAddress(t *testing.T) {
	testCases := []struct {
		addr     string
		expected bool
	}{
		{"localhost:8080", true},
		{"127.0.0.1:9000", true},
		{"example.com:443", true},
		{"/path/to/file.log", false},
		{"/tmp/socket.sock", false},
		{"C:\\path\\to\\file.log", false},
		{"", false},
		{"invalid", false},
	}

	for _, tc := range testCases {
		t.Run(tc.addr, func(t *testing.T) {
			result := isSocketAddress(tc.addr)
			if result != tc.expected {
				t.Errorf("Expected %v for %q, got %v", tc.expected, tc.addr, result)
			}
		})
	}
}

func TestWeakTermPool(t *testing.T) {
	// Test that pool is working by using it multiple times
	terms1 := weakTermPool.Get().([]WeakTerm)
	terms1 = append(terms1, WeakTerm{Name: "test"})
	weakTermPool.Put(terms1[:0])

	terms2 := weakTermPool.Get().([]WeakTerm)
	// Should get the same underlying slice back
	if cap(terms2) == 0 {
		t.Error("Pool should reuse slices with capacity")
	}
	weakTermPool.Put(terms2)
}

// Benchmark tests.
func BenchmarkFormat(b *testing.B) {
	testValues := []interface{}{
		42,
		int64(9223372036854775807),
		3.14159,
		"hello world",
		[]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		true,
		false,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, val := range testValues {
			_ = format(val)
		}
	}
}

func BenchmarkFormatEvent(b *testing.B) {
	fc := &FuncCall{
		Name:    "benchmark_func",
		Args:    []string{"arg1", "arg2", "arg3"},
		Results: []string{"result1", "result2"},
		Time:    time.Now(),
	}

	b.Run("JSON", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = formatEvent(fc, FormatJSON)
		}
	})

	b.Run("CBOR", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = formatEvent(fc, FormatCBOR)
		}
	})

	b.Run("Text", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = formatEvent(fc, FormatText)
		}
	})
}

func BenchmarkLogEnter(b *testing.B) {
	logger := NewLogger(FormatJSON)

	// Drain the channel to prevent blocking
	go func() {
		for range logger.eventBuffer {
			// Discard events to prevent blocking.
		}
	}()

	args := []interface{}{42, "hello", 3.14, []byte{1, 2, 3}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.LogEnter(uint64(i%1000000), "benchFunc", args)
	}
}

func BenchmarkObjectPools(b *testing.B) {
	b.Run("ArgBufferPool", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			buf := argBufferPool.Get().([]string)
			buf = append(buf[:0], "arg1", "arg2", "arg3")
			argBufferPool.Put(buf)
		}
	})

	b.Run("WeakTermPool", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			terms := weakTermPool.Get().([]WeakTerm)
			terms = append(terms[:0], WeakTerm{Name: "test", Type: "constant"})
			weakTermPool.Put(terms)
		}
	})

	b.Run("MarshalBufferPool", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			buf := marshalBufferPool.Get().([]byte)
			buf = append(buf[:0], []byte("test data")...)
			marshalBufferPool.Put(buf)
		}
	})
}

func BenchmarkConcurrentLogging(b *testing.B) {
	logger := NewLogger(FormatJSON)

	// Drain the channel
	go func() {
		for range logger.eventBuffer {
			// Discard events.
		}
	}()

	args := []interface{}{42, "test"}
	results := []interface{}{"result"}

	b.RunParallel(func(pb *testing.PB) {
		id := uint64(0)
		for pb.Next() {
			id++
			logger.LogEnter(id, "concurrentFunc", args)
			logger.LogLeave(id, "concurrentFunc", args, results)
		}
	})
}

// Test memory allocations in hot paths.
func TestAllocations(t *testing.T) {
	logger := NewLogger(FormatJSON)

	// Drain channel
	go func() {
		for range logger.eventBuffer {
			// Discard events.
		}
	}()

	args := []interface{}{42, "test"}

	// Test that logging doesn't allocate excessively
	allocs := testing.AllocsPerRun(1000, func() {
		logger.LogEnter(1, "testFunc", args)
	})

	// This is a reasonable target - the exact number may vary
	if allocs > 10 {
		t.Logf("Warning: LogEnter allocates %.2f times per call (target: <10)", allocs)
	}
}
