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

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

func main() {
	// Listen on port 8080
	listener, err := net.Listen("tcp", "localhost:8080")
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	defer listener.Close()

	fmt.Println("Socket server listening on localhost:8080")
	fmt.Println("Waiting for connections...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		fmt.Printf("New connection from: %s\n", conn.RemoteAddr())

		// Handle each connection in a goroutine
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Read data in chunks to handle both text and binary formats
	buffer := make([]byte, 4096)
	messageCount := 0

	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				fmt.Printf("Connection error: %v\n", err)
			}
			break
		}

		data := buffer[:n]
		messageCount++

		// Try to detect format and display appropriately
		if isLikelyJSON(data) {
			fmt.Printf("Message %d (JSON): %s\n", messageCount, string(data))
		} else {
			// Treat as CBOR
			fmt.Printf("Message %d (CBOR hex): %s\n", messageCount, hex.EncodeToString(data))

			// Try to decode each CBOR message
			decodedMessages := decodeCBORMessages(data)
			for i, decoded := range decodedMessages {
				if decoded != "" {
					fmt.Printf("  CBOR message %d decoded: %s\n", i+1, decoded)
				}
			}
		}
	}

	fmt.Printf("Connection from %s closed (received %d messages)\n", conn.RemoteAddr(), messageCount)
}

// isLikelyJSON checks if data looks like JSON (improved detection).
func isLikelyJSON(data []byte) bool {
	text := strings.TrimSpace(string(data))
	// Check for common JSON patterns including newline-delimited JSON
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
			return true
		}
	}
	return false
}

// decodeCBORMessages attempts to decode multiple CBOR messages from data.
func decodeCBORMessages(data []byte) []string {
	var results []string

	// CBOR messages might be concatenated, try to decode as single message first
	if decoded := decodeCBOR(data); decoded != "" {
		return []string{decoded}
	}

	// If that fails, we could implement more sophisticated CBOR message splitting
	// For now, just return the single attempt
	return results
}

// decodeCBOR attempts to decode CBOR data to JSON for display.
func decodeCBOR(data []byte) string {
	var result interface{}
	if err := cbor.Unmarshal(data, &result); err != nil {
		return ""
	}

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return ""
	}

	return string(jsonBytes)
}
