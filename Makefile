# go-annotate Makefile
# Copyright (C) 2025 CISPA Helmholtz Center for Information Security
# Author: Kevin Morio <kevin.morio@cispa.de>
#
# This file is part of go-annotate.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the MIT License as published by
# the Open Source Initiative.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# MIT License for more details.
#
# You should have received a copy of the MIT License
# along with this program. If not, see <https://opensource.org/licenses/MIT>.

.PHONY: help build test lint clean install format benchmark coverage docker-test release-test examples

# Default target
help: ## Show this help message
	@echo "go-annotate - High-Performance Go Code Instrumentation"
	@echo ""
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Build configuration
BINARY_NAME := go-annotate
BUILD_FLAGS := -ldflags="-s -w"
GO_VERSION := 1.22

# Build targets
build: ## Build the binary
	@echo "Building $(BINARY_NAME)..."
	go build $(BUILD_FLAGS) -o $(BINARY_NAME) .

build-all: ## Build binaries for all platforms
	@echo "Building for all platforms..."
	GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -o $(BINARY_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build $(BUILD_FLAGS) -o $(BINARY_NAME)-linux-arm64 .
	GOOS=darwin GOARCH=amd64 go build $(BUILD_FLAGS) -o $(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build $(BUILD_FLAGS) -o $(BINARY_NAME)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build $(BUILD_FLAGS) -o $(BINARY_NAME)-windows-amd64.exe .

install: build ## Install the binary to $GOPATH/bin
	@echo "Installing $(BINARY_NAME)..."
	go install $(BUILD_FLAGS) .

# Testing targets
test: ## Run all tests
	@echo "Running tests..."
	go test -v -race ./...

test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

benchmark: ## Run benchmarks
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

benchmark-compare: ## Run benchmarks multiple times for comparison
	@echo "Running benchmark comparison..."
	go test -bench=. -benchmem -count=5 ./... | tee benchmark.txt

# Code quality targets
lint: ## Run linter
	@echo "Running linter..."
	golangci-lint run --timeout=5m

format: ## Format code
	@echo "Formatting code..."
	gofmt -s -w .
	go mod tidy

# Development targets
clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME)-*
	rm -f coverage.out coverage.html
	rm -f benchmark.txt
	go clean -cache -testcache -modcache

deps: ## Download and verify dependencies
	@echo "Downloading dependencies..."
	go mod download
	go mod verify

update-deps: ## Update dependencies
	@echo "Updating dependencies..."
	go get -u ./...
	go mod tidy

# Testing with examples
examples: build ## Run examples to verify functionality
	@echo "Testing with examples..."
	@mkdir -p examples
	@echo 'package main\n\nimport "fmt"\n\nfunc Add(a, b int) int {\n\treturn a + b\n}\n\nfunc main() {\n\tresult := Add(5, 10)\n\tfmt.Printf("Result: %d\\n", result)\n}' > examples/simple.go
	./$(BINARY_NAME) -import "github.com/specmon/go-annotate/log" examples/simple.go > examples/instrumented.go
	@echo "Example instrumentation complete. Check examples/instrumented.go"

socket-test: build ## Test socket functionality with test server
	@echo "Starting socket test..."
	@echo "Terminal 1: Starting test server..."
	go run test/test_socket_server.go &
	@sleep 2
	@echo "Terminal 2: Running instrumented example..."
	./$(BINARY_NAME) -import "github.com/specmon/go-annotate/log" -w examples/simple.go || true
	GO_ANNOTATE_LOG_TARGET="localhost:8080" GO_ANNOTATE_LOG_FORMAT="json" go run examples/simple.go || true
	@echo "Socket test complete"

# Release preparation
release-test: ## Test release build process
	@echo "Testing release build..."
	$(MAKE) clean
	$(MAKE) test
	$(MAKE) lint
	$(MAKE) build-all
	@echo "Release test complete"

version: ## Show version information
	@echo "go-annotate build information:"
	@echo "Go version: $(shell go version)"
	@echo "Git commit: $(shell git rev-parse HEAD)"
	@echo "Build time: $(shell date)"

# Docker targets (optional)
docker-test: ## Run tests in Docker container
	@echo "Running tests in Docker..."
	docker run --rm -v $(PWD):/app -w /app golang:$(GO_VERSION) make test

docker-build: ## Build in Docker container
	@echo "Building in Docker..."
	docker run --rm -v $(PWD):/app -w /app golang:$(GO_VERSION) make build

# Development helpers
watch: ## Watch for changes and run tests
	@echo "Watching for changes..."
	@command -v entr >/dev/null 2>&1 || { echo "entr is required for watch. Install with: brew install entr"; exit 1; }
	find . -name "*.go" | entr -c make test

setup-dev: ## Setup development environment
	@echo "Setting up development environment..."
	go mod download
	@echo "Installing golangci-lint..."
	@command -v golangci-lint >/dev/null 2>&1 || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "Development environment ready!"

# Quality checks
quality: ## Run all quality checks
	@echo "Running quality checks..."
	$(MAKE) format
	$(MAKE) lint
	$(MAKE) test
	$(MAKE) benchmark
	@echo "Quality checks complete!"

# Pre-commit hook
pre-commit: ## Run pre-commit checks
	@echo "Running pre-commit checks..."
	$(MAKE) format
	$(MAKE) lint
	$(MAKE) test
	@echo "Pre-commit checks passed!"