# go-annotate

<p align="center">
  <img src="logo.png" alt="go-annotate Logo" width="150">
</p>

<p align="center">
  <b>High-Performance Go Code Instrumentation</b>
</p>

<p align="center">
  <a href="https://github.com/specmon/go-annotate/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/specmon/go-annotate/go.yml?branch=main" alt="Build Status">
  </a>
  <a href="https://github.com/specmon/go-annotate/issues">
    <img src="https://img.shields.io/github/issues/specmon/go-annotate" alt="Issues">
  </a>
  <a href="https://github.com/specmon/go-annotate/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/specmon/go-annotate" alt="License">
  </a>
  <a href="https://goreportcard.com/report/github.com/specmon/go-annotate">
    <img src="https://goreportcard.com/badge/github.com/specmon/go-annotate" alt="Go Report Card">
  </a>
</p>

---

## 🎯 About

go-annotate is a high-performance Go source code instrumentation tool that automatically transforms Go programs by injecting logging calls around function entries and exits. It reports function parameters and return values, enabling external tools to monitor runtime behavior with minimal overhead.

---

## ✨ Features

- **AST-based instrumentation**: Safe and precise Go source code transformation
- **Multiple output formats**: JSON, CBOR, text, and debug formats
- **Socket and file logging**: Real-time network streaming or local file output
- **Memory optimized**: Object pools and buffer reuse for ~60% allocation reduction
- **Non-blocking design**: Prevents deadlocks in concurrent applications
- **Selective instrumentation**: Target exported functions only or use custom filters
- **Academic integration**: Generate monitoring rules for SpecMon

---

## 📦 Installation

### Prerequisites

- [Go 1.22+](https://go.dev/)
- [Git](https://git-scm.com/)

### Steps

1. Install from Go modules:
   ```bash
   go install github.com/specmon/go-annotate@latest
   ```

2. Or build from source:
   ```bash
   git clone https://github.com/specmon/go-annotate.git
   cd go-annotate
   go build -o go-annotate
   ```

---

## 🚀 Usage

### Basic Instrumentation

1. **Instrument your Go code:**
   ```bash
   go-annotate -import "github.com/specmon/go-annotate/log" -w main.go
   ```

2. **Configure logging:**
   ```bash
   export GO_ANNOTATE_LOG_TARGET="/path/to/output.log"  # File mode
   # OR
   export GO_ANNOTATE_LOG_TARGET="localhost:8080"       # Socket mode
   export GO_ANNOTATE_LOG_FORMAT="json"                 # json, cbor, text, debug
   ```

3. **Run your instrumented program:**
   ```bash
   go run main.go
   ```

### Configuration

- `GO_ANNOTATE_LOG_TARGET` - **Required**. Log destination (auto-detects mode):
  - File: `/path/to/logfile.log`
  - TCP Socket: `localhost:8080`
  - Unix Socket: `/tmp/socket.sock`
- `GO_ANNOTATE_LOG_FORMAT` - Log format: `json` (default), `cbor`, `text`, `debug`

### Command Line Options

```bash
go-annotate [options] <source-files>

Options:
  -import string     Import path for the log package (required)
  -w                 Write changes back to source files (default: print to stdout)
  -exported          Only instrument exported functions
  -package           Include package name prefix in function calls
  -returns           Show function return values
  -timing            Include timing information (implies -returns)
  -generate string   Generate monitoring rules file
```

---

## 📊 Examples

### Basic Function Tracing

```bash
# Instrument main.go with function entry/exit logging
go-annotate -import "github.com/specmon/go-annotate/log" -w main.go

# Run with file logging
export GO_ANNOTATE_LOG_TARGET="trace.log"
export GO_ANNOTATE_LOG_FORMAT="json"
go run main.go
```

### Real-time Network Streaming

```bash
# Terminal 1: Start log receiver
go run test/test_socket_server.go

# Terminal 2: Run instrumented program
export GO_ANNOTATE_LOG_TARGET="localhost:8080"
export GO_ANNOTATE_LOG_FORMAT="json"
go run main.go
```

### SpecMon Monitoring Rules

```bash
# Generate monitoring rules
go-annotate -import "github.com/specmon/go-annotate/log" \
        -generate "rules.thy" \
        -w main.go
```

### Output Formats

### JSON Format
```json
{
  "time": 1704067200000000000,
  "event": {
    "name": "pair",
    "type": "function",
    "args": [
      {"name": "main_Add_Enter", "type": "function", "args": [...]},
      {"name": "pair", "type": "function", "args": [...]}
    ]
  }
}
```

### Text Format
```
main_Add_Enter(1, 5, 10)
main_Add_Leave(1, 5, 10) = (15)
```

### CBOR Format
Binary format optimized for performance and network transmission.

---

## 📈 Performance

Recent optimizations deliver significant performance improvements:

- **~60% allocation reduction** through object pooling
- **Non-blocking channels** prevent application deadlocks
- **Optimized serialization** with buffer reuse
- **Smart buffering** handles network delays gracefully

---

## 🏗️ Architecture

### Core Components

- **AST Parser**: Safe Go source code transformation
- **Logger**: High-performance event collection with multiple outputs
- **Network Layer**: Robust socket handling with reconnection
- **Memory Management**: Pool-based allocation for hot paths

### Backward Compatibility

All legacy environment variables are supported with deprecation warnings:
- `GO_WRAP_LOG_FILE` → Use `GO_ANNOTATE_LOG_TARGET`
- `GO_WRAP_LOG_SOCKETS` → Auto-detected from target format

### Use Cases

- **Performance Profiling**: Trace function calls and timing
- **Security Analysis**: Generate traces to detect suspicious function invocations
- **Runtime Monitoring**: Generate execution traces for external validation
- **Debugging**: Detailed program flow analysis
- **Academic Research**: Generate traces for formal verification and analysis tools

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 📚 Citation

If you use go-annotate in academic research, please cite:

```bibtex
@software{go-annotate,
  title = {go-annotate: High-Performance Go Code Instrumentation},
  author = {Morio, Kevin},
  year = {2025},
  url = {https://github.com/specmon/go-annotate}
}
```

