# SnortSharp Dependencies and Installation

## Required Dependencies

### System Dependencies
- **GCC Compiler**: C compiler with C99/GNU99 support
- **Make**: Build system for compilation
- **pthread**: POSIX threads library (usually included with system)
- **Math Library**: Standard math library (`-lm`)

### External Libraries
- **libuv**: Cross-platform asynchronous I/O library for event system
  - Used for inter-process communication between flow analyzer and rule engine
  - Required for `proc1_test` and `proc2_test_events` programs

## Installation Instructions

### Ubuntu/Debian
```bash
sudo apt update
sudo apt install build-essential libuv1-dev
```

### CentOS/RHEL/Fedora
```bash
# CentOS/RHEL
sudo yum install gcc make libuv-devel
# or for newer versions:
sudo dnf install gcc make libuv-devel

# Fedora  
sudo dnf install gcc make libuv-devel
```

### macOS (via Homebrew)
```bash
brew install libuv
```

### Arch Linux
```bash
sudo pacman -S base-devel libuv
```

## Verification

Check if libuv is installed:
```bash
# Check for header files
ls /usr/include/uv.h
# or
pkg-config --exists libuv && echo "libuv found" || echo "libuv not found"

# Check for library
ldconfig -p | grep libuv
```

## Build Instructions

Once dependencies are installed:

```bash
# Clean previous builds
make clean

# Build all targets
make all

# Build specific event-based programs
make proc1_test proc2_test_events
```

## Testing Event System

### Terminal 1: Start Rule Engine (Event Server)
```bash
./proc2_test_events
```

### Terminal 2: Start Flow Analyzer (Event Broadcaster)
```bash
./proc1_test
```

The programs will communicate via libuv named pipes (`/tmp/snortsharp_events`).

## Program Descriptions

### Standard Programs (No libuv required)
- `flow_test` - Basic flow analyzer functionality test
- `interactive_test` - Interactive testing interface
- `demo_test` - Demonstration scenarios
- `validation_test` - Validation tests
- `verbose_test` - Internal state viewer
- `proc2_test` - Rule engine test (standalone)
- `integrated_test` - Full integration test

### Event-Based Programs (libuv required)
- `proc1_test` - Flow analyzer with event broadcasting
- `proc2_test_events` - Rule engine with event listening

## Troubleshooting

### libuv not found
```
/usr/bin/ld: cannot find -luv
```
**Solution**: Install libuv development package (see installation instructions above)

### Header not found
```
event_system.h:4:10: fatal error: uv.h: No such file or directory
```
**Solution**: Install libuv development headers

### Pipe creation errors
```
[EVENT] Bind error: permission denied
```
**Solution**: Ensure `/tmp` directory is writable, or change pipe path in code

### Connection failures
```
[PROC1] Failed to connect to event server
```
**Solution**: Start `proc2_test_events` (server) before `proc1_test` (client)

## Optional: System without libuv

If libuv is not available, you can still use the traditional queue-based programs:
- Use `integrated_test` instead of separate `proc1_test`/`proc2_test_events`
- All other test programs work without libuv
- Only the event system functionality requires libuv

## Development Notes

- Event system uses **named pipes** for IPC (Unix domain sockets)
- Programs are designed to work on Linux/Unix systems
- Thread-safe implementation with proper cleanup
- Memory leak prevention with proper resource management