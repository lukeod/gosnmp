#!/bin/bash
set -e

COUNT=${1:-6}
RESULTS_DIR="/tmp/bench_results"
mkdir -p "$RESULTS_DIR"

# Create the logger-enabled benchmark if it doesn't exist
cat > /tmp/bench_logger_test.go << 'EOF'
//go:build all || marshal

package gosnmp

import (
	"io"
	"log"
	"net"
	"testing"
	"time"
)

func BenchmarkSendOneRequestLoggerEnabled(b *testing.B) {
	b.StopTimer()
	srvr, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		b.Fatalf("udp4 error listening: %s", err)
	}
	defer srvr.Close()

	x := &GoSNMP{
		Version: Version2c,
		Target:  srvr.LocalAddr().(*net.UDPAddr).IP.String(),
		Port:    uint16(srvr.LocalAddr().(*net.UDPAddr).Port),
		Timeout: time.Millisecond * 100,
		Retries: 2,
	}
	x.Logger = NewLogger(log.New(io.Discard, "", 0))
	if err := x.Connect(); err != nil {
		b.Fatalf("error connecting: %s", err)
	}

	go func() {
		buf := make([]byte, 256)
		outBuf := counter64Response()
		for {
			_, addr, err := srvr.ReadFrom(buf)
			if err != nil {
				return
			}
			copy(outBuf[17:21], buf[11:15])
			srvr.WriteTo(outBuf, addr)
		}
	}()

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		x.Get([]string{"1.3.6.1.2.1.1.9.1.4.1"})
	}
}
EOF

run_benchmarks() {
    local name=$1
    echo "=== Running benchmarks for: $name ==="

    # Copy logger test file
    cp /tmp/bench_logger_test.go ./bench_logger_test.go

    # Runtime disabled (no logger set)
    echo "  -> Runtime disabled..."
    go test -tags=marshal -bench=BenchmarkSendOneRequest -benchmem -count="$COUNT" -run='^$' 2>/dev/null | \
        grep -E "^Benchmark|^goos|^goarch|^pkg|^cpu" > "$RESULTS_DIR/${name}_runtime.txt"

    # Build-time disabled (nodebug tag)
    echo "  -> Build-time disabled..."
    go test -tags=marshal,gosnmp_nodebug -bench=BenchmarkSendOneRequest -benchmem -count="$COUNT" -run='^$' 2>/dev/null | \
        grep -E "^Benchmark|^goos|^goarch|^pkg|^cpu" > "$RESULTS_DIR/${name}_buildtime.txt"

    # Logger enabled
    echo "  -> Logger enabled..."
    go test -tags=marshal -bench=BenchmarkSendOneRequestLoggerEnabled -benchmem -count="$COUNT" -run='^$' 2>/dev/null | \
        grep -E "^Benchmark|^goos|^goarch|^pkg|^cpu" > "$RESULTS_DIR/${name}_enabled.txt"

    # Cleanup
    rm -f ./bench_logger_test.go
}

echo "Benchmark comparison script"
echo "Count: $COUNT iterations per benchmark"
echo ""

# Save current branch
CURRENT_BRANCH=$(git branch --show-current || echo "detached")

# Run on master
echo "Switching to master..."
git checkout master --quiet 2>/dev/null || git checkout upstream/master --quiet 2>/dev/null
run_benchmarks "master"

# Run on targeted branch
echo ""
echo "Switching to logger-enabled-guard..."
git checkout logger-enabled-guard --quiet
run_benchmarks "targeted"

# Run on aggressive branch
echo ""
echo "Switching to logger-enabled-guard-aggressive..."
git checkout logger-enabled-guard-aggressive --quiet
run_benchmarks "aggressive"

echo ""
echo "=========================================="
echo "RESULTS"
echo "=========================================="

echo ""
echo "=== Runtime Disabled: Master vs Targeted vs Aggressive ==="
echo "--- Master vs Targeted ---"
benchstat "$RESULTS_DIR/master_runtime.txt" "$RESULTS_DIR/targeted_runtime.txt" 2>/dev/null | tail -n +2
echo ""
echo "--- Master vs Aggressive ---"
benchstat "$RESULTS_DIR/master_runtime.txt" "$RESULTS_DIR/aggressive_runtime.txt" 2>/dev/null | tail -n +2
echo ""
echo "--- Targeted vs Aggressive ---"
benchstat "$RESULTS_DIR/targeted_runtime.txt" "$RESULTS_DIR/aggressive_runtime.txt" 2>/dev/null | tail -n +2

echo ""
echo "=== Build-time Disabled: Master vs Targeted vs Aggressive ==="
echo "--- Master vs Targeted ---"
benchstat "$RESULTS_DIR/master_buildtime.txt" "$RESULTS_DIR/targeted_buildtime.txt" 2>/dev/null | tail -n +2
echo ""
echo "--- Master vs Aggressive ---"
benchstat "$RESULTS_DIR/master_buildtime.txt" "$RESULTS_DIR/aggressive_buildtime.txt" 2>/dev/null | tail -n +2
echo ""
echo "--- Targeted vs Aggressive ---"
benchstat "$RESULTS_DIR/targeted_buildtime.txt" "$RESULTS_DIR/aggressive_buildtime.txt" 2>/dev/null | tail -n +2

echo ""
echo "=== Logger Enabled: Master vs Targeted vs Aggressive ==="
echo "--- Master vs Targeted ---"
benchstat "$RESULTS_DIR/master_enabled.txt" "$RESULTS_DIR/targeted_enabled.txt" 2>/dev/null | tail -n +2
echo ""
echo "--- Master vs Aggressive ---"
benchstat "$RESULTS_DIR/master_enabled.txt" "$RESULTS_DIR/aggressive_enabled.txt" 2>/dev/null | tail -n +2

echo ""
echo "=== Gap Analysis: Runtime vs Build-time ==="
echo "--- Master gap ---"
benchstat "$RESULTS_DIR/master_runtime.txt" "$RESULTS_DIR/master_buildtime.txt" 2>/dev/null | tail -n +2
echo ""
echo "--- Targeted gap ---"
benchstat "$RESULTS_DIR/targeted_runtime.txt" "$RESULTS_DIR/targeted_buildtime.txt" 2>/dev/null | tail -n +2
echo ""
echo "--- Aggressive gap ---"
benchstat "$RESULTS_DIR/aggressive_runtime.txt" "$RESULTS_DIR/aggressive_buildtime.txt" 2>/dev/null | tail -n +2

echo ""
echo "Raw results saved to: $RESULTS_DIR/"

# Return to original branch
echo ""
echo "Returning to $CURRENT_BRANCH..."
git checkout "$CURRENT_BRANCH" --quiet 2>/dev/null || true
