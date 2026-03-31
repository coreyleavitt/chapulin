#!/bin/bash
# Fuzz testing runner for chapulin
# Requires: clang with libFuzzer support
#
# Usage:
#   ./fuzz/run.sh build          # compile all targets
#   ./fuzz/run.sh decode         # fuzz decode()
#   ./fuzz/run.sh validate_path  # fuzz validatePath()
#   ./fuzz/run.sh parse_uri      # fuzz parseTftpUri()
#   ./fuzz/run.sh parse_options  # fuzz parseOackOptions()
#   ./fuzz/run.sh roundtrip      # fuzz encode/decode roundtrip
#   ./fuzz/run.sh all            # fuzz all targets (1 hour each)

set -e

FUZZ_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$FUZZ_DIR")"

NIM_FLAGS="--mm:arc -d:useMalloc -d:danger -d:nosignalhandler --nomain:on --cc:clang"
SANITIZERS="-fsanitize=fuzzer,address,undefined"
COMPILE="nim c $NIM_FLAGS -t:\"$SANITIZERS\" -l:\"$SANITIZERS\" -g"

TARGETS=(decode validate_path parse_uri parse_options roundtrip)

build_target() {
    local target=$1
    echo "Building fuzz_${target}..."
    cd "$PROJECT_DIR"
    eval $COMPILE -o:"fuzz/fuzz_${target}" "fuzz/fuzz_${target}.nim"
    echo "  Built: fuzz/fuzz_${target}"
}

run_target() {
    local target=$1
    local duration=${2:-3600}  # default 1 hour
    echo ""
    echo "=== Fuzzing: $target (${duration}s) ==="
    echo "  Corpus: fuzz/corpus/${target}/"
    echo "  Crashes will be written to current directory as crash-*"
    echo ""
    cd "$PROJECT_DIR"
    mkdir -p "fuzz/corpus/${target}"
    "./fuzz/fuzz_${target}" \
        "fuzz/corpus/${target}/" \
        -max_len=1024 \
        -timeout=5 \
        -max_total_time="$duration" \
        -print_final_stats=1
}

case "${1:-help}" in
    build)
        for t in "${TARGETS[@]}"; do
            build_target "$t"
        done
        echo ""
        echo "All targets built."
        ;;
    all)
        for t in "${TARGETS[@]}"; do
            build_target "$t"
        done
        for t in "${TARGETS[@]}"; do
            run_target "$t" 3600
        done
        ;;
    decode|validate_path|parse_uri|parse_options|roundtrip)
        build_target "$1"
        run_target "$1" "${2:-3600}"
        ;;
    help|*)
        echo "Usage: $0 {build|decode|validate_path|parse_uri|parse_options|roundtrip|all} [duration_seconds]"
        echo ""
        echo "Examples:"
        echo "  $0 build              # compile all targets"
        echo "  $0 decode             # fuzz decode() for 1 hour"
        echo "  $0 decode 300         # fuzz decode() for 5 minutes"
        echo "  $0 all                # fuzz everything, 1 hour each"
        ;;
esac
