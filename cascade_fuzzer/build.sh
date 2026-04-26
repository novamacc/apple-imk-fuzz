#!/bin/bash
set -e
cd "$(dirname "$0")"

COMMON="-framework Foundation -framework CoreText -framework CoreGraphics -framework CoreFoundation"

echo "=== CoreText Cascade-Fallback Fuzzer ==="
echo ""

echo "[1/2] Creating seed corpus..."
mkdir -p corpus crashes

# Seed: minimal valid TrueType (use the system font as starting point)
SYSFONT=/System/Library/Fonts/SFNS.ttf
[ -f "$SYSFONT" ] || SYSFONT=/System/Library/Fonts/Helvetica.ttc
[ -f "$SYSFONT" ] || SYSFONT=/System/Library/Fonts/SFCompact.ttf
if [ -f "$SYSFONT" ]; then
    cp "$SYSFONT" corpus/seed_sysfont.bin
    echo "      seeded with $SYSFONT"
fi

# Random seeds for breadth
for i in $(seq 0 12); do
    dd if=/dev/urandom bs=512 count=1 2>/dev/null > "corpus/random_${i}.bin"
done
echo "      Done. $(ls corpus/ | wc -l | tr -d ' ') seeds"

echo "[2/2] Building fuzzer..."
if echo 'int LLVMFuzzerTestOneInput(const char *d, long s){return 0;}' | clang -fsanitize=fuzzer -x c - -o /dev/null 2>/dev/null; then
    echo "      libFuzzer available"
    clang $COMMON \
        -fsanitize=fuzzer,address,undefined \
        -fno-sanitize-recover=undefined \
        -g -O1 \
        -o fuzz_cascade fuzz_cascade.m
else
    echo "      libFuzzer NOT available"
    clang $COMMON \
        -fsanitize=address,undefined \
        -fno-sanitize-recover=undefined \
        -g -O1 \
        -c -o fuzz_cascade.o fuzz_cascade.m
    clang -fsanitize=address,undefined -g -O1 \
        -c -o standalone_harness.o ../standalone_harness.c
    clang $COMMON \
        -fsanitize=address,undefined \
        -g -O1 \
        -o fuzz_cascade fuzz_cascade.o standalone_harness.o
    rm -f fuzz_cascade.o standalone_harness.o
fi
echo "      Done."

echo ""
echo "=== BUILD COMPLETE ==="
echo "Run: ./fuzz_cascade corpus/ -max_len=524288 -timeout=10 -artifact_prefix=crashes/"
