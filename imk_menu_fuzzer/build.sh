#!/bin/bash
# build.sh - Build IMK menu fuzzer
set -e
cd "$(dirname "$0")"

COMMON="-framework Foundation -framework AppKit -framework CoreText -framework CoreGraphics -framework CoreFoundation"

echo "=== IMK menusDictionaryWithReply Fuzzer ==="
echo ""

echo "[1/2] Creating seed corpus..."
mkdir -p corpus crashes

# Seed 1: minimal valid IMK menus payload (matches what KIM_Extension returns)
python3 - <<'PYEOF'
import plistlib
seed = {
    "InputModes": ["com.apple.inputmethod.Korean.2SetKorean"],
    "InputModesMenuTitle": "Korean",
}
with open("corpus/seed_minimal.plist", "wb") as f:
    plistlib.dump(seed, f, fmt=plistlib.FMT_BINARY)

# Seed 2: rich payload with multiple modes
seed2 = {
    "InputModes": [
        "com.apple.inputmethod.Korean.2SetKorean",
        "com.apple.inputmethod.Korean.HNCRomaja",
    ],
    "InputModesMenuTitle": "Korean",
    "MenuItems": [
        {"name": "2-Set", "shortcut": ""},
        {"name": "HNC Romaja", "shortcut": ""},
    ],
    "ModeProperties": {
        "com.apple.inputmethod.Korean.2SetKorean": {
            "TSInputModeAlternateMenuTitleName": "한",
            "TSInputModeIsVisibleKey": True,
            "TSInputModePrimaryInScriptKey": True,
            "TSInputModeScriptKey": "smKorean",
        }
    }
}
with open("corpus/seed_rich.plist", "wb") as f:
    plistlib.dump(seed2, f, fmt=plistlib.FMT_BINARY)

# Seed 3: deeply-nested but legal (under NSXPCConnection's recursion limit ~128)
nested = "leaf"
for _ in range(64):
    nested = {"x": nested, "n": nested}
seed3 = {"InputModes": [nested]}
with open("corpus/seed_nested.plist", "wb") as f:
    plistlib.dump(seed3, f, fmt=plistlib.FMT_BINARY)
PYEOF

# Add some structured-fallback seeds (the harness builds dicts from raw bytes)
for i in $(seq 0 8); do
    dd if=/dev/urandom bs=128 count=1 2>/dev/null > "corpus/random_${i}.bin"
done
echo "      Done. $(ls corpus/ | wc -l | tr -d ' ') seeds"

echo "[2/2] Building fuzzer..."
if echo 'int LLVMFuzzerTestOneInput(const char *d, long s){return 0;}' | clang -fsanitize=fuzzer -x c - -o /dev/null 2>/dev/null; then
    echo "      libFuzzer available - building with -fsanitize=fuzzer"
    clang $COMMON \
        -fsanitize=fuzzer,address,undefined \
        -fno-sanitize-recover=undefined \
        -g -O1 \
        -o fuzz_imk_menu fuzz_imk_menu.m 2>&1
else
    echo "      libFuzzer NOT available - building with standalone harness"
    clang $COMMON \
        -fsanitize=address,undefined \
        -fno-sanitize-recover=undefined \
        -g -O1 \
        -c -o fuzz_imk_menu.o fuzz_imk_menu.m
    clang -fsanitize=address,undefined -g -O1 \
        -c -o standalone_harness.o ../standalone_harness.c
    clang $COMMON \
        -fsanitize=address,undefined \
        -g -O1 \
        -o fuzz_imk_menu fuzz_imk_menu.o standalone_harness.o
    rm -f fuzz_imk_menu.o standalone_harness.o
fi
echo "      Done."

echo ""
echo "=== BUILD COMPLETE ==="
echo "Run: ./fuzz_imk_menu corpus/ -max_len=131072 -timeout=10 -artifact_prefix=crashes/"
