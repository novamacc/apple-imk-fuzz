# apple-imk-fuzz

Continuous fuzzing of Apple Input Method Kit (IMK) and CoreText cascade-fallback paths on macOS using libFuzzer with AddressSanitizer + UndefinedBehaviorSanitizer.

Born from the IMK launchagent unauthenticated XPC registration finding (sandbox-reachable, hijacks 12+ first-party process IM-discovery channels). The fleet's other repos found nothing in 174 cycles for fonts, NSKeyedUnarchiver, ImageIO, etc. — this repo focuses on the *consumer-side* deserialization of attacker-controlled NSDictionary payloads returned from `menusDictionaryWithReply:` and the CoreText cascade-fallback path that hands provider-returned data to client apps.

## Fuzzers

| Fuzzer | Target | Surface | Why |
|---|---|---|---|
| `imk_menu_fuzzer` | NSXPCDecoder + NSDictionary→NSMenu construction in AppKit | The exact deserialization path that 12 first-party processes (TextEdit, Notes, Safari, Firefox, loginwindow, System Settings, etc) take when calling `menusDictionaryWithReply:` on an attacker-controlled IMK endpoint | We hijack the endpoint already; this fuzzer hunts memory-corruption bugs in the consumer-side parsing |
| `cascade_fuzzer` | CoreText cascade fallback character-coverage queries via `XTCopyFontForCharacter:scope:options:reply:` returning attacker-controlled font bytes | The system-font cascade pathway that fontd may bypass sanitization on for "emergency" character coverage | Architecturally promising (fontd sanitizes the named-font path, but cascade may have a different path) |

## CI

Runs on `macos-15` every 4 hours via GitHub Actions, ~5 hours per cycle, 3 parallel workers per fuzzer. Crash artifacts uploaded automatically.

## Local Build

```bash
cd imk_menu_fuzzer && ./build.sh
./fuzz_imk_menu corpus/ -max_len=131072 -timeout=10 -jobs=4 -workers=4
```
