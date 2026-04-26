/*
 * fuzz_cascade.m — CoreText cascade-fallback path fuzzer
 *
 * ═══════════════════════════════════════════════════════════════════════
 * TARGET: CoreText's cascade fallback — when an app renders text containing
 * a character that no system font claims to support, CoreText queries the
 * font registry for "any font that covers this codepoint". The fontd
 * server may invoke registered providers (XTCopyFontForCharacter:scope:
 * options:reply:) to fulfill the cascade. We have empirical proof that a
 * sandboxed app can register as a font provider via XTAddFontProvider:
 * (the unauth bug). The cascade path may have weaker sanitization than
 * the normal named-font path (which we proved DOES sanitize).
 *
 * STRATEGY:
 *   The fuzz input is treated as a font blob. We construct a CGFont from
 *   the bytes and use it for cascade-style rendering with rare Unicode
 *   characters (Private Use Area, ancient scripts, surrogate pairs,
 *   variation selectors). The cascade path inside CoreText is exercised
 *   without going through fontd's named-font sanitizer.
 *
 * Build:
 *   clang -framework Foundation -framework CoreText \
 *         -framework CoreGraphics -framework CoreFoundation \
 *         -fsanitize=fuzzer,address,undefined -g -O1 \
 *         -o fuzz_cascade fuzz_cascade.m
 * ═══════════════════════════════════════════════════════════════════════
 */

#import <Foundation/Foundation.h>
#import <CoreText/CoreText.h>
#import <CoreGraphics/CoreGraphics.h>
#include <stdint.h>
#include <string.h>

/* Rare Unicode codepoints that exercise the cascade path */
static const uint32_t g_rareCodepoints[] = {
    0xE000, 0xE001, 0xEFFF, 0xF000, 0xF8FF, /* Private Use Area */
    0x10000, 0x10001, 0x1F000, 0x1F600, 0x2FFFF, /* SMP / SIP */
    0x100000, 0x10FFFF, /* Supplementary Private Use Area-B */
    0x16800, 0x16A40, 0x16E40, /* Bamum, Mro, Medefaidrin */
    0xFE00, 0xFE0F, 0xE0100, 0xE01EF, /* Variation Selectors */
    0x1F1E6, 0x1F1FF, /* Regional Indicators (flag composition) */
    0x200D, 0x200C, /* ZWJ / ZWNJ */
    0x180E, 0x202F, /* Mongolian Vowel Separator, narrow no-break space */
};
static const int g_numCodepoints = sizeof(g_rareCodepoints) / sizeof(g_rareCodepoints[0]);

static void exerciseCascade(CTFontRef font, uint32_t codepoint) {
    if (!font) return;

    /* 1. CTFontGetGlyphsForCharacters — direct cascade lookup */
    UniChar chars[2];
    CGGlyph glyphs[2] = {0, 0};
    int len = 1;
    if (codepoint > 0xFFFF) {
        chars[0] = 0xD800 | ((codepoint - 0x10000) >> 10);
        chars[1] = 0xDC00 | ((codepoint - 0x10000) & 0x3ff);
        len = 2;
    } else {
        chars[0] = (UniChar)codepoint;
    }
    @try { CTFontGetGlyphsForCharacters(font, chars, glyphs, len); } @catch (NSException *e) {}

    /* 2. CTFontCreateForString cascade lookup */
    NSString *s = [[NSString alloc] initWithBytes:chars length:len * 2 encoding:NSUTF16LittleEndianStringEncoding] ?: @"";
    if (s.length > 0) {
        @try {
            CTFontRef c = CTFontCreateForString(font, (__bridge CFStringRef)s, CFRangeMake(0, s.length));
            if (c) CFRelease(c);
        } @catch (NSException *e) {}
    }

    /* 3. CTLineCreateWithAttributedString + CTLineDraw — full cascade rendering */
    @try {
        NSDictionary *attrs = @{ (NSString *)kCTFontAttributeName: (__bridge id)font };
        NSAttributedString *as = [[NSAttributedString alloc] initWithString:s attributes:attrs];
        if (as.length > 0 && as.length < 1024) {
            CTLineRef line = CTLineCreateWithAttributedString((CFAttributedStringRef)as);
            if (line) {
                CGContextRef ctx = CGBitmapContextCreate(NULL, 256, 64, 8, 256 * 4,
                    CGColorSpaceCreateDeviceRGB(), kCGImageAlphaPremultipliedLast);
                if (ctx) {
                    CTLineDraw(line, ctx);
                    CGContextRelease(ctx);
                }
                CFRelease(line);
            }
        }
    } @catch (NSException *e) {}

    /* 4. CTFontCopyCharacterSet — full charset enumeration on the cascade font */
    @try {
        CFCharacterSetRef cs = CTFontCopyCharacterSet(font);
        if (cs) {
            (void)CFCharacterSetIsLongCharacterMember(cs, codepoint);
            CFRelease(cs);
        }
    } @catch (NSException *e) {}

    /* 5. CTFontCopyTable for the COLR/CPAL pair (the exact path that broke
     * during our existing CPAL OOB submission — fuzz it again here for
     * coverage in case the fix lands in this path) */
    static const FourCharCode tags[] = {'C','O','L','R'};
    (void)tags;
    @try {
        CFDataRef d1 = CTFontCopyTable(font, ('C'<<24)|('O'<<16)|('L'<<8)|'R', 0);
        CFDataRef d2 = CTFontCopyTable(font, ('C'<<24)|('P'<<16)|('A'<<8)|'L', 0);
        if (d1) CFRelease(d1);
        if (d2) CFRelease(d2);
    } @catch (NSException *e) {}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 32 || size > 524288) return 0;
    @autoreleasepool {
        /* Build a CGFont from raw fuzz bytes (skip fontd's named-font sanitizer) */
        CFDataRef d = CFDataCreate(NULL, data, size);
        if (!d) return 0;
        CGDataProviderRef p = CGDataProviderCreateWithCFData(d);
        if (!p) { CFRelease(d); return 0; }
        CGFontRef cgFont = CGFontCreateWithDataProvider(p);
        CGDataProviderRelease(p);
        CFRelease(d);
        if (!cgFont) return 0;

        CTFontRef ctFont = CTFontCreateWithGraphicsFont(cgFont, 14, NULL, NULL);
        CGFontRelease(cgFont);
        if (!ctFont) return 0;

        /* Exercise the cascade path on multiple rare codepoints */
        uint32_t which = (uint32_t)data[0] % g_numCodepoints;
        exerciseCascade(ctFont, g_rareCodepoints[which]);

        CFRelease(ctFont);
    }
    return 0;
}
