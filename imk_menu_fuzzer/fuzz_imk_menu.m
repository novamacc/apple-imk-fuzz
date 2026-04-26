/*
 * fuzz_imk_menu.m — IMK menusDictionaryWithReply: consumer-side fuzzer
 *
 * TARGET: AppKit's parsing/rendering of NSDictionary payloads that a
 * sandboxed attacker can return over NSXPC from a hijacked IMK endpoint.
 *
 * The IMK launchagent (com.apple.inputmethodkit.setxpcendpoint) accepts
 * unauthenticated registration. With that primitive proven, 12 first-party
 * processes (TextEdit, Notes, Safari, Firefox, loginwindow, System Settings,
 * Spotlight, etc.) call menusDictionaryWithReply: on attacker-controlled
 * endpoints. This fuzzer hunts memory-corruption bugs in the consumer-side
 * NSDictionary -> NSMenu / NSAttributedString rendering pipeline.
 *
 * Approach: turn the fuzz bytes into an NSDictionary (via plist or a
 * structured fallback), then exercise the consumer code paths a real
 * AppKit text-input client would run when handed a menus dict.
 */

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <CoreText/CoreText.h>
#include <stdint.h>
#include <string.h>

/* Build an NSDictionary from raw fuzz bytes. Try plist first, then a
 * structured fallback that always produces a usable dict. */
static NSDictionary *buildDict(const uint8_t *data, size_t size) {
    NSData *blob = [NSData dataWithBytes:data length:size];

    @try {
        id obj = [NSPropertyListSerialization propertyListWithData:blob
                                                           options:NSPropertyListImmutable
                                                            format:NULL
                                                             error:nil];
        if ([obj isKindOfClass:NSDictionary.class]) return obj;
    } @catch (NSException *e) {}

    /* Structured fallback — split into key/value pairs */
    NSMutableDictionary *d = [NSMutableDictionary dictionary];
    size_t i = 0;
    int item = 0;
    while (i + 4 < size && item < 32) {
        uint8_t klen = (data[i++] & 0x1f) + 1;
        if (klen > size - i) break;
        NSString *k = [[NSString alloc] initWithBytes:data + i length:klen encoding:NSUTF8StringEncoding];
        if (!k) k = [NSString stringWithFormat:@"k%d", item];
        i += klen;
        if (i + 1 >= size) break;
        uint8_t vtype = data[i++];
        if (i + 2 >= size) break;
        uint16_t vlen = (((uint16_t)data[i] << 8) | data[i+1]) & 0x07ff;
        i += 2;
        if (vlen > size - i) break;
        NSData *vd = (vlen > 0) ? [NSData dataWithBytes:data + i length:vlen] : [NSData data];
        i += vlen;
        id v = nil;
        switch (vtype & 0x07) {
            case 0:
                v = [[NSString alloc] initWithData:vd encoding:NSUTF8StringEncoding] ?: @"";
                break;
            case 1:
                v = vd;
                break;
            case 2: {
                uint64_t n = 0;
                if (vd.length >= sizeof(n)) memcpy(&n, vd.bytes, sizeof(n));
                else if (vd.length > 0) memcpy(&n, vd.bytes, vd.length);
                v = [NSNumber numberWithLongLong:(long long)n];
                break;
            }
            case 3: {
                NSString *s = [[NSString alloc] initWithData:vd encoding:NSUTF8StringEncoding] ?: @"";
                if (s.length > 0 && s.length < 512) {
                    NSDictionary *attrs = @{ NSFontAttributeName: [NSFont systemFontOfSize:14] };
                    v = [[NSAttributedString alloc] initWithString:s attributes:attrs];
                } else {
                    v = s;
                }
                break;
            }
            case 4: {
                NSString *s = [[NSString alloc] initWithData:vd encoding:NSUTF8StringEncoding] ?: @"";
                if (s.length > 0 && s.length < 512) {
                    /* Use kCTFontAttributeName explicitly (the CPAL trigger pattern) */
                    NSDictionary *attrs = @{ (NSString *)kCTFontAttributeName: (__bridge id)CTFontCreateWithName(CFSTR("Helvetica"), 14, NULL) };
                    v = [[NSAttributedString alloc] initWithString:s attributes:attrs];
                } else {
                    v = s;
                }
                break;
            }
            default:
                v = vd;
                break;
        }
        if (k && v) d[k] = v;
        item++;
    }
    return d;
}

/* Exercise the dict the way a real consumer would. No NSKeyedArchiver
 * round-trip — just direct AppKit menu/attrstr operations. */
static void exerciseAsConsumer(NSDictionary *dict) {
    if (!dict || dict.count == 0) return;

    /* 1. Inspect "InputModes" / menu-like keys the way IMKit consumers do */
    @try {
        id inputModes = dict[@"InputModes"] ?: dict[@"Menus"];
        if ([inputModes isKindOfClass:NSArray.class]) {
            for (id item in (NSArray *)inputModes) {
                if ([item isKindOfClass:NSString.class]) (void)[(NSString *)item length];
                if ([item isKindOfClass:NSAttributedString.class]) {
                    NSAttributedString *as = (NSAttributedString *)item;
                    if (as.length < 1024) (void)[as size];
                }
                if ([item isKindOfClass:NSDictionary.class]) {
                    for (id k in (NSDictionary *)item) (void)[[k description] length];
                }
            }
        }
    } @catch (NSException *e) {}

    /* 2. Build NSMenu items from the dict — direct AppKit consumer path */
    @try {
        NSMenu *menu = [[NSMenu alloc] initWithTitle:@"FuzzMenu"];
        for (id key in dict) {
            id val = dict[key];
            NSString *title = @"item";
            if ([key isKindOfClass:NSString.class]) {
                NSString *k = (NSString *)key;
                if (k.length > 0 && k.length < 64) title = k;
            }
            NSMenuItem *item = [menu addItemWithTitle:title action:NULL keyEquivalent:@""];
            if ([val isKindOfClass:NSAttributedString.class]) {
                NSAttributedString *as = (NSAttributedString *)val;
                if (as.length < 1024) item.attributedTitle = as;
            }
            (void)item;
        }
        (void)menu.numberOfItems;
    } @catch (NSException *e) {}

    /* 3. Try drawing any NSAttributedString values (consumer text-rendering) */
    @try {
        NSImage *canvas = [[NSImage alloc] initWithSize:NSMakeSize(64, 32)];
        for (id key in dict) {
            id val = dict[key];
            if ([val isKindOfClass:NSAttributedString.class]) {
                NSAttributedString *as = (NSAttributedString *)val;
                if (as.length > 0 && as.length < 256) {
                    [canvas lockFocus];
                    [as drawAtPoint:NSMakePoint(0, 0)];
                    [canvas unlockFocus];
                }
            }
        }
    } @catch (NSException *e) {}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4 || size > 131072) return 0;
    @autoreleasepool {
        NSDictionary *dict = buildDict(data, size);
        if (dict) exerciseAsConsumer(dict);
    }
    return 0;
}
