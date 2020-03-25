#undef NDEBUG

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "json.h"
#include "json_helpers.h"
#include "json_out.h"

static unsigned char tmp1[4096];
static unsigned char tmp2[4096];

static void json_msg_cb(void *opaque, size_t loc, const char *msg)
{
    printf("json parser (at %d): %s\n", (int)loc, msg);
}

static bool run_test(const char *text, const char *expect,
                     int max_mem, int max_depth, bool test_limits,
                     int cutoff_input)
{
    memset(tmp2, 0xDF, sizeof(tmp2));
    if (max_mem > sizeof(tmp2))
        max_mem = sizeof(tmp2);

    if (!test_limits)
        printf("parsing: %s\n", text);

    size_t len = strlen(text);
    if (len + 1 > sizeof(tmp1))
        abort();
    memcpy(tmp1, text, len + 1);

    if (cutoff_input > len)
        cutoff_input = len;
    tmp1[cutoff_input] = '\0';

    struct json_parse_opts opts = {
        .depth = max_depth,
        .msg_cb = test_limits ? NULL : json_msg_cb,
    };

    struct json_tok *tok =
        json_parse_destructive(tmp1, tmp2, max_mem, &opts);

    for (int n = max_mem; n < sizeof(tmp2); n++)
        assert(tmp2[n] == 0xDF);

    unsigned char tmp[4096];
    struct json_out dump;
    json_out_init(&dump, tmp, sizeof(tmp));
    json_out_write(&dump, tok);
    char *out = json_out_get_output(&dump);
    if (!test_limits)
        printf(" =>      %s\n", out ? out : "<error?>");

    bool limits_exceeded = opts.error == JSON_ERR_NOMEM ||
                           opts.error == JSON_ERR_DEPTH;

    if (test_limits && !tok && limits_exceeded)
        return false;

    if (test_limits && cutoff_input < len)
        return !tok;

    if (strcmp(expect, out)) {
        if (test_limits)
            printf("Inconsistent test_limits result (%d):\n", opts.error);
        printf("Expected: '%s'\nGot: '%s'\n", expect, out);
        printf("Test failed!\n");
        abort();
    }

    return true;
}

static void parsegen_test(const char *text, const char *expect)
{
    int mem = 4096;
    int depth = 100;
    int input = strlen(text);

    run_test(text, expect, mem, depth, false, input);

    // Test max. stack depth that works.
    bool depth_ok = true;
    for (int n = depth; n >= 1; n--) {
        bool ok = run_test(text, expect, mem, n, true, input);
        if (ok != depth_ok) {
            if (depth_ok) {
                printf(" ... max depth: %d\n", n);
            } else {
                // Lower depth worked again => makes no sense.
                printf("oh no (depth)\n");
                abort();
            }
            depth_ok = ok;
        }
    }

    // Test max. memory size that works.
    bool mem_ok = true;
    for (int n = mem; n >= 0; n--) {
        bool ok = run_test(text, expect, n, depth, true, input);
        if (ok != mem_ok) {
            if (mem_ok) {
                printf(" ... max mem: %d\n", n);
            } else {
                // Lower memory worked again => makes no sense.
                printf("oh no (mem)\n");
                abort();
            }
            mem_ok = ok;
        }
    }

    // Test cut off input. Only in certain cases.
    if (text[0] == '[' || text[0] == '{' || text[0] == '"') {
        for (int n = input - 2; n >= 0; n--) {
            bool ok = run_test(text, expect, mem, depth, true, n);
            if (!ok) {
                printf("oh no (cut off at %d)\n", n);
                abort();
            }
        }
    }
}

static void example(void)
{
    // Working memory for the parser. Must be large enough for any expected
    // input. t (below) will point somewhere into this.
    char tmp[1024];
    // JSON text to parse.
    static const char input[] = "{\"key1\": 123, \"key2\": [12, 34, 56]}";

    struct json_tok *t = json_parse(input, tmp, sizeof(tmp), NULL);

    assert(json_get_int(t, "key1", -1) == 123);

    int sum = 0;
    struct json_array *arr = json_get_array(t, "key2");
    for (size_t n = 0; n < arr->count; n++) {
        int v = json_get_int(&arr->items[n], NULL, -1);
        printf(" array value: %d\n", v);
        sum += v;
    }

    assert(sum == 12 + 34 + 56);
}

int main(void)
{
    example();
    parsegen_test("  { }  ", "{}");
    parsegen_test("  true ", "true");
    parsegen_test("  false ", "false");
    parsegen_test("  null ", "null");
    parsegen_test(" 123 ", "123");
    parsegen_test("{\"field1\": \"test\", \"field2\" : 2}",
                  "{\"field1\":\"test\",\"field2\":2}");
    parsegen_test(" [ 3, 4, true, false ,null ] ", "[3,4,true,false,null]");
    parsegen_test("\"he\\u003a\\t\\u001cll\\\\o \\\"there\"",
                  "\"he:\\t\\u001cll\\\\o \\\"there\"");
    parsegen_test("{\"field1\": [1, 2, 3, {\"f\": [4, 5, 6]}, "
                  " {\"g\": [7, 8, 9, 10 ] }, 11], \"field2\" : 2}",
                  "{\"field1\":[1,2,3,{\"f\":[4,5,6]},"
                  "{\"g\":[7,8,9,10]},11],\"field2\":2}");
    // Unicode escapes (for UTF-16 surrogate parser and UTF-8 encoder).
    parsegen_test("\"\\uD801\\uDC37\"", "\"𐐷\"");
    parsegen_test("\"\\uD834\\uDD1E\"", "\"𝄞\"");
    parsegen_test("\"\\u007F\"", "\"\x7F\"");
    parsegen_test("\"\\u0080\"", "\"\xC2\x80\"");
    parsegen_test("\"\\u07F5\"", "\"\xDF\xB5\"");
    parsegen_test("\"\\u0800\"", "\"\xE0\xA0\x80\"");
    parsegen_test("\"\\u0800\"", "\"\xE0\xA0\x80\"");
    parsegen_test("\"\\u6131\"", "\"\xE6\x84\xB1\"");
    parsegen_test("\"\\uF433\"", "\"\xEF\x90\xB3\"");
    parsegen_test("\"\\uD800\\uDC00\"", "\"\xF0\x90\x80\x80\"");
    parsegen_test("\"\\uD803\\uDE6D\"", "\"\xF0\x90\xB9\xAD\"");
    parsegen_test("\"\\uDBFF\\uDFFF\"", "\"\xF4\x8F\xBF\xBF\"");
    // Must fail.
    parsegen_test("  truek", "<error>");
    parsegen_test("  tru", "<error>");
    parsegen_test("  tr", "<error>");
    parsegen_test("  t", "<error>");
    parsegen_test("  ", "<error>");
    parsegen_test("", "<error>");
    parsegen_test("{", "<error>");
    parsegen_test("\"\\uDBFFa", "<error>");
    parsegen_test("\"\\uDBFF\\uAFFF\"", "<error>");
    // Should fail. There are various extensions to JSON which allow them (and
    // we could support them), but they are not part of standard JSON.
    parsegen_test("{field: hello}", "<error>");
    parsegen_test("[1,2,3,]", "<error>");

    printf("OK\n");
    return 0;
}
