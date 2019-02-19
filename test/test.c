#undef NDEBUG

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"
#include "json_helpers.h"
#include "json_out.h"

static char tmp1[4096];
static char tmp2[4096];

static void json_msg_cb(void *opaque, size_t loc, const char *msg)
{
    printf("json parser (at %d): %s\n", (int)loc, msg);
}

static struct json_tok *parse(const char *text)
{
    size_t len = strlen(text) + 1;
    if (len > sizeof(tmp1))
        abort();
    memcpy(tmp1, text, len);

    struct json_msg_cb cb = {
        .cb = json_msg_cb,
    };

    return json_parse_destructive(tmp1, tmp2, sizeof(tmp2), 100, &cb);
}

static void parsegen_test(const char *text, const char *expect)
{
    char tmp[4096];

    printf("parsing: %s\n", text);
    struct json_tok *tok = parse(text);

    struct json_out dump;
    json_out_init(&dump, tmp, sizeof(tmp));
    json_out_write(&dump, tok);
    char *out = json_out_get_output(&dump);
    printf(" =>      %s\n", out ? out : "<error?>");

    if (!strcmp(expect, out) == 0) {
        printf("Expected: '%s'\nGot: '%s'\n", expect, out);
        printf("Test failed!\n");
        abort();
    }
}

static void example(void)
{
    // Working memory for the parser. Must be large enough for any expected
    // input. t (below) will point somewhere into this.
    char tmp[1024];
    // JSON text to parse.
    static const char input[] = "{\"key1\": 123, \"key2\": [12, 34, 56]}";

    struct json_tok *t = json_parse(input, tmp, sizeof(tmp), 100, NULL);

    assert(json_get_int(t, "key1", -1) == 123);

    int sum = 0;
    struct json_list *arr = json_get_array(t, "key2");
    for (struct json_list_item *c = arr ? arr->head : NULL; c; c = c->next) {
        int v = json_get_int(&c->value, NULL, -1);
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
    parsegen_test("\"he\\u003a\t\\t\\u001cll\\\\o \\\"there\"",
                  "\"he:\\t\\t\\u001cll\\\\o \\\"there\"");
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
