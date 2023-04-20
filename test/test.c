#undef NDEBUG

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "json.h"
#include "json_helpers.h"
#include "json_helpers_malloc.h"
#include "json_out.h"

static void json_msg_cb(void *opaque, size_t loc, const char *msg)
{
    printf("json parser (at %d): %s\n", (int)loc, msg);
}

static bool oom_enable;
static size_t oom_left;
static bool oom_hit;
static bool enable_extensions;

static void *mrealloc(void *opaque, void *p, size_t sz)
{
    if (!sz) {
        free(p);
        return NULL;
    }
    if (oom_enable) {
        if (oom_hit) {
            // Not truly a bug, but unexpected.
            printf("repeated mrealloc after oom\n");
            abort();
        }
        if (sz > oom_left) {
            oom_hit = true;
            return NULL;
        }
        oom_left -= sz;
    }
    return realloc(p, sz);
}

#define BUF_SZ 4096

static bool run_test_(const char *text, const char *expect,
                      int max_mem, int max_depth, bool test_limits,
                      bool error_on_limits, int cutoff_input, bool use_mrealloc,
                      bool use_mrealloc_for_real)
{
    char tmp1_static[BUF_SZ];
    char tmp2_static[BUF_SZ];
    char *tmp1 = tmp1_static;
    char *tmp2 = tmp2_static;

    // Using mrealloc => ensure returned json_tok tree does not point to it by
    // freeing it and letting address sanitizer do the checks.
    if (use_mrealloc) {
        tmp1 = malloc(BUF_SZ);
        tmp2 = malloc(BUF_SZ);
        assert(tmp1 && tmp2);
    }

    memset(tmp2, 0xDF, BUF_SZ);
    if (max_mem > BUF_SZ)
        max_mem = BUF_SZ;

    if (!test_limits)
        printf("parsing: %s\n", text);

    size_t len = strlen(text);
    if (len + 1 > BUF_SZ)
        abort();
    memcpy(tmp1, text, len + 1);

    if (cutoff_input > len)
        cutoff_input = len;
    tmp1[cutoff_input] = '\0';

    struct json_parse_opts opts = {
        .depth = max_depth,
        .msg_cb = test_limits ? NULL : json_msg_cb,
        .mrealloc = use_mrealloc ? mrealloc : NULL,
        .enable_extensions = enable_extensions,
    };

    struct json_tok *tok = NULL;

    if (use_mrealloc_for_real) {
        // The test runner has two mrealloc paths, because json_parse_malloc()
        // is too opaque and does not let you test some of the limits.
        tok = json_parse_malloc(text, &opts);
    } else {
        tok = json_parse_destructive(tmp1, tmp2, max_mem, &opts);
    }

    for (int n = max_mem; n < BUF_SZ; n++)
        assert(tmp2[n] == (char)0xDF);

    if (use_mrealloc) {
        free(tmp1);
        free(tmp2);
        json_free(opts.mrealloc_waste);
    }

    unsigned char tmp[4096];
    struct json_out dump;
    json_out_init(&dump, tmp, sizeof(tmp));
    json_out_write(&dump, tok);
    char *out = json_out_get_output(&dump);
    if (!test_limits)
        printf(" =>      %s\n", out ? out : "<error?>");

    bool success = !!tok;

    if (use_mrealloc || use_mrealloc_for_real)
        json_free(tok);

    bool limits_exceeded = opts.error == JSON_ERR_NOMEM ||
                           opts.error == JSON_ERR_DEPTH;

    if (error_on_limits && !success && limits_exceeded)
        return false;

    if (test_limits && cutoff_input < len)
        return !success;

    if (strcmp(expect, out)) {
        if (test_limits)
            printf("Inconsistent test_limits result (%d):\n", opts.error);
        printf("Expected: '%s'\nGot: '%s'\n", expect, out);
        printf("Test failed!\n");
        abort();
    }

    return true;
}

static bool run_test(const char *text, const char *expect,
                     int max_mem, int max_depth, bool test_limits,
                     bool error_on_limits, int cutoff_input)
{
    bool r = run_test_(text, expect, max_mem, max_depth, test_limits,
                       error_on_limits, cutoff_input, false, false);

    // Test dynamic case; set test_limits=true because it basically means
    // not printing anything normally.
    bool r2 = run_test_(text, expect, max_mem, max_depth, true,
                        error_on_limits, cutoff_input, true, false);

    // Of course the results can be different if limits are applied (different
    // amounts of static memory area are used).
    if (!test_limits) {
        if (r != r2) {
            printf("Inconsistent behavior with static vs. malloc: %d %d\n", r, r2);
            printf("Test failed!\n");
            abort();
        }
    }

    return r;
}

static void parsegen_test_full(const char *text, const char *expect,
                               bool test_cutoff)
{
    int mem = 4096;
    int depth = 10;
    int input = strlen(text);

    run_test(text, expect, mem, depth, false, false, input);

    // Test max. stack depth that works.
    bool depth_ok = true;
    for (int n = depth; n >= 1; n--) {
        bool ok = run_test(text, expect, mem, n, true, true, input);
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
        bool ok = run_test(text, expect, n, depth, true, true, input);
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

    // Test cut off input.
    if (test_cutoff) {
        for (int n = input - 2; n >= 0; n--) {
            bool ok = run_test(text, expect, mem, depth, true, false, n);
            if (!ok) {
                printf("oh no (cut off at %d)\n", n);
                abort();
            }
        }
    }
}

static void parsegen_test(const char *text, const char *expect)
{
    parsegen_test_full(text, expect, true);
}

// Expect failure if extensions are disabled, otherwise like parsegen_test().
static void parsegen_test_ext(const char *text, const char *expect)
{
    enable_extensions = true;
    parsegen_test(text, expect);
    enable_extensions = false;
    parsegen_test(text, "<error>");
}

// Do not test removing characters from the end of the text (avoids test failing
// if text is supposed to fail, but becomes valid by removing characters, but
// also if removing characters does _not_ make parsing fail).
static void parsegen_test_nocut(const char *text, const char *expect)
{
    parsegen_test_full(text, expect, false);
}

static void test_mrealloc_oom(const char *text, const char *expect)
{
    // Step 1: test how much memory it needs.
    oom_enable = true;
    oom_hit = false;
    oom_left = (size_t)-1;

    assert(run_test_(text, expect, 1024, 16, true, true, INT_MAX, true, false));

    // Step 2: test by reducing the memory budget by 1 byte each iteration.
    size_t needed = (size_t)-1 - oom_left;
    size_t cur = needed + 1;
    bool failed = false;
    while (cur) {
        cur -= 1;
        oom_enable = true;
        oom_hit = false;
        oom_left = cur;
        bool r = run_test_(text, expect, 1024, 16, true, true, INT_MAX,
                           true, false);
        if (r) {
            if (oom_hit) {
                printf("should not have hit OOM\n");
                abort();
            }
            if (failed) {
                printf("inconsistent OOM behavior\n");
                abort();
            }
        } else {
            if (!oom_hit) {
                printf("should have hit OOM\n");
                abort();
            }
            if (!failed)
                printf("expected failure on %zu/%zu bytes\n", cur, needed);
            failed = true;
        }
    }
}

static void expect_tree(struct json_tok *tree, const char *expect)
{
    char *s = json_to_string(tree);
    if (strcmp(expect, s)) {
        printf("expected: <%s>\ngot: <%s>\n", expect, s);
        abort();
    }
    free(s);
}

static void test_malloc_helpers(void)
{
    struct json_tok *root = json_copy(JSON_MAKE_OBJ());
    expect_tree(root, "{}");
    assert(json_set_int(root, "num", 123));
    assert(json_set_string(root, "str", "hello"));
    char *s = strdup("aloha");
    assert(s);
    assert(json_set_string_nocopy(root, "str2", s));
    struct json_tok *arr = json_set_array(root, "array");
    assert(arr);
    expect_tree(root, "{\"num\":123,\"str\":\"hello\",\"str2\":\"aloha\",\"array\":[]}");
    struct json_tok *copy = json_copy(root);
    assert(copy);
    expect_tree(copy, "{\"num\":123,\"str\":\"hello\",\"str2\":\"aloha\",\"array\":[]}");
    json_free(copy);
    assert(json_object_remove(root, "str"));
    assert(json_object_remove(root, "num"));
    assert(json_object_remove(root, "str2"));
    assert(!json_object_remove(root, "blubb"));
    expect_tree(root, "{\"array\":[]}");
    assert(json_array_append(arr, JSON_MAKE_NUM(56)));
    assert(json_array_append(arr, JSON_MAKE_NULL()));
    assert(json_array_append(arr, JSON_MAKE_STR("abc")));
    assert(json_array_append(arr, JSON_MAKE_BOOL(true)));
    expect_tree(root, "{\"array\":[56,null,\"abc\",true]}");
    assert(json_array_insert(arr, 2, JSON_MAKE_STR("brrr")));
    assert(json_array_insert(arr, 3, JSON_MAKE_OBJ()));
    expect_tree(root, "{\"array\":[56,null,\"brrr\",{},\"abc\",true]}");
    assert(!json_array_remove(arr, 6));
    assert(json_array_remove(arr, 2));
    expect_tree(root, "{\"array\":[56,null,{},\"abc\",true]}");
    assert(json_array_remove(arr, 4));
    expect_tree(root, "{\"array\":[56,null,{},\"abc\"]}");
    assert(json_array_remove(arr, 0));
    assert(json_array_remove(arr, 0));
    assert(json_array_remove(arr, 1));
    expect_tree(root, "{\"array\":[{}]}");
    assert(json_array_set(arr, 0, JSON_MAKE_BOOL(false)));
    expect_tree(root, "{\"array\":[false]}");
    assert(json_array_remove(arr, 0));
    expect_tree(root, "{\"array\":[]}");
    assert(json_set_int(root, "array", 3000));
    expect_tree(root, "{\"array\":3000}");
    struct json_tok *sub1 = json_get_or_add_typed(root, "array", JSON_TYPE_DOUBLE);
    assert(sub1);
    expect_tree(sub1, "3000");
    struct json_tok *sub2 = json_get_or_add_typed(root, "array", JSON_TYPE_ARRAY);
    assert(sub2);
    expect_tree(sub2, "[]");
    struct json_tok *sub3 = json_get_or_add_typed(root, "mooh", JSON_TYPE_ARRAY);
    json_array_append(sub3, JSON_MAKE_NUM(1));
    expect_tree(root, "{\"array\":[],\"mooh\":[1]}");
    json_free(root);
}

int main(void)
{
    parsegen_test_nocut("  { }  ", "{}");
    parsegen_test_nocut("  true ", "true");
    parsegen_test_nocut("  false ", "false");
    parsegen_test_nocut("  null ", "null");
    parsegen_test_nocut(" 123 ", "123");
    parsegen_test("{\"field1\": \"test\", \"field2\" : 2}",
                  "{\"field1\":\"test\",\"field2\":2}");
    parsegen_test(" [ 3, 4, true, false ,null ] ", "[3,4,true,false,null]");
    parsegen_test_nocut("\"he\\u003a\\t\\u001cll\\\\o \\\"there\"",
                  "\"he:\\t\\u001cll\\\\o \\\"there\"");
    parsegen_test("{\"field1\": [1, 2, 3, {\"f\": [4, 5, 6]}, "
                  " {\"g\": [7, 8, 9, 10,12 ] }, 11], \"field2\" : 2}",
                  "{\"field1\":[1,2,3,{\"f\":[4,5,6]},"
                  "{\"g\":[7,8,9,10,12]},11],\"field2\":2}");
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
    parsegen_test_nocut("  truek", "<error>");
    parsegen_test_nocut("  true1", "<error>");
    parsegen_test_nocut("  1true", "<error>");
    parsegen_test("  tru", "<error>");
    parsegen_test("  tr", "<error>");
    parsegen_test("  t", "<error>");
    parsegen_test("  ", "<error>");
    parsegen_test("", "<error>");
    parsegen_test(" \t ", "<error>");
    parsegen_test("{", "<error>");
    parsegen_test("[", "<error>");
    parsegen_test("\"\\uDBFFa", "<error>");
    parsegen_test("\"\\uDBFF\\uAFFF\"", "<error>");
    parsegen_test_nocut("1 2", "<error>");
    parsegen_test("{4:5}", "<error>");
    parsegen_test("{:5}", "<error>");
    // Deeper than the hardcoded 10 max. nesting depth in parsegen_test().
    parsegen_test("[[[[[[[[[[1]]]]]]]]]]", "<error>");
    // One level less.
    parsegen_test("[[[[[[[[[1]]]]]]]]]", "[[[[[[[[[1]]]]]]]]]");
    // More array items than depth.
    parsegen_test("[[[[[[[[[1,2,3,4,5,6,7,8,9,10,11]]]]]]]]]",
                  "[[[[[[[[[1,2,3,4,5,6,7,8,9,10,11]]]]]]]]]");
    // More array items than depth, ascending again at one point.
    parsegen_test("[[[[[[[[[1,2,3,4,5,6,7,8,9,10,11]],[12,13,14,15,16,17,18,19,20]]]]]]]]",
                  "[[[[[[[[[1,2,3,4,5,6,7,8,9,10,11]],[12,13,14,15,16,17,18,19,20]]]]]]]]");
    // Should fail. There are various extensions to JSON which allow them (and
    // we could support them), but they are not part of standard JSON.
    parsegen_test("{field: 123}", "<error>");
    parsegen_test("[1,2,3,]", "<error>");
    // Supported extension: // comments until the end of a line
    parsegen_test_ext("[1,2,//3,4//9\n//6\n\n5,6]", "[1,2,5,6]");
    parsegen_test_ext("[1,2,//3,4//9\n\"du//foo\"]", "[1,2,\"du//foo\"]");
    parsegen_test_ext("//nuu\n{//dadada\n\"f\"//dududu\n://nuii\n3}", "{\"f\":3}");
    // Supported extension: trailing ',' in arrays/objects
    parsegen_test_ext("[1,2,]", "[1,2]");
    parsegen_test_ext("[1 , 2  ,  ]", "[1,2]");
    parsegen_test_ext("[1,]", "[1]");
    parsegen_test_ext("[1,2,,]", "<error>");
    parsegen_test_ext("[1,2,,3]", "<error>");
    parsegen_test_ext("[,]", "<error>");
    parsegen_test_ext("{\"a\":1,}", "{\"a\":1}");
    enable_extensions = true;
    parsegen_test_nocut("123//uhhhh", "123");
    enable_extensions = false;

    test_mrealloc_oom("{\"field1\": [1, 2, 3, {\"f\": [4, 5, 6]}, "
                      " {\"g\": [7, 8, 9, 10,12 ] }, 11], \"field2\" : 2}",
                      "{\"field1\":[1,2,3,{\"f\":[4,5,6]},"
                      "{\"g\":[7,8,9,10,12]},11],\"field2\":2}");

    // The stuff above never actually tests json_parse_malloc() itself.
    if (!run_test_("{\"a\":123,\"bc\":[]}", "{\"a\":123,\"bc\":[]}",
                   0, 0, false, false, INT_MAX, false, true))
    {
        printf("mrealloc failed\n");
        abort();
    }

    test_malloc_helpers();

    printf("OK\n");
    return 0;
}
