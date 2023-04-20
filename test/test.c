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

// (just in case you're wondering: this wouldn't be as easy to do without malloc)
static bool pull_to_tree(struct json_state *st, struct json_tok *dst)
{
    while (1) {
        struct json_tok tok;
        char *key;
        enum json_pull ev = json_pull_next(st, &tok, &key);

        switch (ev) {
        case JSON_PULL_ERROR:
            assert(json_pull_next(st, &tok, &key) == ev);
            return false;
        case JSON_PULL_END:
            assert(json_pull_next(st, &tok, &key) == ev);
            return true;
        case JSON_PULL_CLOSE_LIST:
            return true;
        case JSON_PULL_TOK: {
            struct json_tok ntok = {0};
            json_copy_inplace(&ntok, &tok);

            bool ok = true;
            if (ntok.type == JSON_TYPE_OBJECT || ntok.type == JSON_TYPE_ARRAY)
                ok = pull_to_tree(st, &ntok);

            if (dst->type == JSON_TYPE_INVALID) {
                // used for first item
                *dst = ntok;
            } else if (dst->type == JSON_TYPE_OBJECT) {
                assert(key);
                json_set_nocopy(dst, key, &ntok);
            } else if (dst->type == JSON_TYPE_ARRAY) {
                json_array_insert_nocopy(dst, dst->u.array->count, &ntok);
            } else {
                assert(0); // successive tokens not in array/object -> bug
            }

            if (!ok)
                return false;
            break;
        }
        default:
            assert(0);
        }
    }
}

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

enum parser {
    PARSER_STATIC,
    PARSER_STATIC_DESTRUCTIVE,
    PARSER_MREALLOC,
    PARSER_MALLOC, // wrapper for mrealloc, allocates even stack with malloc
    PARSER_PULL,

    PARSER_FIRST = PARSER_STATIC,
    PARSER_LAST = PARSER_PULL,
};

struct testargs {
    int max_mem;
    int max_depth;
    bool test_limits;
    bool error_on_limits;
    bool silent;
    int input_len_1;
    int mem_disalign;
    enum parser parser;
};

static bool run_test_(const char *text, const char *expect, struct testargs *args)
{
    size_t len = strlen(text);
    int max_mem = args->max_mem;
    int max_depth = args->max_depth;
    bool test_limits = args->test_limits;
    bool error_on_limits = args->error_on_limits;
    int cutoff_input = args->input_len_1 ? args->input_len_1 - 1 : len;
    enum parser parser = args->parser;

    if (max_mem > BUF_SZ)
        max_mem = BUF_SZ;
    char *tmp2 = malloc(max_mem + args->mem_disalign);
    assert(tmp2);
    memset(tmp2, 0xDF, max_mem);
    void *mem_arg = tmp2 + args->mem_disalign;

    if (cutoff_input > len)
        cutoff_input = len;

    bool silent = args->silent || args->test_limits;

    if (!silent) {
        //printf("parsing: '%s' (mode=%d, mem=%d, depth=%d, cut=%d/%zu)\n", text,
        //       parser, max_mem, max_depth, cutoff_input, len);
        printf("parsing: '%s' (mode=%d)\n", text, parser);
    }

    char *tmp1 = strndup(text, cutoff_input);
    char *tmp3 = strdup(tmp1);
    assert(tmp1 && tmp3);

    struct json_parse_opts opts = {
        .depth = max_depth,
        .msg_cb = silent ? NULL : json_msg_cb,
        .mrealloc = parser == PARSER_MREALLOC ? mrealloc : NULL,
        .enable_extensions = enable_extensions,
    };

    struct json_tok *tok = NULL;
    bool keeps_input = false;
    bool malloc_output = false;

    if (parser == PARSER_STATIC || parser == PARSER_MREALLOC) {
        tok = json_parse(tmp1, mem_arg, max_mem, &opts);
        keeps_input = true;
        malloc_output = !!opts.mrealloc;
    } else if (parser == PARSER_MALLOC) {
        tok = json_parse_malloc(tmp1, &opts);
        keeps_input = true;
        malloc_output = true;
    } else if (parser == PARSER_PULL) {
        struct json_state *st =
            json_pull_init_destructive(tmp1, mem_arg, max_mem, &opts);
        if (st) {
            tok = json_copy(&(struct json_tok){0});
            assert(tok);
            if (!pull_to_tree(st, tok)) {
                json_free(tok);
                tok = NULL;
            }
            malloc_output = true;
        }
    } else if (parser == PARSER_STATIC_DESTRUCTIVE) {
        tok = json_parse_destructive(tmp1, mem_arg, max_mem, &opts);
    } else {
        assert(0);
    }

    if (keeps_input && strcmp(tmp1, tmp3) != 0) {
        printf("input was changed\n");
        abort();
    }

    free(tmp3);

    // Ensure mrealloc mode doesn't reference the source text or working memory.
    if (malloc_output) {
        free(tmp1);
        free(tmp2);
        tmp1 = tmp2 = NULL;
        json_free(opts.mrealloc_waste);
    }

    unsigned char tmp[4096];
    struct json_out dump;
    json_out_init(&dump, tmp, sizeof(tmp));
    json_out_write(&dump, tok);
    char *out = json_out_get_output(&dump);
    if (!silent)
        printf(" =>      %s\n", out ? out : "<error?>");

    bool success = !!tok;

    if (malloc_output)
        json_free(tok);

    free(tmp1);
    free(tmp2);

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

static void parsegen_test_full(const char *text, const char *expect,
                               bool test_cutoff)
{
    int mem = 4096;
    int depth = 10;
    int input = strlen(text);
    bool res;

    for (int parser = PARSER_FIRST; parser <= PARSER_LAST; parser++) {
        struct testargs args2 = {
            .max_mem = mem,
            .max_depth = depth,
            .parser = parser,
        };
        bool r = run_test_(text, expect, &args2);
        if (parser == PARSER_FIRST) {
            res = r;
        } else if (res != r) {
            printf("inconsistent\n");
            abort();
        }

        // Test min. stack depth that works.
        bool depth_ok = true;
        int depth_ok_n = -1;
        for (int n = depth; n >= 1; n--) {
            struct testargs args = {
                .max_mem = mem,
                .max_depth = depth,
                .parser = parser,
                .test_limits = true,
                .error_on_limits = true,
            };
            bool ok = run_test_(text, expect, &args);
            if (ok)
                depth_ok_n = n;
            if (ok != depth_ok) {
                if (!depth_ok) {
                    // Lower depth worked again => makes no sense.
                    printf("oh no (depth)\n");
                    abort();
                }
                depth_ok = ok;
            }
        }
        printf(" ... min depth: %d\n", depth_ok_n);

        // Test min. memory size that works.
        bool mem_ok = true;
        int mem_ok_n = -1;
        for (int n = mem; n >= 0; n--) {
            int mem_arg = n;
            int mem_parser = parser;
            if (parser == PARSER_MREALLOC && n == 0)
                break; // mrealloc allocs stack itself at depth==0
            if (parser == PARSER_MALLOC) {
                // Note: skip the actual PARSER_MALLOC, test PARSER_MREALLOC
                // twice (first limiting the shadow stack memory, then actual
                // mrealloc limiting)
                mem_parser = PARSER_MREALLOC;
                oom_enable = true;
                oom_hit = false;
                oom_left = n;
                mem_arg = 0;
            }
            struct testargs args = {
                .max_mem = mem_arg,
                .max_depth = depth,
                .parser = mem_parser,
                .test_limits = true,
                .error_on_limits = true,
            };
            bool ok = run_test_(text, expect, &args);
            if (parser == PARSER_MALLOC) {
                oom_enable = false;
            }
            if (ok)
                mem_ok_n = n;
            if (ok != mem_ok) {
                if (!mem_ok) {
                    // Lower memory worked again => makes no sense.
                    printf("oh no (mem)\n");
                    abort();
                }
                mem_ok = ok;
            }
        }
        printf(" ... min mem: %d\n", mem_ok_n);

        // Test cut off input.
        if (test_cutoff) {
            for (int n = input - 2; n >= 0; n--) {
                struct testargs args = {
                    .max_mem = mem,
                    .max_depth = depth,
                    .parser = parser,
                    .test_limits = true,
                    .error_on_limits = false,
                    .input_len_1 = n + 1,
                };
                bool ok = run_test_(text, expect, &args);
                if (!ok) {
                    printf("oh no (cut off at %d)\n", n);
                    abort();
                }
            }
        }

        if (parser == PARSER_STATIC) {
            for (int n = 0; n < 16; n++) {
                struct testargs args = {
                    .max_mem = mem,
                    .max_depth = depth,
                    .parser = parser,
                    .mem_disalign = n,
                    .silent = true,
                };
                assert(run_test_(text, expect, &args));
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

    struct testargs args = {
        .max_mem = 1024,
        .max_depth = 16,
        .parser = PARSER_MREALLOC,
        .test_limits = true,
        .error_on_limits = true,
    };
    assert(run_test_(text, expect, &args));

    // Step 2: test by reducing the memory budget by 1 byte each iteration.
    size_t needed = (size_t)-1 - oom_left;
    size_t cur = needed + 1;
    bool failed = false;
    while (cur) {
        cur -= 1;
        oom_enable = true;
        oom_hit = false;
        oom_left = cur;
        bool r = run_test_(text, expect, &args);
        if (cur == needed + 1)
            assert(r);
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

    oom_enable = false;
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

static void test_pull_skip(void)
{
    char input[] = "{\"a\":[1,2,3,4],\"b\":[5],\"c\":[6,7,8,9]}";
    char tmp[200];
    struct json_parse_opts opts = {0};
    struct json_state *st =
        json_pull_init_destructive(input, tmp, sizeof(tmp), &opts);
    assert(st);
    struct json_tok t;
    char *k;
    int r;
    r = json_pull_next(st, &t, &k);
    assert(r == JSON_PULL_TOK && t.type == JSON_TYPE_OBJECT);
    r = json_pull_next(st, &t, &k);
    assert(r == JSON_PULL_TOK && t.type == JSON_TYPE_ARRAY && strcmp(k, "a") == 0);
    r = json_pull_next(st, &t, &k);
    assert(r == JSON_PULL_TOK && t.type == JSON_TYPE_DOUBLE && t.u.d == 1);
    json_pull_skip_nested(st);
    r = json_pull_next(st, &t, &k);
    assert(r == JSON_PULL_TOK && t.type == JSON_TYPE_ARRAY && strcmp(k, "b") == 0);
    r = json_pull_next(st, &t, &k);
    assert(r == JSON_PULL_TOK && t.type == JSON_TYPE_DOUBLE && t.u.d == 5);
    json_pull_skip_nested(st); // returns to previous, even if CLOSE_LIST is next
    r = json_pull_next(st, &t, &k);
    assert(r == JSON_PULL_TOK && t.type == JSON_TYPE_ARRAY && strcmp(k, "c") == 0);
    json_pull_skip_nested(st);
    r = json_pull_next(st, &t, &k);
    assert(r == JSON_PULL_CLOSE_LIST);
    r = json_pull_next(st, &t, &k);
    assert(r == JSON_PULL_END);
    // end remains
    json_pull_skip_nested(st);
    assert(r == JSON_PULL_END);
    // not in a list
    st = json_pull_init_destructive("123", tmp, sizeof(tmp), &opts);
    json_pull_skip_nested(st);
    r = json_pull_next(st, &t, &k);
    assert(r == JSON_PULL_TOK && t.type == JSON_TYPE_DOUBLE && t.u.d == 123);
    // error during skipping
    st = json_pull_init_destructive("[1,2,3,,", tmp, sizeof(tmp), &opts);
    r = json_pull_next(st, &t, &k);
    assert(r == JSON_PULL_TOK && t.type == JSON_TYPE_ARRAY);
    json_pull_skip_nested(st);
    r = json_pull_next(st, &t, &k);
    assert(r == JSON_PULL_ERROR);
    // error remains
    json_pull_skip_nested(st);
    r = json_pull_next(st, &t, &k);
    assert(r == JSON_PULL_ERROR);
}

int main(void)
{
    parsegen_test_nocut("  { }  ", "{}");
    parsegen_test_nocut("  [ ]  ", "[]");
    parsegen_test_nocut("  true ", "true");
    parsegen_test_nocut("  false ", "false");
    parsegen_test_nocut("  null ", "null");
    parsegen_test_nocut(" 123 ", "123");
    parsegen_test_nocut(" \"\\\\\\\"\\/\\b\\f\\n\\r\\t\" ",
                        "\"\\\\\\\"/\\b\\f\\n\\r\\t\"");
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
    parsegen_test("\"\\udbff\\udffF\"", "\"\xF4\x8F\xBF\xBF\"");
    // Missing surrogate codepoints.
    parsegen_test("\"\\uD800 \\uDC00\"", "<error>");
    // Invalid surrogate codepoints.
    parsegen_test("\"\\uDFFF\"", "<error>");
    parsegen_test("\"\\uDBFF\\uCFFF\"", "<error>");
    parsegen_test("\"\\uDBFF\\uEFFF\"", "<error>");
    // Invalid escape syntax.
    parsegen_test("\"\\udbff\\udfxF\"", "<error>");
    parsegen_test("\"\\udbff\\udffx\"", "<error>");
    parsegen_test("\"\\udbff\\uxffF\"", "<error>");
    parsegen_test("\"\\udbff\\uxffF\"", "<error>");
    parsegen_test("\"\\udbff\\xdffF\"", "<error>");
    parsegen_test("\"\\Udbff\\UdffF\"", "<error>");
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
    parsegen_test(" \"\t\" ", "<error>");
    parsegen_test("{", "<error>");
    parsegen_test("[", "<error>");
    parsegen_test("\"\\uDBFFa", "<error>");
    parsegen_test("\"\\uDBFF\\uAFFF\"", "<error>");
    parsegen_test_nocut("1 2", "<error>");
    parsegen_test("{4:5}", "<error>");
    parsegen_test("{:5}", "<error>");
    parsegen_test("nan", "<error>");
    parsegen_test("inf", "<error>");
    parsegen_test_nocut("1e400", "<error>");
    // Implementation choice.
    parsegen_test("\"\\u0000\"", "<error>");
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
                      " {\"g\": [7, 8, 9, 10,12,13,14,15,16 ] }, 11], \"field2\" : 2}",
                      "{\"field1\":[1,2,3,{\"f\":[4,5,6]},"
                      "{\"g\":[7,8,9,10,12,13,14,15,16]},11],\"field2\":2}");

    test_malloc_helpers();
    test_pull_skip();

    // shadow stack alloc overflow calculation
    struct json_parse_opts opts = {.depth = INT_MAX};
    assert(!json_parse_malloc("123", &opts));

    opts.mrealloc = mrealloc;
    assert(!json_pull_init_destructive("", NULL, 0, &opts));
    assert(!json_pull_init_destructive("", NULL, 0, NULL));
    assert(!json_parse_destructive("[\"abc\" ...]", NULL, 0, &opts));

    uint64_t tmp[80];
    assert(json_parse("123", tmp, sizeof(tmp), NULL));
    // trigger very specific alignment alloc failure code path
    assert(!json_parse("123", ((char *)tmp) + 1, sizeof(struct json_tok), NULL));

    printf("OK\n");
    return 0;
}
