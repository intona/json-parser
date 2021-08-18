/*
 * Copyright (C) 2018 Intona Technology GmbH
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"

struct state {
    char *start;
    char *text;
    char *mem_ptr;          // offset for allocations
    char *stack_ptr;        // offset for stack
    char *mem_end;
    int idepth;             // inverse nesting depth
    struct curlist *top;    // top-most list element (NULL if none)
    struct json_parse_opts *opts;
};

struct curlist {
    struct json_tok *tok;
    struct curlist *prev;
};

// To keep the stack allocator simple: keep alignment when allocating curlist.
union curlist_alloc {
    struct curlist a;
    struct json_tok b;
    struct json_object_entry c;
};

#define MAX_ALIGN (_Alignof(struct json_tok))
// Stack allocation must not add additional padding (array/object parsing assumes
// allocating is like appending to a C array), so they must be multiples of the
// stack's inherent alignment. (Generally simplifies stack pointer management.)
static_assert(!(sizeof(struct json_tok) & (MAX_ALIGN - 1)), "");
static_assert(!(sizeof(union curlist_alloc) & (MAX_ALIGN - 1)), "");
static_assert(!(sizeof(struct json_object_entry) & (MAX_ALIGN - 1)), "");
// "Heap" allocations only need a common minimum alignment.
static_assert(MAX_ALIGN >= _Alignof(struct json_tok), "");
static_assert(MAX_ALIGN >= _Alignof(struct json_array), "");
static_assert(MAX_ALIGN >= _Alignof(struct json_object), "");

static void json_err_val(struct state *st, int err, const char *msg)
{
    if (!st->opts->error)
        st->opts->error = err;
    if (st->opts->msg_cb)
        st->opts->msg_cb(st->opts->msg_cb_opaque, (st)->text - (st)->start, msg);
}

static void json_err(struct state *st, const char *msg)
{
    json_err_val(st, JSON_ERR_SYNTAX, msg);
}

static void json_err_oom(struct state *st)
{
    json_err_val(st, JSON_ERR_NOMEM, "out of memory");
}

// Allocate memory of given size, with MAX_ALIGN alignment.
static void *json_alloc(struct state *st, size_t obj_size)
{
    // Ensure _next_ allocation will remain aligned.
    if ((obj_size & (MAX_ALIGN - 1)) && obj_size < ((size_t)-1) - MAX_ALIGN)
        obj_size += MAX_ALIGN - (obj_size & (MAX_ALIGN - 1));

    if (obj_size > st->stack_ptr - st->mem_ptr) {
        json_err_oom(st);
        return NULL;
    }

    void *res = st->mem_ptr;
    st->mem_ptr += obj_size;
    return res;
}

// Allocate stack memory of given size. obj_size must be a multiple of MAX_ALIGN.
static void *json_stack_alloc(struct state *st, size_t obj_size)
{
    if (obj_size > st->stack_ptr - st->mem_ptr || (obj_size & (MAX_ALIGN - 1))) {
        json_err_oom(st);
        return NULL;
    }
    st->stack_ptr -= obj_size;
    return st->stack_ptr;
}

static bool parse_value(struct state *st, struct json_tok *tok);

static void skip_ws(struct state *st)
{
    st->text += strspn(st->text, " \t\r\n");
}

static bool skip_str(struct state *st, const char *str)
{
    skip_ws(st);
    size_t str_len = strlen(str);
    if (strncmp(st->text, str, str_len) != 0)
        return false;
    st->text += str_len;
    return true;
}

static bool push_list_head(struct state *st, struct json_tok *tok)
{
    if (!st->idepth) {
        json_err_val(st, JSON_ERR_DEPTH, "maximum nesting depth reached");
        return false;
    }

    struct curlist *cur = json_stack_alloc(st, sizeof(union curlist_alloc));
    if (!cur)
        return false;

    cur->tok = tok;
    cur->prev = st->top;

    st->top = cur;
    st->idepth--;

    return true;
}

#define REVERSE_ITEMS(ITEM_T, f) do {               \
    ITEM_T *arr_ = (f)->items;                      \
    size_t count_ = (f)->count;                     \
    for (size_t n_ = 0; n_ < count_ / 2; n_++) {    \
        ITEM_T tmp = arr_[n_];                      \
        arr_[n_] = arr_[count_ - 1 - n_];           \
        arr_[count_ - 1 - n_] = tmp;                \
    }                                               \
} while (0)

// Parse JSON_TYPE_OBJECT or JSON_TYPE_ARRAY into tok.
static bool parse_lists(struct state *st)
{
    while (st->top) {
        struct curlist *cur = st->top;
        struct json_tok *tok = cur->tok;

        if (skip_str(st, tok->type == JSON_TYPE_OBJECT ? "}" : "]")) {
            // At the end of the parsing loop, all items will have been "pushed"
            // to the stack between st->stack_ptr and cur (in reverse order).
            // Move the items on the stack to the heap, and remove the stack.
            // (This always works because everything is already correctly
            // aligned.)
            size_t items_size = (char *)cur - st->stack_ptr;
            void *items = st->mem_ptr;
            memmove(items, st->stack_ptr, items_size);
            st->mem_ptr += items_size;

            st->top = cur->prev;
            st->stack_ptr = (char *)cur + sizeof(union curlist_alloc);

            if (tok->type == JSON_TYPE_OBJECT) {
                tok->u.object = json_alloc(st, sizeof(*tok->u.object));
                if (!tok->u.object)
                    return false;
                tok->u.object->items = items;
                tok->u.object->count = items_size / sizeof(tok->u.object->items[0]);
                REVERSE_ITEMS(struct json_object_entry, tok->u.object);
            } else if (tok->type == JSON_TYPE_ARRAY) {
                tok->u.array = json_alloc(st, sizeof(*tok->u.array));
                if (!tok->u.array)
                    return false;
                tok->u.array->items = items;
                tok->u.array->count = items_size / sizeof(tok->u.array->items[0]);
                REVERSE_ITEMS(struct json_tok, tok->u.array);
            }

            continue;
        }

        if (st->stack_ptr != (char *)cur && !skip_str(st, ",")) {
            json_err(st, "',' expected");
            return false;
        }

        struct json_tok *item_tok = NULL;

        if (tok->type == JSON_TYPE_OBJECT) {
            struct json_object_entry *e = json_stack_alloc(st, sizeof(*e));
            if (!e)
                return NULL;

            struct json_tok tmp;
            if (!parse_value(st, &tmp) || tmp.type != JSON_TYPE_STRING) {
                json_err(st, "object member name expected (quoted string)");
                return false;
            }
            if (!skip_str(st, ":")) {
                json_err(st, "':' after object member name expected");
                return false;
            }
            e->key = tmp.u.str;

            item_tok = &e->value;
        } else if (tok->type == JSON_TYPE_ARRAY) {
            item_tok = json_stack_alloc(st, sizeof(*item_tok));
        }

        if (!item_tok)
            return false;

        if (!parse_value(st, item_tok)) {
            json_err(st, "array/object value expected");
            return false;
        }
    }

    return true;
}

// Numeric escapes, e.g. "\u005C", without the "\u" prefix.
static int parse_numeric_escape(struct state *st)
{
    // Manually parse the 4-digit hex (easier than using strtol()).
    int v = 0;
    for (int n = 0; n < 4; n++) {
        unsigned char c = st->text[n];
        if (c >= '0' && c <= '9') {
            c = c - '0';
        } else if (c >= 'A' && c <= 'F') {
            c = c - 'A' + 10;
        } else if (c >= 'a' && c <= 'f') {
            c = c - 'a' + 10;
        } else {
            if (c) {
                json_err(st, "invalid character in numeric escape");
            } else {
                json_err(st, "cut off numeric escape");
            }
            return -1;
        }
        v = (v << 4) | c;
    }
    st->text += 4;
    return v;
}

// Encode the given codepoint as UTF-8, write to dst, and return the pointer to
// the next free byte. Can write at most 4 bytes. Returns NULL on error (invalid
// unicode codepoints).
static char *encode_utf8(char *dst, uint32_t cp)
{
    if (cp >= 0xD800 && cp <= 0xDFFF)
        return NULL; // invalid surrogate pair codepoints

    if (cp <= 0x7F) {
        *dst++ = cp;
    } else if (cp <= 0x7FF) {
        *dst++ = 0xC0 | (cp >> 6);
        *dst++ = 0x80 | (cp & 0x3F);
    } else if (cp <= 0xFFFF) {
        *dst++ = 0xE0 | (cp >> 12);
        *dst++ = 0x80 | ((cp >> 6) & 0x3F);
        *dst++ = 0x80 | (cp & 0x3F);
    } else if (cp <= 0x10FFFF) {
        *dst++ = 0xF0 | (cp >> 18);
        *dst++ = 0x80 | ((cp >> 12) & 0x3F);
        *dst++ = 0x80 | ((cp >> 6) & 0x3F);
        *dst++ = 0x80 | (cp & 0x3F);
    } else {
        return NULL; // invalid high codepoints
    }
    return dst;
}

// Terminating the string with \0 and resolving escapes is done in-place to
// reduce memory usage. The string starts at st->text, and the unescaped string
// is "appended" to this position in-place.
static bool parse_str(struct state *st)
{
    char *dst = st->text;
    while (1) {
        unsigned char c = st->text[0];
        if (!c) {
            json_err(st, "closing '\"' missing in string literal");
            return false;
        }
        st->text += 1;
        if (c == '"') {
            *dst = '\0';
            return true;
        } else if (c <= 0x1F) {
            json_err(st, "unescaped control character in string literal");
            return false;
        } else if (c == '\\') {
            c = st->text[0];
            if (c)
                st->text += 1;
            // Error on other standard JSON escapes, or '\0' for cut off JSON.
            switch (c) {
            case '\\': c = '\\'; break;
            case '\"': c = '\"'; break;
            case '/':  c = '/';  break;
            case 'b':  c = '\b'; break;
            case 'f':  c = '\f'; break;
            case 'n':  c = '\n'; break;
            case 'r':  c = '\r'; break;
            case 't':  c = '\t'; break;
            case 'u': {
                // Numeric escapes, e.g. "\u005C"
                int v = parse_numeric_escape(st);
                if (v < 0)
                    return false;
                uint32_t cp = v;
                // Surrogate pairs for characters outside of the BMP.
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    if (!skip_str(st, "\\u")) {
                        json_err(st, "missing low surrogate pair");
                        return false;
                    }
                    v = parse_numeric_escape(st);
                    if (v < 0)
                        return false;
                    if (v < 0xDC00 || v > 0xDFFF) {
                        json_err(st, "invalid low surrogate pair");
                        return false;
                    }
                    cp = ((cp & 0x3FF) << 10) + (v & 0x3FF) + 0x10000;
                }
                // What should \u0000 do? Just error out.
                if (cp == 0) {
                    json_err(st, "0 byte escape rejected");
                    return false;
                }
                // Note: in-place encoding is still possible. In the worst case,
                // we write 4 bytes, while the escape syntax uses 6 bytes.
                dst = encode_utf8(dst, cp);
                if (!dst) {
                    json_err(st, "invalid unicode escape");
                    return false;
                }
                continue;
            }
            default:
                json_err(st, "unknown escape");
                return false;
            }
        }
        *dst++ = c;
    }
}

static bool parse_number(struct state *st, struct json_tok *tok)
{
    char *endptr;
    errno = 0;
    double v = strtod(st->text, &endptr);
    if (endptr == st->text || errno || !isfinite(v))
        return false; // error message handled by parse_value()
    st->text = endptr;
    tok->type = JSON_TYPE_DOUBLE;
    tok->u.d = v;
    return true;
}

// This will parse e.g. "truek" as JSON_TYPE_BOOL and move *text to "k", but
// this is OK as the "k" could never be valid syntax in the parsing after it.
// Returns false on any error.
static bool parse_value(struct state *st, struct json_tok *tok)
{
    skip_ws(st);

    char c = st->text[0];
    switch (c) {
    case '\0':
        json_err(st, "value expected, but end of input reached");
        return false;
    case 'n':
        tok->type = JSON_TYPE_NULL;
        if (!skip_str(st, "null"))
            break;
        return true;
    case 't':
        tok->type = JSON_TYPE_BOOL;
        tok->u.b = true;
        if (!skip_str(st, "true"))
            break;
        return true;
    case 'f':
        tok->type = JSON_TYPE_BOOL;
        tok->u.b = false;
        if (!skip_str(st, "false"))
            break;
        return true;
    case '[':
    case '{':
        tok->type = c == '[' ? JSON_TYPE_ARRAY : JSON_TYPE_OBJECT;
        st->text += 1;
        return push_list_head(st, tok);
    case '"': {
        st->text += 1;
        tok->type = JSON_TYPE_STRING;
        tok->u.str = st->text;
        return parse_str(st);
    }
    default: ;
        // The only valid other thing could be a number.
        if (!parse_number(st, tok))
            break;
        return true;
    }

    json_err(st, "character does not start a valid JSON token");
    return false;
}

static struct json_tok *do_parse(const char *text, bool copy, void *mem,
                                 size_t mem_size, struct json_parse_opts *opts)
{
    struct state *st = &(struct state){
        .start = (char *)text, // json_err()
        .text = (char *)text,
        .mem_ptr = mem,
        .mem_end = (char *)mem + mem_size,
        .opts = opts ? opts : &(struct json_parse_opts){0},
    };

    st->idepth = st->opts->depth > 0 ? st->opts->depth - 1 : INT_MAX;

    st->opts->error = JSON_ERR_NONE;

    if (mem_size < MAX_ALIGN) {
        json_err_val(st, JSON_ERR_NOMEM, "out of memory");
        return NULL;
    }

    size_t align = (uintptr_t)st->mem_ptr & (MAX_ALIGN - 1);
    st->mem_ptr += align ? MAX_ALIGN - align : 0;

    align = (uintptr_t)st->mem_end & (MAX_ALIGN - 1);
    st->stack_ptr = st->mem_end - align;

    if (copy) {
        size_t len = strlen(text) + 1;
        char *tmp = json_alloc(st, len);
        if (!tmp)
            return NULL;
        memcpy(tmp, text, len);
        st->text = st->start = tmp;
    }

    struct json_tok *res = json_alloc(st, sizeof(*res));
    if (!res)
        return NULL;

    if (!parse_value(st, res) || !parse_lists(st))
        return NULL;

    // No trailing non-whitespace text allowed.
    skip_ws(st);
    if (st->text[0]) {
        json_err(st, "trailing text at end of JSON value");
        return NULL;
    }
    return res;
}

struct json_tok *json_parse_destructive(char *text, void *mem, size_t mem_size,
                                        struct json_parse_opts *opts)
{
    return do_parse(text, false, mem, mem_size, opts);
}

struct json_tok *json_parse(const char *text, void *mem, size_t mem_size,
                            struct json_parse_opts *opts)
{
    return do_parse(text, true, mem, mem_size, opts);
}
