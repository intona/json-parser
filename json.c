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
    void *mem;
    size_t mem_size;
    struct json_msg_cb msg;
};

static void json_err(struct state *st, const char *msg)
{
    if (st->msg.cb)
        st->msg.cb(st->msg.opaque, (st)->text - (st)->start, msg);
}

// Allocate memory of size obj_size, with the alignment in obj_align. obj_align
// _must_ be a power of 2.
static void *json_alloc(struct state *st, size_t obj_align, size_t obj_size)
{
    uintptr_t sptr = (uintptr_t)st->mem;
    uintptr_t res = (sptr + (obj_align - 1)) & ~(obj_align - 1);
    uintptr_t nptr = res + obj_size;

    // Catch any kind of overflows. Assumes out of bound uintptr_t values are
    // OK, because they're not pointers (pointer values before or beyond the
    // allocated memory area are undefined behavior), and unsigned overflow is
    // well-defined.
    if (res < sptr || nptr < res) {
        json_err(st, "out of memory");
        return NULL;
    }

    st->mem = (void *)nptr;
    st->mem_size -= nptr - sptr;
    return (void *)res;
}

#define JSON_ALLOC(T, st) \
    (T *)json_alloc(st, _Alignof(T), sizeof(T))

static bool parse_value(struct state *st, struct json_tok *tok, int d);

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

// Parse JSON_TYPE_OBJECT or JSON_TYPE_ARRAY into tok.
static bool parse_list(struct state *st, struct json_tok *tok, int d)
{
    struct json_list *list = JSON_ALLOC(struct json_list, st);
    if (!list)
        return false;

    list->count = 0;
    list->head = NULL;

    tok->u.list = list;

    const char *end = tok->type == JSON_TYPE_OBJECT ? "}" : "]";
    struct json_list_item **next_ptr = &list->head;

    while (!skip_str(st, end)) {
        if (list->count && !skip_str(st, ",")) {
            json_err(st, "',' expected");
            return false;
        }

        struct json_list_item *item = JSON_ALLOC(struct json_list_item, st);
        if (!item)
            return false;

        item->key = NULL;
        item->next = NULL;

        if (tok->type == JSON_TYPE_OBJECT) {
            struct json_tok tmp;
            if (!parse_value(st, &tmp, d) || tmp.type != JSON_TYPE_STRING) {
                json_err(st, "object member name expected (quoted string)");
                return false;
            }
            if (!skip_str(st, ":")) {
                json_err(st, "':' after object member name expected");
                return false;
            }
            item->key = tmp.u.str;
        }

        if (!parse_value(st, &item->value, d)) {
            json_err(st, "array/object value expected");
            return false;
        }

        *next_ptr = item;
        next_ptr = &item->next;

        list->count += 1;
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
                        return -1;
                    }
                    v = parse_numeric_escape(st);
                    if (v < 0)
                        return false;
                    if (v < 0xDC00 || v > 0xDFFF) {
                        json_err(st, "invalid low surrogate pair");
                        return -1;
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
// Returns NULL on any error.
static bool parse_value(struct state *st, struct json_tok *tok, int d)
{
    if (d == 0) {
        json_err(st, "maximum nesting depth reached");
        return false;
    }
    d--;

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
        return parse_list(st, tok, d);
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

    return false;
}

static struct json_tok *parse(struct state *st, int d)
{
    struct json_tok *res = JSON_ALLOC(struct json_tok, st);
    if (!res)
        return NULL;
    if (!parse_value(st, res, d)) {
        json_err(st, "character does not start a valid JSON token");
        return NULL;
    }
    // No trailing non-whitespace text allowed.
    skip_ws(st);
    if (st->text[0]) {
        json_err(st, "trailing text at end of JSON value");
        return NULL;
    }
    return res;
}

struct json_tok *json_parse_destructive(char *text, void *mem, size_t mem_size,
                                        int depth, struct json_msg_cb *msg_ctx)
{
    struct state st = {
        .start = text,
        .text = text,
        .mem = mem,
        .mem_size = mem_size,
        .msg = msg_ctx ? *msg_ctx : (struct json_msg_cb){0},
    };
    return parse(&st, depth);
}

struct json_tok *json_parse(const char *text, void *mem, size_t mem_size,
                            int depth, struct json_msg_cb *msg_ctx)
{
    struct state st = {
        // json_err() needs to have this set, but won't mutate it.
        .start = (char *)text,
        .text = (char *)text,
        .mem = mem,
        .mem_size = mem_size,
        .msg = msg_ctx ? *msg_ctx : (struct json_msg_cb){0},
    };
    size_t len = strlen(text) + 1;
    char *tmp = json_alloc(&st, 1, len);
    if (!tmp)
        return NULL;
    memcpy(tmp, text, len);
    st.text = st.start = tmp;
    return parse(&st, depth);
}
