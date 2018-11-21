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

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "json_out.h"

#ifdef __GNUC__
#define FORMAT_STR(a, b) __attribute__((format(printf, a, b)))
#else
#define FORMAT_STR(a, b)
#endif

void json_out_init(struct json_out *out, char *buffer, size_t buffer_size)
{
    *out = (struct json_out){
        .start = buffer,
        .buffer = buffer,
        .buffer_size = buffer_size,
    };
    if (buffer_size)
        buffer[0] = '\0';
}

char *json_out_get_output(struct json_out *out)
{
    return out->error ? NULL : out->start;
}

static void append_buf(struct json_out *out, const char *buf, size_t len)
{
    // (The +1 is for making it 0-terminated at the end of the function.)
    if (out->buffer_size < len + 1) {
        out->error = true;
        return;
    }
    memcpy(out->buffer, buf, len);
    out->buffer += len;
    out->buffer_size -= len;
    out->buffer[0] = '\0';
}

static void append_str(struct json_out *out, const char *str)
{
    append_buf(out, str, strlen(str));
}

void json_out_newline(struct json_out *out)
{
    append_buf(out, "\n", 1);
}

FORMAT_STR(2, 3)
static void append_f(struct json_out *out, const char *fmt, ...)
{
    int len;

    va_list va;
    va_start(va, fmt);
    len = vsnprintf(out->buffer, out->buffer_size, fmt, va);
    va_end(va);

    if (len < 0 || out->buffer_size < (unsigned)len + 1) {
        out->error = true;
        return;
    }

    out->buffer += len;
    out->buffer_size -= len;
}

void json_out_null(struct json_out *out)
{
    append_str(out, "null");
}

void json_out_int(struct json_out *out, int val)
{
    append_f(out, "%d", val);
}

void json_out_double(struct json_out *out, double val)
{
    append_f(out, "%f", val);
}

void json_out_bool(struct json_out *out, bool val)
{
    append_str(out, val ? "true" : "false");
}

void json_out_string(struct json_out *out, const char *str)
{
    json_out_start_string(out);
    json_out_continue_string(out, str);
    json_out_end_string(out);
}

void json_out_start_string(struct json_out *out)
{
    append_str(out, "\"");
}

void json_out_end_string(struct json_out *out)
{
    append_str(out, "\"");
}

void json_out_continue_string(struct json_out *out, const char *str)
{
    const char *cur = str;
    while (*cur) {
        unsigned char c = *cur++;
        if (c < 32 || c == '\\' || c == '\"') {
            append_buf(out, str, cur - str - 1);
            append_buf(out, "\\", 1);
            switch (c) {
            case '\\': c = '\\'; break;
            case '\"': c = '\"'; break;
            case '\f': c = 'f'; break;
            case '\n': c = 'n'; break;
            case '\r': c = 'r'; break;
            case '\t': c = 't'; break;
            default:
                append_f(out, "u%04x", c);
                c = 0;
            }
            if (c)
                append_buf(out, &(char){c}, 1);
            str = cur;
        }
    }
    append_buf(out, str, cur - str);
}

void json_out_object_start(struct json_out *out)
{
    append_str(out, "{");
    out->first_entry = true;
}

void json_out_field_start(struct json_out *out, const char *key)
{
    if (!out->first_entry)
        append_str(out, ",");
    out->first_entry = false;

    json_out_string(out, key);
    append_str(out, ":");
}

void json_out_object_end(struct json_out *out)
{
    append_str(out, "}");
    out->first_entry = false;
}

void json_out_array_start(struct json_out *out)
{
    append_str(out, "[");
    out->first_entry = true;
}

void json_out_array_entry_start(struct json_out *out)
{
    if (!out->first_entry)
        append_str(out, ",");
    out->first_entry = false;
}

void json_out_array_end(struct json_out *out)
{
    append_str(out, "]");
    out->first_entry = false;
}

void json_out_field_int(struct json_out *out, const char *key, int val)
{
    json_out_field_start(out, key);
    json_out_int(out, val);
}

void json_out_field_double(struct json_out *out, const char *key, double val)
{
    json_out_field_start(out, key);
    json_out_double(out, val);
}

void json_out_field_bool(struct json_out *out, const char *key, bool val)
{
    json_out_field_start(out, key);
    json_out_bool(out, val);
}

void json_out_field_string(struct json_out *out, const char *key, const char *str)
{
    json_out_field_start(out, key);
    json_out_string(out, str);
}

static bool is_int(double d)
{
    // (This may not be correct in all corner cases.)
    return (double)(int)d == d;
}

void json_out_write(struct json_out *out, struct json_tok *root)
{
    switch (root ? root->type : JSON_TYPE_INVALID) {
    case JSON_TYPE_NULL:
        json_out_null(out);
        break;
    case JSON_TYPE_BOOL:
        json_out_bool(out, root->u.b);
        break;
    case JSON_TYPE_STRING:
        json_out_string(out, root->u.str);
        break;
    case JSON_TYPE_DOUBLE: {
        double d = root->u.d;
        if (is_int(d)) {
            json_out_int(out, d);
        } else {
            json_out_double(out, d);
        }
        break;
    }
    case JSON_TYPE_ARRAY:
        json_out_array_start(out);
        for (struct json_list_item *i = root->u.list->head; i; i = i->next) {
            json_out_array_entry_start(out);
            json_out_write(out, &i->value);
        }
        json_out_array_end(out);
        break;
    case JSON_TYPE_OBJECT:
        json_out_object_start(out);
        for (struct json_list_item *i = root->u.list->head; i; i = i->next) {
            json_out_field_start(out, i->key);
            json_out_write(out, &i->value);
        }
        json_out_object_end(out);
        break;
    default:
        append_str(out, "<error>");
    }
}
