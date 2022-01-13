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

#ifndef JSON_OUT_
#define JSON_OUT_

#include "json.h"

// JSON writer which does not bother going through struct json_tok. This is good
// if only unique fields are written.
// May provide pretty-printing capabilities in the future.

struct json_out {
    // All fields should be considered private. Call json_out_init() to
    // initialize the fields. Use json_out_get_output() to query the result.
    // Deinitialization is not required, since the caller has to provide
    // preallocated memory.
    char *start;
    char *buffer;
    size_t buffer_size;
    bool error;
    bool first_entry;
    void (*write)(void *ctx, const char *buf, size_t len);
    void *write_ctx;
    int depth;
    bool enable_newlines;
    int indent;
};

// Output to a fixed-size buffer.
void json_out_init(struct json_out *out, char *buffer, size_t buffer_size);

// Output via a callback. write() is called with write_ctx as cookie in the
// first parameter, and a buffer that is _not_ necessarily \0 terminated,
void json_out_init_cb(struct json_out *out,
    void (*write)(void *ctx, const char *buf, size_t len), void *write_ctx);

// Possibly flush still buffered data, perform error checks, return results.
bool json_out_finish(struct json_out *out);

// Call json_out_finish(), and return the pointer to the output string (in
// practice, the buffer that was passed in), or NULL if the former failed.
char *json_out_get_output(struct json_out *out);

// Append a raw string to the output (for example, splicing in pre-formatted
// JSON data).
void json_out_raw(struct json_out *out, const char *s, size_t s_size);

// For cosmetic purposes, or as terminator.
void json_out_newline(struct json_out *out);

// Write standard primitive values.
void json_out_null(struct json_out *out);
void json_out_int(struct json_out *out, int val);
void json_out_double(struct json_out *out, double val);
void json_out_bool(struct json_out *out, bool val);
void json_out_string(struct json_out *out, const char *str);

// Incremental writing of string literals.
void json_out_start_string(struct json_out *out);
void json_out_continue_string(struct json_out *out, const char *str);
void json_out_end_string(struct json_out *out);

// Nested values require being aware of the state.
void json_out_object_start(struct json_out *out);
// (There is no "_end".)
void json_out_field_start(struct json_out *out, const char *key);
void json_out_object_end(struct json_out *out);
void json_out_array_start(struct json_out *out);
// (There is no "_end".)
void json_out_array_entry_start(struct json_out *out);
void json_out_array_end(struct json_out *out);

void json_out_field_int(struct json_out *out, const char *key, int val);
void json_out_field_double(struct json_out *out, const char *key, double val);
void json_out_field_bool(struct json_out *out, const char *key, bool val);
void json_out_field_string(struct json_out *out, const char *key, const char *str);

// Write the token (potentially a sub-tree of JSON elements).
void json_out_write(struct json_out *out, struct json_tok *root);

// Pretty printing: enable line breaks after each array/object item.
void json_out_enable_newlines(struct json_out *out);

// Pretty printing: enable adding indent spaces for each array/object nesting.
// This internally calls json_out_enable_newlines().
void json_out_set_indent(struct json_out *out, int indent);

#endif
