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

#ifndef JSON_H_
#define JSON_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum json_type {
    // Note: JSON_TYPE_INVALID is guaranteed to be 0, so a 0-initialized
    // json_tok is guaranteed to have type==JSON_TYPE_INVALID.
    JSON_TYPE_INVALID = 0,  // does not occur in valid json
    JSON_TYPE_NULL,         // "null" (no value in json_tok.u)
    JSON_TYPE_BOOL,         // true/false
    JSON_TYPE_STRING,       // string (0-terminated, escapes resolved)
    JSON_TYPE_DOUBLE,       // IEEE 754 binary64
    JSON_TYPE_ARRAY,        // list of unnamed values
    JSON_TYPE_OBJECT,       // list of named values
};

struct json_tok {
    // Determines which field in u is valid.
    enum json_type type;
    union {
        // JSON_TYPE_BOOL:
        bool b;
        // JSON_TYPE_STRING:
        char *str;
        // JSON_TYPE_DOUBLE:
        double d;
        // JSON_TYPE_ARRAY:
        struct json_array *array;
        // JSON_TYPE_OBJECT:
        struct json_object *object;
    } u;
};

struct json_array {
    size_t count;
    struct json_tok *items;
};

struct json_object {
    size_t count;
    struct json_object_entry *items;
};

struct json_object_entry {
    const char *key;
    struct json_tok value;
};

enum json_error {
    JSON_ERR_NONE = 0,
    JSON_ERR_SYNTAX,        // failed due to a syntax error
    JSON_ERR_NOMEM,         // failed due to provided memory not being enough
    JSON_ERR_DEPTH,         // failed due to json_parse_opts.depth exceeded
};

struct json_parse_opts {
    // Maximum nesting of JSON elements allowed. The parser's depth value starts
    // out with 1. Every nested object or array adds 1 to it. If the value is
    // larger than the depth parameter provided here, an error is returned.
    // depth<=0 sets the depth to JSON_DEFAULT_PARSE_DEPTH.
    // depth=INT_MAX sets the maximum allowed depth.
    int depth;

    // msg_cb() is called with the given opaque field. loc is the byte
    // position of the error/warning. (The first error sets json_parse_opts.error
    // before msg_cb is called.)
    // If this is NULL, no messages are returned.
    void (*msg_cb)(void *opaque, size_t loc, const char *msg);

    // Passed as first parameter to msg_cb(), unused otherwise.
    void *msg_cb_opaque;

    // This is always set by json_parse() and related functions. If multiple
    // errors happen, this is set to the first one that was reported.
    enum json_error error;
};

// Default maximum depth for json_parse().
#define JSON_DEFAULT_PARSE_DEPTH 64

// Parse JSON and turn it into a tree of json_tok structs. All tokens are
// allocated from the provided mem pointer. Returns the root token on success,
// returns NULL on error (including if mem_size is too small).
//  text: JSON source
//  mem: scratch memory (will be overwritten and referenced by returned tokens)
//  mem_size: size of mem memory area in bytes that can be used
//  opts: can be NULL
//  returns: root token, or NULL on error
struct json_tok *json_parse(const char *text, void *mem, size_t mem_size,
                            struct json_parse_opts *opts);

// Like json_parse(), but saves some memory by mutating the input text (which is
// why the function has the _destructive suffix). This is done for performance
// reasons and to save copying the input text to the provided memory buffer for
// internal reasons. String fields in the returned json_tok tree will point into
// text buffer.
struct json_tok *json_parse_destructive(char *text, void *mem, size_t mem_size,
                                        struct json_parse_opts *opts);

#endif
