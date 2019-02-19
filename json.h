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
    JSON_TYPE_INVALID,      // does not occur in valid json
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
        // JSON_TYPE_OBJECT:
        struct json_list *list;
    } u;
};

struct json_list {
    // Total number of entries (members/array values).
    size_t count;
    struct json_list_item *head;
};

struct json_list_item {
    // Array entry value or object member value.
    struct json_tok value;
    // JSON_TYPE_OBJECT: the name of the object member
    // JSON_TYPE_ARRAY: NULL
    const char *key;
    // Next element in the array/object order, or NULL on end of list.
    struct json_list_item *next;
};

struct json_msg_cb {
    // cb() is called with the given opaque field. loc is the byte
    // position of the error/warning. You know whether it's an error or
    // warning only after the fact (error => parser returns NULL).
    void (*cb)(void *opaque, size_t loc, const char *msg);
    // For free use by cb().
    void *opaque;
};

// Parse JSON and turn it into a tree of json_tok structs. All tokens are
// allocated from the provided mem pointer. Returns the root token on success,
// returns NULL on error (including if mem_size is too small).
// text is actually mutated during parsing, which is why the function has the
// suffix _destructive. This is done for performance reasons and to avoid
// malloc(). String fields in *dst will point into the mutated text.
//  text: JSON source (mutated by parser, and returned tokens reference it!)
//  mem: scratch memory (will be overwritten and referenced by returned tokens)
//  mem_size: size of mem memory area in bytes that can be used
//  depth: maximum allowed recursion/nested object depth (e.g. 1 allows 1 object)
//  msg_ctx: for receiving parser messages; can be NULL (=> no messages)
//  returns: root token, or NULL on error
struct json_tok *json_parse_destructive(char *text, void *mem, size_t mem_size,
                                        int depth, struct json_msg_cb *msg_ctx);

// Like json_parse_destructive(), but does not mutate the input.
struct json_tok *json_parse(const char *text, void *mem, size_t mem_size,
                            int depth, struct json_msg_cb *msg_ctx);

#endif
