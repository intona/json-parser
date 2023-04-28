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
    JSON_ERR_INVAL,         // some kind of API usage error, or internal error
};

// Warning:
// - To remain compatible with possible future extensions, you should always
//   zero-init the entire struct.
// - All callbacks must return normally. If any of them return by longjmp() or
//   throw C++ exceptions, the behavior is undefined. Callbacks are not expected
//   to write to json_parse_opts, the input, the memory, etc. passed to the
//   parser functions.
struct json_parse_opts {
    // Maximum nesting of JSON elements allowed. The parser's depth value starts
    // out with 1. Every nested object or array adds 1 to it. If the value is
    // larger than the depth parameter provided here, an error is returned.
    // depth<=0 sets the depth to JSON_DEFAULT_PARSE_DEPTH.
    // depth=INT_MAX sets the maximum allowed depth.
    // Note if json_parse_malloc() is used (or mrealloc in some cases), the
    // entire stack is pre-allocated according to the depth field, so you
    // shouldn't set this to a very high value, and INT_MAX intentionally fails.
    int depth;

    // msg_cb() is called with the given opaque field. loc is the byte
    // position of the error/warning. (The first error sets json_parse_opts.error
    // before msg_cb is called.)
    // If this is NULL, no messages are returned.
    void (*msg_cb)(void *opaque, size_t loc, const char *msg);

    // Passed as first parameter to msg_cb(), unused otherwise.
    void *msg_cb_opaque;

    // If set to true, accept various syntax that is not covered by standard
    // JSON. If false (the default), such extensions are rejected as errors.
    bool enable_extensions;

    // This is always set by json_parse() and related functions. If multiple
    // errors happen, this is set to the first one that was reported.
    enum json_error error;

    // Optional memory allocation function. If set to non-NULL, the JSON AST
    // returned by the parser is allocated using this function, instead of the
    // memory provided to the json_parse group of functions.
    // Please use json_parse_malloc() instead, which is a wrapper around this,
    // and uses system realloc() while taking care of the messy details.
    //
    // For sz!=0, mrealloc(_, p, sz) must behave exactly as standard C
    // realloc(p, sz) (though errno does not need to be set).
    // For sz==0, mrealloc(_, p, 0) must behave like standard C free(p). (Note
    // that realloc(p, 0) is implementation defined, and does not necessarily
    // free the memory! The even less portable variant mrealloc(_, NULL, 0) is
    // also called and should do nothing.) Return NULL in this case.
    // The following changes for the json_parse*() API:
    //  - struct json_tok values and all memory they reference are allocated
    //    with mrealloc()
    //  - you don't need to pass mem/mem_size to the parser; if mem_size==0,
    //    the parser will allocate a shadow stack with mrealloc; if not, mem
    //    is used for the shadow stack; in all cases the parsing function still
    //    has constant C stack usage
    // The returned pointer must have suitable alignment (standard realloc()
    // takes care of this).
    // Arrays/objects are over-allocated to power of 2 boundaries, which is due
    // to pre-allocation during parsing, and trades higher internal
    // fragmentation for speed.
    // The callback must return normally. If it returns by longjmp() or throws
    // C++ exceptions, the behavior is undefined. With json_pull*(), the
    // callback is not allowed to call these functions in a reentrant way.
    void *(*mrealloc)(void *opaque, void *p, size_t sz);

    // Passed as first parameter to mrealloc(), unused otherwise.
    void *mrealloc_opaque;

    // If parsing fails with mrealloc set, the result must be free'd again. Then
    // the parser sets this field to the (possibly incomplete) JSON tree that
    // needs to be freed.  It needs to be done by the caller for various funny
    // reasons.
    // json_parse_malloc() does this automatically.
    struct json_tok *mrealloc_waste;
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
// Setting opts->mrealloc disables this (will behave exactly like json_parse()).
struct json_tok *json_parse_destructive(char *text, void *mem, size_t mem_size,
                                        struct json_parse_opts *opts);

// Opaque state for the pull parser API.
struct json_state;

// Initialize the pull parser. The returned json_state is allocated from mem.
// The arguments are like json_parse_destructive(). All pointers are referenced
// by json_state, so they must remain valid and none of the memory can be
// changed by the caller as long as the json_state is used.
// Like with json_parse(), mem_size limits the effective stack depth in addition
// to opts->depth. It will use less memory than json_parse_destructive(), as it
// doesn't have to allocate tokens.
// Note: mrealloc is not supported (no real reason, it's trivial, but seems to
//       have little usefulness, and wasn't what the author needed)
//  text, mem, mem_size: like in json_parse_destructive()
//  opts: this cannot be NULL
//  returns: state for use with json_parser_pull(), NULL if out of memory to
//           allocate the state, or mrealloc is set
struct json_state *json_pull_init_destructive(char *text,
                                              void *mem, size_t mem_size,
                                              struct json_parse_opts *opts);

enum json_pull {
    JSON_PULL_ERROR = 0,    // an error happened, always 0, see opts->error
    JSON_PULL_END,          // end of JSON input reached (redundant, because the
                            // caller is supposed to track nesting of tokens)
    JSON_PULL_TOK,          // a token was parsed (json_tok arg is set)
    JSON_PULL_KEY,          // an object key was parsed (json_tok arg is set)
                            // (needed because there is no object key token)
    JSON_PULL_CLOSE_LIST,   // an array or object was closed
};

// Read the next token from the parser. The JSON_PULL_* value tells the caller
// what was parsed. The ERROR and END states end parsing and never change.
// Strings returned in *out are valid until the next call, and point into the
// user memory or the JSON input text. Returned JSON_TYPE_ARRAY/JSON_TYPE_OBJECT
// tokens are dummies with 0 items.
// Objects in particular return sequences of JSON_PULL_KEY/JSON_PULL_TOK pairs
// in guaranteed order: the first token is always JSON_PULL_KEY,
// JSON_PULL_CLOSE_LIST, or JSON_PULL_ERROR; the second token is always
// JSON_PULL_TOK or JSON_PULL_ERROR; then the same again.
// JSON_PULL_KEY will set out to JSON_TYPE_STRING. This is guaranteed and the
// caller can just access out->u.str directly after checking that JSON_PULL_KEY
// was returned. Note that it becomes invalid on the next pull call.
//  st: state allocated with json_pull_init_destructive()
//  out: written by the function; valid if JSON_PULL_TOK or JSON_PULL_KEY was
//       returned, otherwise the contents are undefined; treat any referenced
//       memory as read-only; strictly becomes invalid on the next call
//  returns: parser state, JSON_PULL_TOK/KEY if *out was set to a valid value
enum json_pull json_pull_next(struct json_state *st, struct json_tok *out);

// Skip all tokens until the current array or object ends. Error information is
// returned with the next json_pull_next() call (and opts->msg_cb, if set).
// Does nothing if not in an array/object.
void json_pull_skip_nested(struct json_state *st);

#endif
