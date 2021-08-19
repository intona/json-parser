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

#ifndef JSON_HELPERS_H_
#define JSON_HELPERS_H_

#include "json.h"

// Various accessors for traversing JSON objects easily. The function names
// imply a specific type (e.g. json_get_string() implies JSON_TYPE_STRING).
// On error, they return the def parameter (or NULL if there is no def
// parameter).
//
// If name is not NULL:
//      If j is an object, look for the given field. If the field is present in
//      the object, and the field value has the correct type, return it.
//      Otherwise, return the def parameter.
// If name is NULL:
//      If j has the implied type, return its value.
//      Otherwise, return the def parameter.
//
// In all cases, a NULL j parameter is allowed and results in returning def.
//
// Object lookup is O(n).
int json_get_int(struct json_tok *j, const char *name, int def);
double json_get_double(struct json_tok *j, const char *name, double def);
const char *json_get_string(struct json_tok *j, const char *name,
                                  const char *def);
bool json_get_bool(struct json_tok *j, const char *name, bool def);
struct json_array *json_get_array(struct json_tok *j, const char *name);
struct json_object *json_get_object(struct json_tok *j, const char *name);
struct json_tok *json_get(struct json_tok *j, const char *name);

// Return the index of the field with the given name. If j is not an object, or
// if name could not be found, return -1. This is O(n).
ptrdiff_t json_object_find(struct json_tok *j, const char *name);

// Return the array item at the given index. If j is not an array, or the index
// is out of bounds, return NULL.
struct json_tok *json_array_get(struct json_tok *j, size_t index);

// C99 macros for constructing stack json_toks.
#define JSON_MAKE_NULL()  (&(struct json_tok){.type = JSON_TYPE_NULL})
#define JSON_MAKE_BOOL(v) (&(struct json_tok){.type = JSON_TYPE_BOOL,   .u.b = (v)})
#define JSON_MAKE_STR(v)  (&(struct json_tok){.type = JSON_TYPE_STRING, .u.str = (v)})
#define JSON_MAKE_NUM(v)  (&(struct json_tok){.type = JSON_TYPE_DOUBLE, .u.d = (v)})
#define JSON_MAKE_OBJ()   (&(struct json_tok){.type = JSON_TYPE_OBJECT, \
                            .u.object = &(struct json_object){0}})
#define JSON_MAKE_ARR()   (&(struct json_tok){.type = JSON_TYPE_ARRAY, \
                            .u.array = &(struct json_array){0}})

#endif
