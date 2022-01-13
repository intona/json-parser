/*
 * Copyright (C) 2021 Intona Technology GmbH
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

#ifndef JSON_HELPERS_MALLOC_H_
#define JSON_HELPERS_MALLOC_H_

#include "json.h"
#include "json_helpers.h"

// Parse JSON and turn it into a tree of json_tok structs. The result is a tree
// allocated with malloc(), as if returned by json_copy(). Returns the root
// token on success, returns NULL on error.
// Note that unlike json_parse(), this functions uses recursion in some places.
//  text: JSON source
//  opts: can be NULL; if set, all mrealloc* fields are ignored
//  returns: root token, or NULL on error
struct json_tok *json_parse_malloc(const char *text, struct json_parse_opts *opts);

// Recursively copy the entire tree. The result is allocated with malloc(). Each
// pointer returned by the function is malloc()ed separately:
//
//  - the returned json_tok itself is a single malloc() allocation
//  - JSON_TYPE_STRING, JSON_TYPE_ARRAY, JSON_TYPE_OBJECT each point to
//    separate allocations
//  - json_array.items and json_object.items are separate allocations
//    In general, these arrays can be, but don't need to be, overallocated.
//    Though json_copy() itself makes exactly sized allocations.
//  - json_object_entry.key is a separate allocation
//
// Note how json_parse() does _not_ return such a tree, but json_parse_malloc()
// does.
//
// Normally, none of these fields should be NULL (except the items arrays, if
// the corresponding count is 0). At least json_copy() tolerates disallowed NULL
// pointers in _some_ cases, and just leaves them NULL in the copy.
//
// Returns NULL if memory allocation failed, or if tree is NULL.
struct json_tok *json_copy(const struct json_tok *tree);

// Like json_copy(), except the result is put it into an already allocated
// json_tok field provided by the user (dst). Before writing to *dst,
// json_free_inplace(dst) is called. You can set *dst to all-0 to avoid this.
// If the function fails, *dst is left untouched.
// If src is NULL, *dst is set to all-0 and success is returned.
// Returns success (false if memory allocation failed).
bool json_copy_inplace(struct json_tok *dst, const struct json_tok *src);

// Free the given tree, including the tree token itself, and all memory
// referenced by it. Does nothing if tree==NULL.
void json_free(struct json_tok *tree);

// Like json_free(), but do not free the tree token itself. Only free all
// memory referenced by *tree, and then set *tree to all-0.
// If *tree is already all-0, this is a NOP.
void json_free_inplace(struct json_tok *tree);

// Various accessors for modifying JSON objects easily. The function names
// imply a specific type (e.g. json_set_string() implies JSON_TYPE_STRING).
//
// json_copy() describes memory management of the JSON tree argument "j".
//
// If name is not NULL:
//      If j is an object, look for the given field. If the field does not
//      exist, add it to the object. Deallocate the old value of the field,
//      and copy the new value to it.
//      If j is not an object, NULL is returned.
//
// If name is NULL:
//      Set j itself to the new type. Deallocate the old value in its place.
//
// In all cases, a NULL j parameter is allowed and results in returning NULL.
// They return NULL on other errors as well (malloc() failure).
//
// The _nocopy variants basically move the val argument to the j tree, meaning
// the json_tok is just assigned, but no recursive copy is done (shallow copy).
// On error the user value is not touched. All other functions copy their val
// argument recursively. For numbers/bools/nulls, both variants are equal.
//
// The name argument is always copied if an object entry is inserted.
//
// json_set_array() and json_set_object() do not take a value parameter, but
// simply add/overwrite the field with an empty new array or object.
//
// On success, the json_tok containing the newly placed value is returned.
struct json_tok *json_set_int(struct json_tok *j, const char *name, int val);
struct json_tok *json_set_double(struct json_tok *j, const char *name, double val);
struct json_tok *json_set_string(struct json_tok *j, const char *name, const char *val);
struct json_tok *json_set_string_nocopy(struct json_tok *j, const char *name, char *val);
struct json_tok *json_set_bool(struct json_tok *j, const char *name, bool val);
struct json_tok *json_set_array(struct json_tok *j, const char *name);
struct json_tok *json_set_object(struct json_tok *j, const char *name);
struct json_tok *json_set(struct json_tok *j, const char *name, const struct json_tok *val);
struct json_tok *json_set_nocopy(struct json_tok *j, const char *name, struct json_tok *val);

// Forces the field named by name to be of the given type. (Or clears and resets
// if if it's not the given type, or adds it if it doesn't exist.)
// Basically this acts like json_get() if the types matches,
// or json_object_remove() followed by json_set() (with default init as in
// JSON_MAKE_()) if the type mismatches or the field did not exist.
// This returns NULL only if memory allocation failed, or if j is not an OBJECT
// while name is not NULL (or if type is invalid).
struct json_tok *json_get_or_add_typed(struct json_tok *j, const char *name,
                                       enum json_type type);

// Remove the named entry in object j. Returns false if not an object or name
// not found. This is O(1), but changes the order of elements (note that the
// field order in JSON objects is not supposed to matter).
bool json_object_remove(struct json_tok *j, const char *name);

// If j is an array, copy val, append it to the array, and return the pointer to
// the new item. If j is not an array or an error happened, return NULL.
struct json_tok *json_array_append(struct json_tok *j, const struct json_tok *val);

// Like json_array_append(), but insert it at index, such that it will be the
// index of the newly inserted item. index can be j->u.array->count, in which
// case it behaves exactly like json_array_append().
struct json_tok *json_array_insert(struct json_tok *j, size_t index,
                                   const struct json_tok *val);

// Like json_array_insert(), but do not recursively copy the val argument.
struct json_tok *json_array_insert_nocopy(struct json_tok *j, size_t index,
                                          struct json_tok *val);

// Set the given array index to a copy of the given value. Deallocate the old
// value. Return NULL on error (memory allocation failure, not an array, index
// out of bounds).
struct json_tok *json_array_set(struct json_tok *j, size_t index,
                                const struct json_tok *val);

// Remove the array item with the given index. Returns false if not an array or
// index is out of bounds.
bool json_array_remove(struct json_tok *j, size_t index);

// Convert the given JSON value to a string. The string is allocated with
// malloc() and can be free'd with free().
// This uses recursion. May contain error notices on invalid json_types.
// Returns NULL on malloc() failure.
char *json_to_string(struct json_tok *tree);

#endif
