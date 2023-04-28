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

struct json_state {
    char *start;
    char *text;
    char *mem_ptr;          // offset for allocations
    char *stack_ptr;        // offset for stack
    char *stack_start;
    bool top_empty;
    bool destructive;
    bool pull_mode;
    bool initialized;
    bool pull_in_object;
    bool end_reached;
    int idepth;             // inverse nesting depth
    struct curlist *top;    // top-most list element (NULL if none)
    struct json_parse_opts *opts;
    char *pin_buf;          // streaming input mode: buffer to keep
    size_t loc_offs;        // streaming input mode: error location reporting
    union {
        struct json_array arr;
        struct json_object obj;
    } dummy; // for pull mode, assumes same zero-init for both types
};

struct curlist {
    struct json_tok *tok;
    size_t prev_offset : (sizeof(size_t) * CHAR_BIT - 1);
    bool is_object : 1;
};

union heap_align {
    struct json_object_entry oe;
    struct json_tok t;
    struct json_array a;
    struct json_object o;
};

#define IS_POW_2(x) ((x) > 0 && !((x) & (x - 1)))
#define MIN(a, b) ((a) > (b) ? (b) : (a))

static void json_err_val(struct json_state *st, int err, const char *msg)
{
    if (st->opts->error == JSON_ERR_NOMEM)
        return;
    if (!st->opts->error)
        st->opts->error = err;
    if (st->opts->msg_cb) {
        st->opts->msg_cb(st->opts->msg_cb_opaque,
                         st->loc_offs + ((st)->text - (st)->start), msg);
    }
}

static void json_err(struct json_state *st, const char *msg)
{
    json_err_val(st, JSON_ERR_SYNTAX, msg);
}

static void json_err_oom(struct json_state *st)
{
    json_err_val(st, JSON_ERR_NOMEM, "out of memory");
}

static void *json_stack_alloc(struct json_state *st, size_t size, size_t align)
{
    assert(IS_POW_2(align));
    size = (size + (align - 1)) & ~(align - 1);
    size_t disalign = (uintptr_t)st->stack_ptr & (align - 1);
    if (disalign)
        disalign = align - disalign;
    if (size + disalign > st->mem_ptr - st->stack_ptr) {
        json_err_oom(st);
        return NULL;
    }
    void *res = st->stack_ptr + disalign;
    assert(!((uintptr_t)res & (align - 1)));
    st->stack_ptr += size + disalign;
    return res;
}

// Available in malloc-mode only. Wraps mrealloc().
static void *json_mrealloc(struct json_state *st, void *p, size_t size)
{
    if (!st->opts->mrealloc || (!p && !size))
        return NULL;
    void *res = st->opts->mrealloc(st->opts->mrealloc_opaque, p, size);
    if (size) {
        if (res) {
            memset(res, 0, size); // makes error handling less of a PITA
        } else {
            json_err_oom(st);
        }
    }
    return res;
}

static void *json_alloc_align(struct json_state *st, size_t size, size_t align)
{
    assert(IS_POW_2(align));
    size_t alm = align - 1;

    if (st->opts->mrealloc)
        return json_mrealloc(st, NULL, size);

    size_t disalign = (((uintptr_t)st->mem_ptr & alm) - (size & alm)) & alm;
    size_t free = st->mem_ptr - st->stack_ptr;
    if (size > free || size + disalign > free || !size) {
        json_err_oom(st);
        return NULL;
    }

    st->mem_ptr = st->mem_ptr - (size + disalign);
    assert(!((uintptr_t)st->mem_ptr & alm));
    return st->mem_ptr;
}

static void *json_alloc(struct json_state *st, size_t size)
{
    return json_alloc_align(st, size, _Alignof(union heap_align));
}

// Reallocate the array arr to add an item at the end. On failure, return NULL
// and log the error. On success, return the reallocated array (the input arr
// pointer may become invalid), on failure return NULL (input arr untouched).
// This assumes arr is pre-allocated in the way this function does.
// Only works if st->opts->mrealloc is set.
static void *append_array(struct json_state *st, void *arr, size_t count,
                          size_t item_size)
{
    assert(st->opts->mrealloc);
    // If count is non-0 and not a power of 2, we must be within pre-allocated
    // bounds, so there is enough space.
    if ((!count || IS_POW_2(count))) {
        if (count < ((size_t)-1) / item_size / 2) {
            arr = st->opts->mrealloc(st->opts->mrealloc_opaque, arr,
                                     (count ? count * 2 : 2) * item_size);
        } else {
            arr = NULL;
        }
    }

    if (!arr)
        json_err_oom(st);

    return arr;
}

static bool parse_value(struct json_state *st, struct json_tok *tok);
static char *parse_str(struct json_state *st);

// Ensures st->text has at least JSON_LOOKAHEAD_SIZE bytes. Meaningful only
// in streaming input mode. After the lookahead size, the input either continues,
// or is cut short with a \0. If pin_buf is used (string tokens), the lookahead
// may be lower, and the caller has to take care of it.
// A return value !=0 means more input _may_ have been read, but if it didn't,
// all remaining input is visible, and the next call is guaranteed to return 0.
//  returns: input move offset, means the remaining input was moved by this many
//           bytes to the start of the buffer, and the rest of the buffer
//           possibly filled
static size_t lookahead(struct json_state *st)
{
    if (!st->opts->read_input)
        return 0;
    char *end = st->start + st->opts->read_input_buffer_size;
    if (end - st->text >= JSON_LOOKAHEAD_SIZE)
        return 0;
    char *pin = st->pin_buf ? st->pin_buf : st->text;
    size_t move = pin - st->start;
    size_t oldsz = end - st->text;
    memmove(st->start, pin, end - pin);
    st->pin_buf = st->pin_buf ? st->pin_buf - move : NULL;
    st->text -= move;
    st->loc_offs += move;
    char *tend = st->text + oldsz;
    if (end != tend && !st->end_reached) {
        size_t amount = end - tend;
        int r = st->opts->read_input(st->opts->read_input_opaque, tend, amount);
        if (r >= 0) {
            tend += r;
            if (r < amount)
                st->end_reached = true;
        } else {
            json_err_val(st, JSON_ERR_IO, "read error");
        }
    }
    *tend = '\0'; // buffer is over-allocated by 1 byte for this
    return move;
}

static void skip_ws(struct json_state *st)
{
    for (;;) {
        lookahead(st);
        st->text += strspn(st->text, " \t\r\n");
        if (st->opts->enable_extensions &&
            st->text[0] == '/' && st->text[1] == '/')
        {
            st->text += strcspn(st->text, "\n");
            continue;
        }
        break;
    }
}

static bool skip_str(struct json_state *st, const char *str)
{
    size_t str_len = strlen(str);
    lookahead(st);
    if (strncmp(st->text, str, str_len) != 0)
        return false;
    st->text += str_len;
    return true;
}

static bool push_list_head(struct json_state *st, struct json_tok *tok)
{
    if (!st->idepth) {
        json_err_val(st, JSON_ERR_DEPTH, "maximum nesting depth reached");
        return false;
    }

    struct curlist *cur = json_stack_alloc(st, sizeof(*cur), _Alignof(*cur));
    if (!cur)
        return false;

    cur->prev_offset = st->top ? (char *)cur - (char *)st->top : 0;
    cur->is_object = tok->type == JSON_TYPE_OBJECT;

    st->top = cur;
    st->idepth--;

    if (st->pull_mode) {
        if (tok->type == JSON_TYPE_ARRAY)
            tok->u.array = &st->dummy.arr;
        if (tok->type == JSON_TYPE_OBJECT)
            tok->u.object = &st->dummy.obj;
    } else {
        cur->tok = tok;
        if (tok->type == JSON_TYPE_OBJECT) {
            tok->u.object = json_alloc(st, sizeof(*tok->u.object));
            if (!tok->u.object)
                return false;
            *tok->u.object = (struct json_object){0};
        } else if (tok->type == JSON_TYPE_ARRAY) {
            tok->u.array = json_alloc(st, sizeof(*tok->u.array));
            if (!tok->u.array)
                return false;
            *tok->u.array = (struct json_array){0};
        }
    }

    st->top_empty = true;

    return true;
}

// Returns true if there's an item to parse. False on error or end of list.
static bool parse_list_next(struct json_state *st)
{
    struct curlist *cur = st->top;

    char *endsym = cur->is_object ? "}" : "]";
    skip_ws(st);

    if (skip_str(st, endsym)) {
        // Continue parsing into the previous list (returning from recursion).
        st->top = (struct curlist *)
                    (cur->prev_offset ? (char *)cur - cur->prev_offset : NULL);
        st->idepth++;
        st->top_empty = false;

        // Restore stack to before the previous push_list_head(). This can be
        // right after the st->top item, but if the previous list has pushed
        // items on the stack, it has to point at the end of the last item.
        st->stack_ptr = st->top ? (char *)(st->top + 1) : st->stack_start;

        if (!st->opts->mrealloc && !st->pull_mode) {
            // Restore stack from previous list (it always has an item, cur).
            if (st->top) {
                struct json_tok *tok = st->top->tok;
                void *items = NULL;
                size_t sz = 0;
                if (tok->type == JSON_TYPE_OBJECT) {
                    items = tok->u.object->items;
                    sz = tok->u.object->count * sizeof(tok->u.object->items[0]);
                } else if (tok->type == JSON_TYPE_ARRAY) {
                    items = tok->u.array->items;
                    sz = tok->u.array->count * sizeof(tok->u.array->items[0]);
                }
                st->stack_ptr = (char *)items + sz;
            }

            // At the end of the parsing loop, all items will have been
            // "pushed" to the stack. Consistent json_stack_alloc() use
            // ensures the items are placed in memory like a C array.
            struct json_tok *tok = cur->tok;

            void *items = NULL;
            size_t sz = 0;
            if (tok->type == JSON_TYPE_OBJECT) {
                items = tok->u.object->items;
                sz = tok->u.object->count * sizeof(tok->u.object->items[0]);
            } else if (tok->type == JSON_TYPE_ARRAY) {
                items = tok->u.array->items;
                sz = tok->u.array->count * sizeof(tok->u.array->items[0]);
            }

            void *nitems = NULL;
            if (sz) {
                nitems = json_alloc(st, sz);
                if (!nitems)
                    return false; // does not happen in practice
                memmove(nitems, items, sz); // may overlap
            }

            if (tok->type == JSON_TYPE_OBJECT) {
                tok->u.object->items = nitems;
            } else if (tok->type == JSON_TYPE_ARRAY) {
                tok->u.array->items = nitems;
            }
        }

        return false;
    }

    if (!st->top_empty) {
        skip_ws(st);
        if (!skip_str(st, ",")) {
            json_err(st, "',' expected");
            return false;
        }

        if (st->opts->enable_extensions) {
            skip_ws(st);
            // let it see and process endsym
            // relying on tail call optimization (no recursion) => no ugly goto
            if (st->text[0] == endsym[0])
                return parse_list_next(st);
        }
    }

    st->top_empty = false;

    return true;
}

static struct json_object_entry *alloc_obj_item(struct json_state *st,
                                                struct json_object *obj)
{
    struct json_object_entry *e;
    if (st->opts->mrealloc) {
        void *new = append_array(st, obj->items, obj->count,
                                    sizeof(obj->items[0]));
        if (!new)
            return NULL;
        obj->items = new;
        e = &obj->items[obj->count];
    } else {
        e = json_stack_alloc(st, sizeof(*e), _Alignof(*e));
        if (!e)
            return NULL;
        if (!obj->count)
            obj->items = e;
    }
    *e = (struct json_object_entry){0};
    obj->count++;
    return e;
}

static char *parse_obj_key(struct json_state *st)
{
    skip_ws(st);
    char *key = parse_str(st);
    if (!key)
        json_err(st, "object member name expected (quoted string)");
    return key;
}

static bool parse_obj_value(struct json_state *st, struct json_tok *val)
{
    skip_ws(st);
    if (!skip_str(st, ":")) {
        json_err(st, "':' after object member name expected");
        return false;
    }

    bool r = parse_value(st, val);
    if (!r)
        json_err(st, "object value expected");
    return r;
}

static bool parse_obj(struct json_state *st, struct json_object_entry *e)
{
    e->key = parse_obj_key(st);
    if (!e->key)
        return false;
    return parse_obj_value(st, &e->value);
}

static struct json_tok *alloc_arr_item(struct json_state *st,
                                       struct json_array *arr)
{
    struct json_tok *item_tok;
    if (st->opts->mrealloc) {
        void *new = append_array(st, arr->items, arr->count, sizeof(arr->items[0]));
        if (!new)
            return NULL;
        arr->items = new;
        item_tok = &arr->items[arr->count];
    } else {
        item_tok = json_stack_alloc(st, sizeof(*item_tok), _Alignof(*item_tok));
        if (!item_tok)
            return NULL;
        if (!arr->count)
            arr->items = item_tok;
    }
    *item_tok = (struct json_tok){0};
    arr->count++;
    return item_tok;
}

static bool parse_arr(struct json_state *st, struct json_tok *e)
{
    bool r = parse_value(st, e);
    if (!r)
        json_err(st, "array value expected");
    return r;
}

static bool parse_ast(struct json_state *st, struct json_tok *res)
{
    if (!parse_value(st, res))
        return false;

    while (st->top) {
        if (!parse_list_next(st)) {
            if (st->opts->error)
                return false;
            continue;
        }

        struct json_tok *tok = st->top->tok;
        if (tok->type == JSON_TYPE_OBJECT) {
            struct json_object_entry *obj = alloc_obj_item(st, tok->u.object);
            if (!obj || !parse_obj(st, obj))
                return false;
        } else if (tok->type == JSON_TYPE_ARRAY) {
            struct json_tok *e = alloc_arr_item(st, tok->u.array);
            if (!e || !parse_arr(st, e))
                return false;
        }
    }

    return true;
}

// Numeric escapes, e.g. "\u005C", without the "\u" prefix.
static int parse_numeric_escape(struct json_state *st)
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

// How many bytes the given codepoint needs to be encoded as UTF-8 (0=error).
static size_t utf8_len(uint32_t cp)
{
    if (cp >= 0xD800 && cp <= 0xDFFF) {
        return 0; // invalid surrogate pair codepoints
    } else if (cp <= 0x7F) {
        return 1;
    } else if (cp <= 0x7FF) {
        return 2;
    } else if (cp <= 0xFFFF) {
        return 3;
    } else if (cp <= 0x10FFFF) {
        return 4;
    } else {
        return 0; // invalid high codepoints
    }
}

// Encode the given codepoint as UTF-8, write to dst, and return the number of
// bytes written, which is utf8_len() bytes, at most 4 bytes, 0 on error.
static size_t encode_utf8(char *dst, uint32_t cp)
{
    size_t len = utf8_len(cp);

    if (len == 1) {
        *dst++ = cp;
    } else if (len == 2) {
        *dst++ = 0xC0 | (cp >> 6);
        *dst++ = 0x80 | (cp & 0x3F);
    } else if (len == 3) {
        *dst++ = 0xE0 | (cp >> 12);
        *dst++ = 0x80 | ((cp >> 6) & 0x3F);
        *dst++ = 0x80 | (cp & 0x3F);
    } else if (len == 4) {
        *dst++ = 0xF0 | (cp >> 18);
        *dst++ = 0x80 | ((cp >> 12) & 0x3F);
        *dst++ = 0x80 | ((cp >> 6) & 0x3F);
        *dst++ = 0x80 | (cp & 0x3F);
    }

    return len;
}

// dst==NULL to determine the dst allocation size.
// In-place parsing uses dst==st->text (result is always shorter than input).
// st->text is advanced if dst!=NULL or if an error happens.
// Returns dst allocation size (final string length + 1), 0 on error.
static size_t do_parse_str(struct json_state *st, char *dst)
{
    if (st->text[0] != '"')
        return 0;
    st->pin_buf = st->text;
    size_t len = 0;
    st->text += 1;
    while (1) {
        lookahead(st);
        unsigned char c = st->text[0];
        if (!c) {
            json_err(st, "closing '\"' missing in string literal");
            return 0;
        }
        st->text += 1;
        if (c == '"') {
            len += 1;
            if (dst) {
                *dst = '\0';
            } else {
                st->text = st->pin_buf;
            }
            st->pin_buf = NULL;
            return len;
        } else if (c <= 0x1F) {
            json_err(st, "unescaped control character in string literal");
            return 0;
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
                    return 0;
                uint32_t cp = v;
                // Surrogate pairs for characters outside of the BMP.
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    if (!skip_str(st, "\\u")) {
                        json_err(st, "missing low surrogate pair");
                        return 0;
                    }
                    v = parse_numeric_escape(st);
                    if (v < 0)
                        return 0;
                    if (v < 0xDC00 || v > 0xDFFF) {
                        json_err(st, "invalid low surrogate pair");
                        return 0;
                    }
                    cp = ((cp & 0x3FF) << 10) + (v & 0x3FF) + 0x10000;
                }
                // What should \u0000 do? Just error out.
                if (cp == 0) {
                    json_err(st, "0 byte escape rejected");
                    return 0;
                }
                size_t sz = 0;
                if (dst) {
                    // Note: in-place encoding is still possible. In the worst
                    // case, we write 4 bytes, while the escape syntax uses 6
                    // bytes.
                    sz = encode_utf8(dst, cp);
                    dst += sz;
                } else {
                    sz = utf8_len(cp);
                }
                if (!sz) {
                    json_err(st, "invalid unicode escape");
                    return 0;
                }
                len += sz;
                continue;
            }
            default:
                json_err(st, "unknown escape");
                return 0;
            }
        }
        len += 1;
        if (dst)
            *dst++ = c;
    }
}

static char *parse_str(struct json_state *st)
{
    if (st->destructive) {
        char *dst = st->text; // Do it in-place.
        return do_parse_str(st, dst) ? dst : NULL;
    }

    size_t len = do_parse_str(st, NULL);
    if (!len)
        return NULL;
    char *dst = json_alloc_align(st, len, 1);
    if (!dst)
        return NULL;
    len = do_parse_str(st, dst);
    assert(len); // it's impossible for the second pass to fail
    return dst;
}

static bool parse_number(struct json_state *st, struct json_tok *tok)
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
static bool parse_value(struct json_state *st, struct json_tok *tok)
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
    case '"':
        tok->type = JSON_TYPE_STRING;
        tok->u.str = parse_str(st);
        return !!tok->u.str;
    default: ;
        // The only valid other thing could be a number.
        if (!parse_number(st, tok))
            break;
        return true;
    }

    json_err(st, "character does not start a valid JSON token");
    return false;
}

static void common_init(struct json_state *st)
{
    st->opts->error = JSON_ERR_NONE;
    st->idepth =
        (st->opts->depth > 0 ? st->opts->depth : JSON_DEFAULT_PARSE_DEPTH) - 1;
}

static struct json_tok *do_parse(char *text, void *mem, size_t mem_size,
                                 struct json_parse_opts *opts, bool copy)
{
    struct json_tok *res = NULL;
    void *stack_alloc = NULL;
    struct json_state *st = &(struct json_state){
        .start = text,
        .text = text,
        .stack_ptr = mem,
        .destructive = !(copy || (opts && opts->mrealloc)),
        .opts = opts ? opts : &(struct json_parse_opts){0},
    };

    common_init(st);

    if (!mem_size && st->opts->mrealloc) {
        // Estimate needed shadow-stack size.
        if (st->idepth + 1 < INT_MAX / (sizeof(struct curlist))) {
            mem_size = (st->idepth + 1) * sizeof(struct curlist);
            stack_alloc = json_mrealloc(st, NULL, mem_size);
        }
        if (!stack_alloc) {
            json_err_val(st, JSON_ERR_NOMEM, "out of memory (allocating stack)");
            goto done;
        }
        st->stack_ptr = stack_alloc;
    }

    st->mem_ptr = st->stack_ptr + mem_size;
    st->stack_start = st->stack_ptr;

    if (st->opts->read_input) {
        //assert(st->opts->read_input_buffer_size >= JSON_MIN_READ_BUFFER);
        assert(!text);
        size_t sz = MIN((size_t)-1 - 1, st->opts->read_input_buffer_size) + 1;
        st->start = json_alloc_align(st, sz, 1);
        if (!st->start)
            assert(0);
        st->text = st->start + st->opts->read_input_buffer_size; // empty
    }

    st->end_reached = !st->opts->read_input;

    res = json_alloc(st, sizeof(*res));
    if (!res)
        goto done;

    if (!parse_ast(st, res))
        goto done;

    // No trailing non-whitespace text allowed.
    skip_ws(st);
    if (st->text[0]) {
        json_err(st, "trailing text at end of JSON value");
        goto done;
    }

done:
    if (st->opts->error) {
        st->opts->mrealloc_waste = st->opts->mrealloc ? res : NULL;
        res = NULL;
    }
    json_mrealloc(st, stack_alloc, 0);
    if (st->opts->read_input)
        json_mrealloc(st, st->start, 0);
    return res;
}

struct json_tok *json_parse_destructive(char *text, void *mem, size_t mem_size,
                                        struct json_parse_opts *opts)
{
    return do_parse(text, mem, mem_size, opts, false);
}

struct json_tok *json_parse(const char *text, void *mem, size_t mem_size,
                            struct json_parse_opts *opts)
{
    return do_parse((char *)text, mem, mem_size, opts, true);
}

struct json_state *json_pull_init_destructive(char *text,
                                              void *mem, size_t mem_size,
                                              struct json_parse_opts *opts)
{
    if (!opts)
        return NULL;

    struct json_state st_boot = {
        .start = text,
        .text = text,
        .destructive = true,
        .pull_mode = true,
        .stack_ptr = mem,
        .stack_start = mem,
        .mem_ptr = (char *)mem + mem_size,
        .opts = opts,
    };

    common_init(&st_boot);

    if (st_boot.opts->mrealloc) {
        json_err_val(&st_boot, JSON_ERR_INVAL, "mrealloc not supported");
        return NULL;
    }

    struct json_state *st = json_alloc(&st_boot, sizeof(*st));
    if (st)
        *st = st_boot;
    return st;
}

enum json_pull json_pull_next(struct json_state *st, struct json_tok *out)
{
    if (st->opts->error)
        goto error;

    if (!st->initialized) {
        // First token.
        st->initialized = true;
        if (!parse_value(st, out))
            goto error;
        return JSON_PULL_TOK;
    }

    if (st->pull_in_object) {
        st->pull_in_object = false;
        if (!parse_obj_value(st, out))
            goto error;
        return JSON_PULL_TOK;
    }

    if (!st->top) {
        skip_ws(st);
        if (st->text[0]) {
            json_err(st, "trailing text at end of JSON value");
            goto error;
        }
        return JSON_PULL_END;
    }

    if (!parse_list_next(st)) {
        if (st->opts->error)
            goto error;
        return JSON_PULL_CLOSE_LIST;
    }

    if (st->top->is_object) {
        *out = (struct json_tok){JSON_TYPE_STRING, .u.str = parse_obj_key(st)};
        if (!out->u.str)
            goto error;
        st->pull_in_object = true;
        return JSON_PULL_KEY;
    } else {
        if (!parse_arr(st, out))
            goto error;
        return JSON_PULL_TOK;
    }

error:
    assert(st->opts->error);
    return JSON_PULL_ERROR;
}

void json_pull_skip_nested(struct json_state *st)
{
    if (!st->top)
        return;

    // JSON_PULL_CLOSE_LIST will change idepth.
    int depth = st->idepth;
    while (st->idepth <= depth) {
        struct json_tok tok;
        enum json_pull r = json_pull_next(st, &tok);
        if (r != JSON_PULL_TOK && r != JSON_PULL_KEY && r != JSON_PULL_CLOSE_LIST)
            return;
    }
}
