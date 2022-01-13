#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "json_helpers_malloc.h"
#include "json_out.h"

static void *mrealloc(void *opaque, void *p, size_t sz)
{
    if (!sz) {
        free(p);
        return NULL;
    }
    return realloc(p, sz);
}

struct json_tok *json_parse_malloc(const char *text, struct json_parse_opts *opts)
{
    struct json_tok *res = NULL;
    void *mem = NULL;
    size_t text_len = strlen(text);
    struct json_parse_opts s_opts = {0};
    if (opts)
        s_opts = *opts;

    s_opts.mrealloc = mrealloc;
    if (s_opts.depth <= 0)
        s_opts.depth = JSON_DEFAULT_PARSE_DEPTH; // for size calculation below

    size_t mem_size = text_len + 1;

    // Estimate needed shadow-stack size (this is a guess based on json.c
    // internals). On overflow let malloc() fail.
    if (s_opts.depth < ((size_t)-1 - mem_size - 16) / (sizeof(void *) * 2)) {
        mem_size = 16 + s_opts.depth * sizeof(void *) * 2;
    } else {
        mem_size = (size_t)-1;
    }

    mem = malloc(mem_size);
    if (!mem) {
        s_opts.error = JSON_ERR_NOMEM;
        goto done;
    }

    res = json_parse(text, mem, mem_size, &s_opts);

done:
    free(mem);
    json_free(s_opts.mrealloc_waste);
    // Copy back any other results passed through json_parse_opts.
    if (opts)
        opts->error = s_opts.error;
    return res;
}

static void free_tok(struct json_tok *tree)
{
    switch (tree->type) {
    case JSON_TYPE_STRING:
        free(tree->u.str);
        break;
    case JSON_TYPE_ARRAY: {
        struct json_array *arr = tree->u.array;
        if (arr) {
            for (size_t n = 0; n < arr->count; n++)
                free_tok(&arr->items[n]);
            free(arr->items);
            free(arr);
        }
        break;
    }
    case JSON_TYPE_OBJECT: {
        struct json_object *obj = tree->u.object;
        if (obj) {
            for (size_t n = 0; n < obj->count; n++) {
                free_tok(&obj->items[n].value);
                free((char *)obj->items[n].key);
            }
            free(obj->items);
            free(obj);
        }
        break;
    }
    default: ;
    }
}

void json_free_inplace(struct json_tok *tree)
{
    if (tree) {
        free_tok(tree);
        *tree = (struct json_tok){0};
    }
}

void json_free(struct json_tok *tree)
{
    if (tree)
        free_tok(tree);
    free(tree);
}

static bool json_do_copy(struct json_tok *dst, const struct json_tok *src)
{
    if (!dst || !src) {
        if (dst)
            *dst = (struct json_tok){0};
        return false;
    }

    *dst = *src;

    switch (src->type) {
    case JSON_TYPE_STRING:
        if (src->u.str) {
            dst->u.str = strdup(src->u.str);
            if (!dst->u.str)
                goto error;
        }
        break;
    case JSON_TYPE_ARRAY: {
        struct json_array *arr = src->u.array;
        if (arr) {
            dst->u.array = calloc(1, sizeof(struct json_array));
            if (!dst->u.array)
                goto error;
            struct json_array *darr = dst->u.array;
            darr->items = calloc(arr->count, sizeof(struct json_tok));
            if (!darr->items)
                goto error;
            darr->count = arr->count;

            for (size_t n = 0; n < arr->count; n++) {
                if (!json_do_copy(&darr->items[n], &arr->items[n]))
                    goto error;
            }
        }
        break;
    }
    case JSON_TYPE_OBJECT: {
        struct json_object *obj = src->u.object;
        if (obj) {
            dst->u.object = calloc(1, sizeof(struct json_object));
            if (!dst->u.object)
                goto error;
            struct json_object *dobj = dst->u.object;
            dobj->items = calloc(obj->count, sizeof(struct json_object_entry));
            if (!dobj->items)
                goto error;
            dobj->count = obj->count;

            for (size_t n = 0; n < obj->count; n++) {
                if (!json_do_copy(&dobj->items[n].value, &obj->items[n].value))
                    goto error;
                if (obj->items[n].key) {
                    dobj->items[n].key = strdup(obj->items[n].key);
                    if (!dobj->items[n].key)
                        goto error;
                }
            }
        }
        break;
    }
    default: ;
    }

    return true;

error:
    json_free_inplace(dst);
    return false;
}

bool json_copy_inplace(struct json_tok *dst, const struct json_tok *src)
{
    struct json_tok tmp = {0};
    if (!json_do_copy(&tmp, src))
        return false;
    json_free_inplace(dst);
    *dst = tmp;
    return true;
}

struct json_tok *json_copy(const struct json_tok *tree)
{
    struct json_tok *res = calloc(1, sizeof(*res));
    if (!res)
        return NULL;
    if (!json_copy_inplace(res, tree)) {
        free(res);
        return NULL;
    }
    return res;
}

struct json_tok *json_set_int(struct json_tok *j, const char *name, int val)
{
    return json_set(j, name, JSON_MAKE_NUM(val));
}

struct json_tok *json_set_double(struct json_tok *j, const char *name, double val)
{
    return json_set(j, name, JSON_MAKE_NUM(val));
}

struct json_tok *json_set_string(struct json_tok *j, const char *name, const char *val)
{
    return json_set(j, name, JSON_MAKE_STR((char *)val));
}

struct json_tok *json_set_string_nocopy(struct json_tok *j, const char *name, char *val)
{
    return json_set_nocopy(j, name, JSON_MAKE_STR(val));
}

struct json_tok *json_set_bool(struct json_tok *j, const char *name, bool val)
{
    return json_set(j, name, JSON_MAKE_BOOL(val));
}

static struct json_tok *json_get_or_add(struct json_tok *j, const char *name)
{
    if (!name || !j)
        return j;

    if (j->type != JSON_TYPE_OBJECT)
        return NULL;

    ptrdiff_t idx = json_object_find(j, name);
    if (idx >= 0)
        return &j->u.object->items[idx].value;

    size_t count = j->u.object->count;
    void *ptr =
        realloc(j->u.object->items, (count + 1) * sizeof(j->u.object->items[0]));
    if (!ptr)
        return NULL;
    j->u.object->items = ptr;

    struct json_object_entry *nitem = &j->u.object->items[count];
    *nitem = (struct json_object_entry){0};
    nitem->key = strdup(name);
    if (!nitem->key)
        return NULL; // can leave items[] overallocated
    j->u.object->count = count + 1;

    return &nitem->value;
}

struct json_tok *json_get_or_add_typed(struct json_tok *j, const char *name,
                                       enum json_type type)
{
    struct json_tok *tok = json_get_or_add(j, name);
    if (!tok)
        return NULL;

    if (tok->type != type) {
        // Overwrite with default init of requested type.
        struct json_tok init = {.type = type};
        struct json_array array = {0};
        struct json_object object = {0};
        switch (type) {
        case JSON_TYPE_NULL:
        case JSON_TYPE_BOOL:
        case JSON_TYPE_DOUBLE:
            break;
        case JSON_TYPE_STRING:
            init.u.str = "";
            break;
        case JSON_TYPE_ARRAY:
            init.u.array = &array;
            break;
        case JSON_TYPE_OBJECT:
            init.u.object = &object;
            break;
        default:
            // invalid type
            return NULL;
        }
        if (!json_copy_inplace(tok, &init))
            return NULL;
    }

    return tok;
}

struct json_tok *json_set_nocopy(struct json_tok *j, const char *name, struct json_tok *val)
{
    struct json_tok *res = json_get_or_add(j, name);
    if (!res)
        return NULL;

    json_free_inplace(res);
    *res = *val;
    return res;
}

struct json_tok *json_set(struct json_tok *j, const char *name, const struct json_tok *val)
{
    struct json_tok tmp = {0};
    if (!json_copy_inplace(&tmp, val))
        return NULL;

    struct json_tok *res = json_set_nocopy(j, name, &tmp);
    if (!res)
        json_free_inplace(&tmp);
    return res;
}

struct json_tok *json_set_array(struct json_tok *j, const char *name)
{
    return json_set(j, name, JSON_MAKE_ARR());
}

struct json_tok *json_set_object(struct json_tok *j, const char *name)
{
    return json_set(j, name, JSON_MAKE_OBJ());
}

bool json_object_remove(struct json_tok *j, const char *name)
{
    ptrdiff_t idx = json_object_find(j, name);
    if (idx < 0)
        return false;
    json_free_inplace(&j->u.object->items[idx].value);
    free((char *)j->u.object->items[idx].key);
    j->u.object->items[idx] = j->u.object->items[j->u.object->count - 1];
    j->u.object->count--;
    return true;
}

struct json_tok *json_array_append(struct json_tok *j, const struct json_tok *val)
{
    struct json_array *arr = json_get_array(j, NULL);
    if (!arr)
        return NULL;
    return json_array_insert(j, arr->count, val);
}

struct json_tok *json_array_insert(struct json_tok *j, size_t index,
                                   const struct json_tok *val)
{
    struct json_tok tmp = {0};
    if (!json_copy_inplace(&tmp, val))
        return NULL;

    struct json_tok *res = json_array_insert_nocopy(j, index, &tmp);
    if (!res)
        json_free_inplace(&tmp);
    return res;
}

struct json_tok *json_array_insert_nocopy(struct json_tok *j, size_t index,
                                          struct json_tok *val)
{
    struct json_array *arr = json_get_array(j, NULL);
    if (!arr || index > arr->count)
        return NULL;

    void *ptr = realloc(arr->items, (arr->count + 1) * sizeof(arr->items[0]));
    if (!ptr)
        return NULL;

    arr->items = ptr;

    memmove(&arr->items[index + 1], &arr->items[index],
            (arr->count - index) * sizeof(arr->items[0]));

    arr->count++;
    arr->items[index] = *val;
    return &arr->items[index];
}

struct json_tok *json_array_set(struct json_tok *j, size_t index,
                                const struct json_tok *val)
{
    struct json_tok *item = json_array_get(j, index);
    if (item)
        json_copy_inplace(item, val);
    return item;
}

bool json_array_remove(struct json_tok *j, size_t index)
{
    struct json_array *arr = json_get_array(j, NULL);
    if (!arr || index >= arr->count)
        return false;

    json_free_inplace(&arr->items[index]);
    arr->count--;
    memmove(&arr->items[index], &arr->items[index + 1],
            (arr->count - index) * sizeof(arr->items[0]));

    // Try to release memory (unknown whether this is a good idea).
    if (arr->count) {
        void *ptr = realloc(arr->items, arr->count * sizeof(arr->items[0]));
        // Ignore failure, leaving it overallocated is OK.
        if (ptr)
            arr->items = ptr;
    } else {
        free(arr->items);
        arr->items = NULL;
    }

    return true;
}

struct write_ctx {
    bool failed;
    char *buf;
    size_t buf_size;
    size_t buf_alloc;
};

static void buf_write(void *ctx, const char *buf, size_t len)
{
    struct write_ctx *wctx = ctx;

    while (len && !wctx->failed) {
        size_t left = wctx->buf_alloc - wctx->buf_size;
        if (left) {
            if (left > len)
                left = len;
            memcpy(wctx->buf + wctx->buf_size, buf, left);
            wctx->buf_size += left;
            buf += left;
            len -= left;
        } else {
            size_t size = wctx->buf_alloc;
            if (size >= (size_t)-1 / 2) {
                size = (size_t)-1;
            } else {
                size = size ? size * 2 : 8;
            }
            void *ptr = realloc(wctx->buf, size);
            if (!ptr) {
                wctx->failed = true;
                break;
            }
            wctx->buf = ptr;
            wctx->buf_alloc = size;
        }
    }
}

char *json_to_string(struct json_tok *tree)
{
    struct write_ctx wctx = {0};
    struct json_out out;

    json_out_init_cb(&out, buf_write, &wctx);
    json_out_write(&out, tree);

    buf_write(&wctx, "\0", 1);
    if (wctx.failed) {
        free(wctx.buf);
        wctx.buf = NULL;
    }

    return wctx.buf;
}
