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

#include <string.h>
#include <stdlib.h>

#include "json_helpers.h"

struct json_tok *json_get(struct json_tok *j, const char *name)
{
    if (!name)
        return j;

    if (j && j->type == JSON_TYPE_OBJECT) {
        for (struct json_list_item *i = j->u.list->head; i; i = i->next) {
            if (strcmp(i->key, name) == 0)
                return &i->value;
        }
    }

    return NULL;
}

int json_get_int(struct json_tok *j, const char *name, int def)
{
    j = json_get(j, name);
    // "Best effort".
    return j && j->type == JSON_TYPE_DOUBLE ? (int)j->u.d : def;
}

double json_get_double(struct json_tok *j, const char *name, double def)
{
    j = json_get(j, name);
    return j && j->type == JSON_TYPE_DOUBLE ? j->u.d : def;
}

const char *json_get_string(struct json_tok *j, const char *name, const char *def)
{
    j = json_get(j, name);
    return j && j->type == JSON_TYPE_STRING ? j->u.str : def;
}

bool json_get_bool(struct json_tok *j, const char *name, bool def)
{
    j = json_get(j, name);
    return j && j->type == JSON_TYPE_BOOL ? j->u.b : def;
}

struct json_list *json_get_array(struct json_tok *j, const char *name)
{
    j = json_get(j, name);
    return j && j->type == JSON_TYPE_ARRAY ? j->u.list : NULL;
}

struct json_list *json_get_object(struct json_tok *j, const char *name)
{
    j = json_get(j, name);
    return j && j->type == JSON_TYPE_OBJECT ? j->u.list : NULL;
}
