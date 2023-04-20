#include <assert.h>
#include <stdio.h>

#include "json.h"
#include "json_helpers.h"
#include "json_out.h"

int main(int argc, char **argv)
{
    // Example without malloc(). You provide a fixed size area as working memory
    // to the parser. Must be large enough for any expected input.
    // t (below) will point somewhere into this!
    char tmp[1024];
    // JSON text to parse.
    static const char input[] = "{\"key1\": 123, \"key2\": [12, 34, 56]}";

    struct json_tok *t = json_parse(input, tmp, sizeof(tmp), NULL);

    assert(t); // NULL on error, can use json_parse_opts to get error info

    assert(json_get_int(t, "key1", -1) == 123);

    int sum = 0;
    struct json_array *arr = json_get_array(t, "key2");
    assert(arr); // NULL if not present in input
    for (size_t n = 0; n < arr->count; n++) {
        int v = json_get_int(&arr->items[n], NULL, -1);
        printf(" array value: %d\n", v);
        sum += v;
    }
    assert(sum == 12 + 34 + 56);
}
