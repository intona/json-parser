#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"

static void dump_tok(struct json_tok *tok, int depth)
{
    printf("%*s", depth, "");
    switch (tok->type) {
    case JSON_TYPE_NULL:
        printf("null\n");
        break;
    case JSON_TYPE_BOOL:
        printf("%s\n", tok->u.b ? "true" : "false");
        break;
    case JSON_TYPE_STRING:
        printf("'%s'\n", tok->u.str);
        break;
    case JSON_TYPE_DOUBLE:
        printf("%f\n", tok->u.d);
        break;
    case JSON_TYPE_ARRAY:
        printf("[\n");
        for (size_t n = 0; n < tok->u.array->count; n++)
            dump_tok(&tok->u.array->items[n], depth + 2);
        printf("%*s]\n", depth, "");
        break;
    case JSON_TYPE_OBJECT:
        printf("{\n");
        for (size_t n = 0; n < tok->u.object->count; n++) {
            printf("%*s'%s':\n", depth, "", tok->u.object->items[n].key);
            dump_tok(&tok->u.object->items[n].value, depth + 2);
        }
        printf("%*s}\n", depth, "");
        break;
    default:
        printf("error\n");
    }
}

static void json_msg_cb(void *opaque, size_t loc, const char *msg)
{
    fprintf(stderr, "json parser (at %d): %s\n", (int)loc, msg);
}

int main(int argc, char **argv)
{
    char *arg = NULL;
    bool is_file = true;
    bool dump = false;

    for (int n = 1; n < argc; n++) {
        if (strcmp(argv[n], "--string") == 0) {
            is_file = false;
        } else if (strcmp(argv[n], "--dump") == 0) {
            dump = true;
        } else if (argv[n][0] == '-') {
            fprintf(stderr, "Invalid command line arguments.\n");
            fprintf(stderr, "   --string    Argument is a string to parse.\n");
            fprintf(stderr, "   --dump      Dump JSON tree.\n");
            fprintf(stderr, "   arg         File, or JSON string if --string.\n");
            return 2;
        } else {
            if (arg) {
                fprintf(stderr, "Only one non-option argument expected.\n");
                return 2;
            }
            arg = argv[n];
        }
    }

    if (!arg) {
        fprintf(stderr, "%s argument expected.\n", is_file ? "file" : "string");
        return 2;
    }

    long size = 0;
    void *data = NULL;
    if (is_file) {
        FILE *f = fopen(argv[1], "rb");
        if (!f)
            goto error_file;

        if (fseek(f, 0, SEEK_END) < 0)
            goto error_file;

        size = ftell(f);
        if (size < 0)
            goto error_file;

        if (fseek(f, 0, SEEK_SET) < 0)
            goto error_file;

        data = calloc(1, size + 1);
        if (!data)
            goto error_size;

        if (size && fread(data, size, 1, f) != 1)
            goto error_file;
    } else {
        size = strlen(arg);
        data = arg;
    }

    // Estimate "some" memory size to hold the result. Normally, you'd provide a
    // fixed buffer size (embedded scenario), or modify the parser to use malloc
    // (desktop scenario; heavier json parser libs might be preferable).
    if (size > ((size_t)-1 - 64 * 1024) / 64)
        goto error_size;
    size_t memory_size = 64 * 1024 + size * 16; // unchecked overflow
    void *memory = malloc(memory_size);
    if (!memory)
        goto error_size;

    struct json_parse_opts opts = {.depth = 1000, .msg_cb = json_msg_cb};
    struct json_tok *tok = json_parse(data, memory, memory_size, &opts);
    if (tok) {
        printf("Success.\n");
        if (dump)
            dump_tok(tok, 0);
        return 0;
    } else {
        fprintf(stderr, "Parsing failed.\n");
        return 1;
    }

error_file:
    fprintf(stderr, "could not open or read file.\n");
    return 3;

error_size:
    fprintf(stderr, "Failed to allocate memory.\n");
    return 4;
}
