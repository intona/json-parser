#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "json.h"

static void json_msg_cb(void *opaque, size_t loc, const char *msg)
{
    fprintf(stderr, "json parser (at %d): %s\n", (int)loc, msg);
}

int main(int argc, char **argv)
{
    if (argc != 2)
        goto error_args;

    FILE *f = fopen(argv[1], "rb");
    if (!f)
        goto error_file;

    if (fseek(f, 0, SEEK_END) < 0)
        goto error_file;

    long size = ftell(f);
    if (size < 0)
        goto error_file;

    if (fseek(f, 0, SEEK_SET) < 0)
        goto error_file;

    // Estimate "some" memory size to hold the result. Normally, you'd provide a
    // fixed buffer size (embedded scenario), or modify the parser to use malloc
    // (desktop scenario; heavier json parser libs might be preferable).
    if (size > ((size_t)-1 - 64 * 1024) / 64)
        goto error_size;
    size_t memory_size = 64 * 1024 + size * 16; // unchecked overflow
    void *memory = malloc(memory_size);
    if (!memory)
        goto error_size;

    void *data = calloc(1, size + 1);
    if (!data)
        goto error_size;

    if (size && fread(data, size, 1, f) != 1)
        goto error_file;



    struct json_msg_cb cb = {json_msg_cb};
    struct json_tok *tok = json_parse(data, memory, memory_size, 1000, &cb);
    if (tok) {
        printf("Success.\n");
        return 0;
    } else {
        fprintf(stderr, "Parsing failed.\n");
        return 1;
    }

error_args:
    fprintf(stderr, "Invalid command line arguments.\n");
    return 2;

error_file:
    fprintf(stderr, "could not open or read file.\n");
    return 3;

error_size:
    fprintf(stderr, "Failed to allocate memory.\n");
    return 4;
}
