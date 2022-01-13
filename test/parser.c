#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"
#include "json_helpers_malloc.h"
#include "json_out.h"

static void do_write(void *ctx, const char *buf, size_t len)
{
    fwrite(buf, len, 1, stdout);
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
    bool use_malloc = false;
    int indent_count = 3;

    for (int n = 1; n < argc; n++) {
        if (strcmp(argv[n], "--string") == 0) {
            is_file = false;
        } else if (strcmp(argv[n], "--dump") == 0) {
            dump = true;
        } else if (strcmp(argv[n], "--malloc") == 0) {
            use_malloc = true;
        } else if (strncmp(argv[n], "--indent=", 9) == 0) {
            indent_count = atoi(argv[n] + 9); // lazy!
        } else if (argv[n][0] == '-') {
            fprintf(stderr, "Invalid command line arguments.\n");
            fprintf(stderr, "   --string    Argument is a string to parse.\n");
            fprintf(stderr, "   --dump      Dump JSON tree.\n");
            fprintf(stderr, "   --indent=N  Dump indentation (0 no indentation,\n");
            fprintf(stderr, "               -1 disable pretty print, >0: num. spaces\n");
            fprintf(stderr, "   --malloc    Use malloc().\n");
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

    struct json_parse_opts opts = {.depth = 1000, .msg_cb = json_msg_cb};

    struct json_tok *tok;
    if (use_malloc) {
        tok = json_parse_malloc(data, &opts);
    } else {
        // Estimate "some" memory size to hold the result. Normally, you'd
        // use a fixed buffer (embedded scenario), or use json_parse_malloc().
        size_t memory_size = 64 * 1024 + size * 8; // unchecked overflow
        void *memory = malloc(memory_size);
        if (!memory)
            goto error_size;
        tok = json_parse(data, memory, memory_size, &opts);
        // reminder that tok will point to memory
    }

    if (tok) {
        printf("Success.\n");
        if (dump) {
            struct json_out out;
            json_out_init_cb(&out, do_write, NULL);
            if (indent_count >= 0)
                json_out_set_indent(&out, indent_count);
            json_out_write(&out, tok);
            json_out_finish(&out);
            printf("\n");
        }
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
