JSON Parser
===========

This is a simple JSON parser, written in C11. It's suitable for embedded use.
In particular, it's small and compact, yet fully featured and easy to use. It
requires the caller to preallocate memory and returns an AST (basically a
tree structure of JSON values). It also supports a minimum of error reporting.

The main focus is on correctness, small code size, low dependencies, and ease
of use.

The relevant specifications are RFC 8259 and RFC 7493.

How to use
----------

Add json.c and json.h to your build system. Call json_parse_destructive() or
json_parse(). The arguments and semantics are documented in the header file.

The optional json_out.h/json_out.c files are trivial helpers to write JSON data.

The optional json_helpers.h/json_helpers.c provide trivial helpers to traverse
the data structure the parser returns.

Hints for embedded use
----------------------

- It uses floats (double C type) and strtod(). If floats are not available on
  the target architecture, you can replace all occurences of "double" with
  "int" or "long", and "strtod" with "strtol" (or use your own string to
  integer conversion).
- strtod() is very bloated on some embedded libcs. If you do not require correct
  float conversion, this simple strtod() function can be easily adapted:
  https://github.com/libass/libass/blob/master/libass/ass_strtod.c
  Or extract musl-libc's implementation for something if you need correctness.
- The only math.h symbol, isfinite(), is trivially replaceable, or can be
  removed entirely (the parser will then accept inf/nan).
- It uses assert() in at least one place. Some embedded libcs will pull in stdio
  for it, so you may want to comment all of its uses.
- In addition, it uses some simple string functions, which should not pose any
  trouble.
- The only required C11 feature that is not available in C99 is the use of the
  _Alignof operator. If you do not have a C11 compiler, replace it with 4 or 8
  (depending on "double" alignment requirements), or 1 if your target
  architecture supports fast unaligned accesses. Adapting to C89 will be harder.
- json_out.c (not required by the parser) uses stdio's vsnprintf() to format
  numbers. A sufficiently non-bloated libc for embedded use is here:
  https://github.com/mpaland/printf/
  (This does not correctly format floats as of this writing.)

Design choices
--------------

The main parsing function, json_parse_destructive(), mutates the input text (i.e.
it writes to the memory pointed to by the text argument). This is an attempt to
save memory. Parsed string values do not need to be allocated from the provided
memory region.

Arrays are represented as linked lists. This is done because it's hard to
allocate a linear array. You would either have to parse the JSON in multiple
passes to preallocate the array with the correct number of elements, or have to
use a complete memory manager that efficiently supports realloc().

Test programs
-------------

These use the Meson build system: https://mesonbuild.com/Quick-guide.html

test/test.c is a simple test of the parser and some of the helpers.

test/parser.c expects a filename as argument, and returns success or failure.
On failure, it also prints the error. This is suitable for use with
[JSONTestSuite][1]. (As of this writing, it passed all tests, except some
SHOULD_HAVE_FAILEDs with number strictness, and 2 SHOULD_HAVE_PASSED where this
parser rejects escapes resulting in strings with embedded zeros.)

Known deviations from standard JSON
-----------------------------------

- Number parsing is not very strict and allows anything strtod() allows.
- Some JSON variants require support other encodings (such as UTF-16), while
  this parser requires UTF-8.
- Some JSON variants require strict UTF-8, while this parser does not check
  whether input text is valid UTF-8. The API user must check for valid UTF-8 on
  its own if required.
- Some JSON variants require rejecting duplicate object keys, which this parser
  does not do.
- According to some, standard JSON technically allows embedding \0 in strings
  with "\u0000" escapes. This parser explicitly rejects them, because the API
  uses C strings, which cannot represent strings with embedded zeros. (Also
  consider section 9 in RFC 8259.)

TODO
----

- The test program under is probably not exhaustive enough. Ensure 100% code
  coverage and fuzz the parser. Also, verify 100% JSON correctness.
- The json_helpers.h functions are very primitive. There need to be functions
  which can report errors in a human readable way. (Consider you use JSON for
  a network API. You want to provide good error information to API users if e.g.
  a JSON object key is missing or has the wrong type.)

License
-------

ISC (permissive, similar to BSD and MIT)

Links
-----

[1]: https://github.com/nst/JSONTestSuite
