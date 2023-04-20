project('json_test', 'c')
incdir = include_directories('../')
libfiles = [
    '../json.c',
    '../json_out.c',
    '../json_helpers.c',
    '../json_helpers_malloc.c',
    ]
executable('json_test', 'test.c', libfiles,
           include_directories: incdir)
executable('json_parser', 'parser.c', libfiles,
           include_directories: incdir)
executable('example', 'example.c', libfiles,
           include_directories: incdir)
