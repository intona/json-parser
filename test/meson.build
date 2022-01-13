project('json_test', 'c')
incdir = include_directories('../')
executable('json_test', 'test.c', '../json.c', '../json_out.c',
           '../json_helpers.c','../json_helpers_malloc.c',
           include_directories: incdir)
executable('json_parser', 'parser.c', '../json.c', include_directories: incdir)
