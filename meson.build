project('aimelib', 'c',
        version : '1.0.0',
        default_options : ['warning_level=3', 'c_std=c2x'])

# These arguments are only used to build the shared library
# not the executables that use the library.
lib_args = ['-DBUILDING_MESON_LIBRARY']

aime_lib = static_library('aimelib',
               install : true,
               c_args : lib_args,
               sources : [
                   'aime.c',
                   'aime.h',
                   'util/dprintf.c',
                   'util/dprintf.h',
                   'util/dump.c',
                   'util/dump.h',
               ]
)