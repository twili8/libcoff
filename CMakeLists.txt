cmake_minimum_required(VERSION 4.3)
project(libcoff C)

set(CMAKE_C_STANDARD 11)
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_compile_options(
            --target=x86_64-w64-windows-gnu
            -nostdlib
    )

    add_link_options(
            --target=x86_64-w64-windows-gnu
            -fuse-ld=bfd
            -nostdlib
    )
endif()
add_library(libcoff STATIC library.c
        worker.c
        worker.h)
