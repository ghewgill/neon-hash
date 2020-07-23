cmake_minimum_required(VERSION 3.0)
cmake_policy(SET CMP0054 NEW)
project(neon_hash)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY .)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG .)

find_path(CRYPTO_INCLUDE_DIRS NAMES openssl/sha.h)
find_library(CRYPTO_LIBRARY NAMES crypto)
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(crypto
    DEFAULT_MSG
    CRYPTO_LIBRARY
    CRYPTO_INCLUDE_DIRS)

if (CRYPTO_FOUND)
    add_library(CRYPTO::CRYPTO UNKNOWN IMPORTED)
    set_target_properties(CRYPTO::CRYPTO PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${CRYPTO_INCLUDE_DIRS}")
    set_target_properties(CRYPTO::CRYPTO PROPERTIES IMPORTED_LOCATION "${CRYPTO_LIBRARY}")
    set(CRYPTO_TARGET "CRYPTO::CRYPTO")
else()
    if (NOT EXISTS libressl-2.2.4/configure)
        execute_process(
            COMMAND cmake -E tar zxf libressl-2.2.4.tar.gz
            RESULT_VARIABLE retcode
        )
        if (NOT "${retcode}" STREQUAL "0")
            message(FATAL_ERROR "Fatal error extracting archive")
        endif()
    endif()

    if (WIN32)
        set(EXPLICIT_BZERO_CPP libressl-2.2.4/crypto/compat/explicit_bzero_win.c)
    else()
        set(EXPLICIT_BZERO_CPP libressl-2.2.4/crypto/compat/explicit_bzero.c)
    endif()
    add_library(libressl
        ${EXPLICIT_BZERO_CPP}
        libressl-2.2.4/crypto/mem_clr.c
        libressl-2.2.4/crypto/md5/md5_dgst.c
        libressl-2.2.4/crypto/md5/md5_one.c
        libressl-2.2.4/crypto/sha/sha1_one.c
        libressl-2.2.4/crypto/sha/sha1dgst.c
        libressl-2.2.4/crypto/sha/sha256.c
        libressl-2.2.4/crypto/sha/sha512.c
    )
    if (${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
        target_compile_definitions(libressl
            PRIVATE HAVE_STRLCPY
            PRIVATE HAVE_STRLCAT
        )
    endif()
    if (${CMAKE_SYSTEM_NAME} STREQUAL "OpenBSD")
        target_compile_definitions(libressl
            PRIVATE HAVE_ATTRIBUTE__BOUNDED__
        )
    endif()
    if (NOT WIN32)
        target_compile_options(libressl PRIVATE -fPIC)
    endif()
    target_include_directories(libressl
        PUBLIC libressl-2.2.4/include
        PRIVATE libressl-2.2.4/include/compat
        PRIVATE libressl-2.2.4/crypto
    )
    set(CRYPTO_TARGET "libressl")
endif()

add_library(neon_hash SHARED hash.cpp)
target_link_libraries(neon_hash ${CRYPTO_TARGET})
