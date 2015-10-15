project(zerod C)
cmake_minimum_required(VERSION 2.8)
enable_testing()

# Configurable options
OPTION(ENABLE_TCMALLOC "TCmalloc Support" OFF)
OPTION(ENABLE_JEMALLOC "JEmalloc Support" OFF)

set(zerod_VERSION_MAJOR 1)
set(zerod_VERSION_MINOR 4)
set(zerod_VERSION_UPDATE 7)

set(zerod_DEFAULT_LOG_LEVEL "LOG_ERR")

if (CMAKE_BINARY_DIR STREQUAL ${CMAKE_SOURCE_DIR})
    message(FATAL_ERROR "Building in source dir prohibited. Remove CMakeCache.txt and try 'mkdir build && cd build && cmake ..'.")
endif (CMAKE_BINARY_DIR STREQUAL ${CMAKE_SOURCE_DIR})

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake/modules)

if (NOT CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE EQUAL "")
    message(STATUS "No build type selected, default to RelWithDebInfo")
    set(CMAKE_BUILD_TYPE "RelWithDebInfo")
endif ()

if (NOT CMAKE_INSTALL_PREFIX)
    message(STATUS "No install prefix provided, will set default /usr/local")
    set(CMAKE_INSTALL_PREFIX /usr/local)
elseif(CMAKE_INSTALL_PREFIX STREQUAL "/")
    set(CMAKE_INSTALL_PREFIX "")
endif ()

set(CMAKE_C_FLAGS_RELEASE "-O2 -flto -DNDEBUG")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-g -O2 -flto -DNDEBUG")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11 -Wall -Wextra -Werror")
add_definitions(-D_GNU_SOURCE)

find_package(Threads REQUIRED)
find_package(Libevent 2.0 REQUIRED core pthreads)
find_package(Libconfig 1.4.8 REQUIRED)
find_package(Libfreeradius_client REQUIRED)
find_package(Libbson REQUIRED)
find_package(Pcap REQUIRED)

set(INCLUDES
        "${PROJECT_BINARY_DIR}"
        "${CMAKE_SOURCE_DIR}/3rdparty"
        "${LIBCONFIG_INCLUDE_DIRS}"
        "${LIBFREERADIUS_CLIENT_INCLUDE_DIRS}"
        "${LIBEVENT_INCLUDE_DIRS}"
        "${LIBBSON_INCLUDE_DIRS}"
        "${PCAP_INCLUDE_DIR}"
)


set(zerod_LIBS
        "${LIBCONFIG_LIBRARIES}"
        "${LIBFREERADIUS_CLIENT_LIBRARIES}"
        "${LIBEVENT_LIBRARIES}"
        "${LIBBSON_LIBRARIES}"
        "${CMAKE_THREAD_LIBS_INIT}"
        "${PCAP_LIBRARY}"
)

if (ENABLE_TCMALLOC AND ENABLE_JEMALLOC)
    message(FATAL_ERROR "Only one memory allocator can be enabled")
endif ()

if (ENABLE_TCMALLOC)
    find_package(Tcmalloc 2.0 REQUIRED)
    list(APPEND zerod_LIBS "${TCMALLOC_LIBRARY}")
elseif(ENABLE_JEMALLOC)
    find_package(Jemalloc 3.0 REQUIRED)
    list(APPEND zerod_LIBS "${JEMALLOC_LIBRARY}")
endif ()

configure_file("${PROJECT_SOURCE_DIR}/src/config.h.in" "${PROJECT_BINARY_DIR}/config.h")
configure_file("${PROJECT_SOURCE_DIR}/zerod.conf.dist.in" "${PROJECT_BINARY_DIR}/zerod.conf.dist")

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_subdirectory(tests)
endif ()

add_subdirectory(src)

install(FILES "${PROJECT_BINARY_DIR}/zerod.conf.dist" DESTINATION etc)
install(PROGRAMS zeroctl.py DESTINATION bin RENAME zeroctl)
