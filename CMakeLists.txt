project(zerod C)
cmake_minimum_required(VERSION 2.8)
enable_testing()

set(zerod_VERSION_MAJOR 0)
set(zerod_VERSION_MINOR 6)
set(zerod_VERSION_UPDATE 0)

set(zerod_DEFAULT_LOG_LEVEL "LOG_ERR")

if(CMAKE_BINARY_DIR STREQUAL ${CMAKE_SOURCE_DIR})
    message(FATAL_ERROR "Building in source dir prohibited. Remove CMakeCache.txt and try 'mkdir build && cd build && cmake ..'.")
endif(CMAKE_BINARY_DIR STREQUAL ${CMAKE_SOURCE_DIR})

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake/modules)

if (NOT CMAKE_BUILD_TYPE)
    message(STATUS "No build type selected, default to RelWithDebInfo")
    set(CMAKE_BUILD_TYPE "RelWithDebInfo")
endif()

if (NOT CMAKE_INSTALL_PREFIX)
    message(STATUS "No install prefix provided, default to /usr/local")
    set(CMAKE_INSTALL_PREFIX  /usr/local)
endif()

set(CMAKE_C_FLAGS_RELEASE "-Ofast -flto -march=native -funroll-loops -DNDEBUG")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-g -rdynamic -Ofast -flto -march=native -funroll-loops -DNDEBUG")
set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -std=gnu11 -Wall -Wextra")
add_definitions(-D_GNU_SOURCE)

find_package(Threads REQUIRED)
find_package(Libevent REQUIRED core pthreads)
find_package(Libconfig 1.4.8 REQUIRED)
find_package(Libfreeradius_client REQUIRED)

set(INCLUDES
    "${PROJECT_BINARY_DIR}"
    "${CMAKE_SOURCE_DIR}/3rdparty"
    "${LIBCONFIG_INCLUDE_DIRS}"
    "${LIBFREERADIUS_CLIENT_INCLUDE_DIRS}"
    "${LIBEVENT_INCLUDE_DIRS}"
)

set(zerod_LIBS
    "${LIBCONFIG_LIBRARIES}"
    "${LIBFREERADIUS_CLIENT_LIBRARIES}"
    "${LIBEVENT_LIBRARIES}"
    "${CMAKE_THREAD_LIBS_INIT}"
)

configure_file(
  "${PROJECT_SOURCE_DIR}/src/config.h.in"
  "${PROJECT_BINARY_DIR}/config.h"
)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_subdirectory(tests)
endif()

add_subdirectory(src)

install(FILES zerod.conf.dist DESTINATION etc)
install(PROGRAMS etc/zerod DESTINATION /etc/init.d)
