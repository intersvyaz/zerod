# - Find libpcre
# Find the native libpcre includes and library.
# Once done this will define
#
#  LIBPCRE_INCLUDE_DIRS - where to find pcre.h, etc.
#  LIBPCRE_LIBRARIES    - List of libraries when using libpcre.
#  LIBPCRE_FOUND        - True if libpcre found.
#
#  LIBPCRE_VERSION_STRING - The version of libpcre found (x.y)
#  LIBPCRE_VERSION_MAJOR  - The major version
#  LIBPCRE_VERSION_MINOR  - The minor version
#  LIBPCRE_VERSION_MICRO  - The micro version

FIND_PATH(LIBPCRE_INCLUDE_DIR NAMES pcre.h)
FIND_LIBRARY(LIBPCRE_LIBRARY  NAMES pcre)

MARK_AS_ADVANCED(LIBPCRE_LIBRARY LIBPCRE_INCLUDE_DIR)

IF(LIBPCRE_INCLUDE_DIR AND EXISTS "${LIBPCRE_INCLUDE_DIR}/pcre.h")
    # Read and parse version header file for version number
    file(READ "${LIBPCRE_INCLUDE_DIR}/pcre.h" _libpcre_HEADER_CONTENTS)
    IF(_libpcre_HEADER_CONTENTS MATCHES ".*PCRE_MAJOR.*")
        string(REGEX REPLACE ".*#define +PCRE_MAJOR +([0-9]+).*" "\\1" LIBPCRE_VERSION_MAJOR "${_libpcre_HEADER_CONTENTS}")
        string(REGEX REPLACE ".*#define +PCRE_MINOR +([0-9]+).*" "\\1" LIBPCRE_VERSION_MINOR "${_libpcre_HEADER_CONTENTS}")
    ELSE()
       SET(LIBPCRE_VERSION_MAJOR 0)
       SET(LIBPCRE_VERSION_MINOR 0)
    ENDIF()

    SET(LIBPCRE_VERSION_STRING "${LIBPCRE_VERSION_MAJOR}.${LIBPCRE_VERSION_MINOR}")
ENDIF()

# handle the QUIETLY and REQUIRED arguments and set LIBPCRE_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(Libpcre
    REQUIRED_VARS LIBPCRE_LIBRARY LIBPCRE_INCLUDE_DIR
    VERSION_VAR LIBPCRE_VERSION_STRING
)

IF(LIBPCRE_FOUND)
    SET(LIBPCRE_INCLUDE_DIRS ${LIBPCRE_INCLUDE_DIR})
    SET(LIBPCRE_LIBRARIES ${LIBPCRE_LIBRARY})
ENDIF()
