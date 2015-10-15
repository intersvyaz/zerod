# - Find libbson
# Find the native libbson includes and library.
# Once done this will define
#
#  LIBBSON_INCLUDE_DIRS - where to find bson.h, etc.
#  LIBBSON_LIBRARIES    - List of libraries when using libbson.
#  LIBBSON_FOUND        - True if libbson found.
#
#  LIBBSON_VERSION_STRING - The version of libbson found (x.y.z)
#  LIBBSON_VERSION_MAJOR  - The major version
#  LIBBSON_VERSION_MINOR  - The minor version
#  LIBBSON_VERSION_MICRO  - The micro version

FIND_PATH(LIBBSON_INCLUDE_DIR NAMES bson.h PATH_SUFFIXES libbson-1.0)
FIND_LIBRARY(LIBBSON_LIBRARY  NAMES bson-1.0)

MARK_AS_ADVANCED(LIBBSON_LIBRARY LIBBSON_INCLUDE_DIR)

IF(LIBBSON_INCLUDE_DIR AND EXISTS "${LIBBSON_INCLUDE_DIR}/bson-version.h")
    # Read and parse version header file for version number
    file(READ "${LIBBSON_INCLUDE_DIR}/bson-version.h" _libbson_HEADER_CONTENTS)
    IF(_libbson_HEADER_CONTENTS MATCHES ".*BSON_MAJOR_VERSION.*")
                                #define BSON_MAJOR_VERSION
        string(REGEX REPLACE ".*#define +BSON_MAJOR_VERSION +\\(([0-9]+)\\).*" "\\1" LIBBSON_VERSION_MAJOR "${_libbson_HEADER_CONTENTS}")
        string(REGEX REPLACE ".*#define +BSON_MINOR_VERSION +\\(([0-9]+)\\).*" "\\1" LIBBSON_VERSION_MINOR "${_libbson_HEADER_CONTENTS}")
        string(REGEX REPLACE ".*#define +BSON_MICRO_VERSION +\\(([0-9]+)\\).*" "\\1" LIBBSON_VERSION_MICRO "${_libbson_HEADER_CONTENTS}")
    ELSE()
       SET(LIBBSON_VERSION_MAJOR 0)
       SET(LIBBSON_VERSION_MINOR 0)
       SET(LIBBSON_VERSION_MICRO 0)
    ENDIF()

    SET(LIBBSON_VERSION_STRING "${LIBBSON_VERSION_MAJOR}.${LIBBSON_VERSION_MINOR}.${LIBBSON_VERSION_MICRO}")
ENDIF()

# handle the QUIETLY and REQUIRED arguments and set LIBBSON_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(Libbson
    REQUIRED_VARS LIBBSON_LIBRARY LIBBSON_INCLUDE_DIR
    VERSION_VAR LIBBSON_VERSION_STRING
)

IF(LIBBSON_FOUND)
    SET(LIBBSON_INCLUDE_DIRS ${LIBBSON_INCLUDE_DIR})
    SET(LIBBSON_LIBRARIES ${LIBBSON_LIBRARY})
ENDIF()
