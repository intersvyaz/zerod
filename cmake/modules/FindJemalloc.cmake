# - Find Jemalloc
# Find the native jemalloc includes and library
#
#  JEMALLOC_INCLUDE_DIR - where to find tcmalloc.h, etc.
#  JEMALLOC_LIBRARY     - List of libraries when using Jemalloc.
#  JEMALLOC_FOUND       - True if Jemalloc found.

FIND_PATH(JEMALLOC_INCLUDE_DIR jemalloc/jemalloc.h)
FIND_LIBRARY(JEMALLOC_LIBRARY NAMES jemalloc)

IF(JEMALLOC_INCLUDE_DIR AND EXISTS "${JEMALLOC_INCLUDE_DIR}/jemalloc/jemalloc.h")
    # Read and parse jemalloc version header file for version number
    file(READ "${JEMALLOC_INCLUDE_DIR}/jemalloc/jemalloc.h" _jemalloc_HEADER_CONTENTS)

    string(REGEX REPLACE ".*JEMALLOC_VERSION_MAJOR ([0-9]+).*" "\\1" JEMALLOC_VERSION_MAJOR "${_jemalloc_HEADER_CONTENTS}")
    string(REGEX REPLACE ".*JEMALLOC_VERSION_MINOR +([0-9]+).*" "\\1" JEMALLOC_VERSION_MINOR "${_jemalloc_HEADER_CONTENTS}")
    string(REGEX REPLACE ".*JEMALLOC_VERSION_BUGFIX +([0-9]+).*" "\\1" JEMALLOC_VERSION_BUGFIX "${_jemalloc_HEADER_CONTENTS}")

    SET(JEMALLOC_VERSION_STRING "${JEMALLOC_VERSION_MAJOR}.${JEMALLOC_VERSION_MINOR}.${JEMALLOC_VERSION_BUGFIX}")
ENDIF()

# handle the QUIETLY and REQUIRED arguments and set JEMALLOC_FOUND to TRUE if all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(Jemalloc
    REQUIRED_VARS JEMALLOC_LIBRARY JEMALLOC_INCLUDE_DIR
    VERSION_VAR JEMALLOC_VERSION_STRING
)

MARK_AS_ADVANCED(JEMALLOC_INCLUDE_DIR JEMALLOC_LIBRARY)
