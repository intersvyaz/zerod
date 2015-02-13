# - Find Tcmalloc
# Find the native tcmalloc includes and library
#
#  TCMALLOC_INCLUDE_DIR - where to find tcmalloc.h, etc.
#  TCMALLOC_LIBRARY     - List of libraries when using Tcmalloc.
#  TCMALLOC_FOUND       - True if Tcmalloc found.

FIND_PATH(TCMALLOC_INCLUDE_DIR gperftools/tcmalloc.h)
FIND_LIBRARY(TCMALLOC_LIBRARY NAMES tcmalloc)

IF(TCMALLOC_INCLUDE_DIR AND EXISTS "${TCMALLOC_INCLUDE_DIR}/gperftools/tcmalloc.h")
    # Read and parse tcmalloc version header file for version number
    file(READ "${TCMALLOC_INCLUDE_DIR}/gperftools/tcmalloc.h" _tcmalloc_HEADER_CONTENTS)

    string(REGEX REPLACE ".*#define TC_VERSION_MAJOR +([0-9]+).*" "\\1" TCMALLOC_VERSION_MAJOR "${_tcmalloc_HEADER_CONTENTS}")
    string(REGEX REPLACE ".*#define TC_VERSION_MINOR +([0-9]+).*" "\\1" TCMALLOC_VERSION_MINOR "${_tcmalloc_HEADER_CONTENTS}")
    string(REGEX REPLACE ".*#define TC_VERSION_PATCH +\"([\\.0-9]*)\".*" "\\1" TCMALLOC_VERSION_PATCH "${_tcmalloc_HEADER_CONTENTS}")

    SET(TCMALLOC_VERSION_STRING "${TCMALLOC_VERSION_MAJOR}.${TCMALLOC_VERSION_MINOR}${TCMALLOC_VERSION_PATCH}")
ENDIF()

# handle the QUIETLY and REQUIRED arguments and set TCMALLOC_FOUND to TRUE if all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(Tcmalloc
    REQUIRED_VARS TCMALLOC_LIBRARY TCMALLOC_INCLUDE_DIR
    VERSION_VAR TCMALLOC_VERSION_STRING
)

MARK_AS_ADVANCED(TCMALLOC_INCLUDE_DIR TCMALLOC_LIBRARY)
