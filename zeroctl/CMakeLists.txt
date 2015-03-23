set(zeroctl_SOURCES
    zeroctl.c
    ../src/util.c
)

list(APPEND INCLUDES "../src")

include_directories(${INCLUDES})

add_executable(zeroctl ${zeroctl_SOURCES})

#install(TARGETS zeroctl RUNTIME DESTINATION bin)
