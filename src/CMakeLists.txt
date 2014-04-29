set(zerod_SOURCES
    main.c
    netmap.c
    log.c
    zero.c
    packet.c
    client.c
    session.c
    util.c
    config.c
    overlord.c
    remotectl.c
    master.c
    netproto.c
    router/nat.c
    router/forwarder.c
    router/firewall.c
    crules.c
    srules.c
    exception.c
)

set(zerod_HEADERS
    netmap.h
    log.h
    zero.h
    client.h
    session.h
    util.h
    zrc_proto.h
    netproto.h
    router/router.h
    crules.h
    srules.h
    exception.h
)

set(zeroctl_SOURCES
    zeroctl.c
    util.c
)

include_directories(${INCLUDES})

add_executable(zerod ${zerod_SOURCES} ${zerod_HEADERS})
add_executable(zeroctl ${zeroctl_SOURCES})

target_link_libraries(zerod ${zerod_LIBS})

install(TARGETS zerod RUNTIME DESTINATION sbin)
install(TARGETS zeroctl RUNTIME DESTINATION bin)
