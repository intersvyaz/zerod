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
    monitor.c
)

include_directories(${INCLUDES})

add_executable(zerod ${zerod_SOURCES} ${zerod_HEADERS})

target_link_libraries(zerod ${zerod_LIBS} -rdynamic)

install(TARGETS zerod RUNTIME DESTINATION sbin)
