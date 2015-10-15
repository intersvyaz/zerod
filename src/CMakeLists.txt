set(zerod_SOURCES
        blacklist.c
        client.c
        config.c
        crules.c
        log.c
        main.c
        master.c
        monitor.c
        netmap.c
        overlord.c
        packet.c
        packet_arp.c
        packet_ipv4.c
        rc-bson.c
        rc-zrcp.c
        rc.c
        router/dhcp.c
        router/firewall.c
        router/forwarder.c
        router/nat.c
        run.c
        session.c
        speed_meter.c
        srules.c
        token_bucket.c
        util.c
        zero.c
)

include_directories(${INCLUDES})

add_executable(zerod ${zerod_SOURCES} ${zerod_HEADERS})

target_link_libraries(zerod ${zerod_LIBS} -rdynamic)

install(TARGETS zerod RUNTIME DESTINATION sbin)
