set(zerod_SOURCES
        blacklist.c
        client.c
        client_db.c
        config.c
        client_rules.c
        dhcp.c
        firewall.c
        forwarder.c
        log.c
        main.c
        master.c
        monitor.c
        nat.c
        netmap.c
        netproto.c
        overlord.c
        packet.c
        packet_arp.c
        packet_dhcp.c
        packet_ipv4.c
        radius.c
        remotectl_bson.c
        remotectl.c
        scope.c
        scope_rules.c
        session.c
        session_db.c
        speed_meter.c
        token_bucket.c
        worker.c
        util.c
        util_string.c
        util_time.c
        zero.c
)

include_directories(${INCLUDES})

add_executable(zerod ${zerod_SOURCES} ${zerod_HEADERS})

target_link_libraries(zerod ${zerod_LIBS} -rdynamic)

install(TARGETS zerod RUNTIME DESTINATION sbin)
