find_package(Check REQUIRED)

set(INCLUDES
        ${INCLUDES}
        ${CHECK_INCLUDE_DIRS}
        ../src
)
include_directories(${INCLUDES})

set(tests_LIBS ${CHECK_LIBRARIES} ${zerod_LIBS})

add_definitions(-DTEST_DATA_PATH="${CMAKE_CURRENT_SOURCE_DIR}/data")

add_executable(util_test util_test.c)
target_link_libraries(util_test ${tests_LIBS})
add_test(util ${CMAKE_CURRENT_BINARY_DIR}/util_test)

add_executable(util_string_test util_string_test.c)
target_link_libraries(util_string_test ${tests_LIBS})
add_test(util_string ${CMAKE_CURRENT_BINARY_DIR}/util_string_test)

add_executable(nat_test nat_test.c ../src/util.c ../src/util_time.c)
target_link_libraries(nat_test ${tests_LIBS})
add_test(nat ${CMAKE_CURRENT_BINARY_DIR}/nat_test)

add_executable(firewall_test firewall_test.c ../src/util.c)
target_link_libraries(firewall_test ${tests_LIBS})
add_test(firewall ${CMAKE_CURRENT_BINARY_DIR}/firewall_test)

add_executable(forwarder_test forwarder_test.c ../src/util.c ../src/util_time.c ../src/nat.c)
target_link_libraries(forwarder_test ${tests_LIBS})
add_test(forwarder ${CMAKE_CURRENT_BINARY_DIR}/forwarder_test)

add_executable(client_rules_test client_rules_test.c ../src/util.c ../src/util_time.c ../src/util_string.c)
target_link_libraries(client_rules_test ${tests_LIBS})
add_test(client_rules ${CMAKE_CURRENT_BINARY_DIR}/client_rules_test)

add_executable(blacklist_test blacklist_test.c ../src/util.c ../src/util_string.c ../src/log.c)
target_link_libraries(blacklist_test ${tests_LIBS})
add_test(blacklist ${CMAKE_CURRENT_BINARY_DIR}/blacklist_test)

add_executable(netproto_test netproto_test.c)
target_link_libraries(netproto_test ${tests_LIBS})
add_test(netproto ${CMAKE_CURRENT_BINARY_DIR}/netproto_test)
