find_package(Check REQUIRED)

set(INCLUDES
    ${INCLUDES}
    ${CHECK_INCLUDE_DIRS}
    ../src
)
include_directories(${INCLUDES})

set(tests_LIBS ${CHECK_LIBRARIES} ${zerod_LIBS})

add_executable(util_test util_test.c)
target_link_libraries(util_test ${tests_LIBS})
add_test(util ${CMAKE_CURRENT_BINARY_DIR}/util_test)

add_executable(nat_test router/nat_test.c ../src/util.c)
target_link_libraries(nat_test ${tests_LIBS})
add_test(nat ${CMAKE_CURRENT_BINARY_DIR}/nat_test)

add_executable(firewall_test router/firewall_test.c ../src/util.c)
target_link_libraries(firewall_test ${tests_LIBS})
add_test(firewall ${CMAKE_CURRENT_BINARY_DIR}/firewall_test)

add_executable(forwarder_test router/forwarder_test.c ../src/util.c ../src/netproto.c ../src/router/nat.c)
target_link_libraries(forwarder_test ${tests_LIBS})
add_test(forwarder ${CMAKE_CURRENT_BINARY_DIR}/forwarder_test)

add_executable(crules_test crules_test.c ../src/util.c)
target_link_libraries(crules_test ${tests_LIBS})
add_test(crules ${CMAKE_CURRENT_BINARY_DIR}/crules_test)
