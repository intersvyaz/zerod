#include <check.h>

#include <router/firewall.c>

#define TEST_PORT_53 htons(53)
#define TEST_PORT_80 htons(80)

START_TEST (test_firewall_empty)
{
    struct zfirewall *fire = zfwall_create();

    fail_if(0 != zfwall_allowed(fire, PROTO_TCP, TEST_PORT_53), "Deny on empty rules");
    fail_if(0 != zfwall_allowed(fire, PROTO_UDP, TEST_PORT_53), "Deny on empty rules");

    zfwall_destroy(fire);
}
END_TEST

START_TEST (test_firewall_allow)
{
    struct zfirewall *fire = zfwall_create();

    zfwall_add_rule(fire, PROTO_TCP, PORT_ALLOW, TEST_PORT_53);
    zfwall_add_rule(fire, PROTO_UDP, PORT_ALLOW, TEST_PORT_53);

    fail_if(0 != zfwall_allowed(fire, PROTO_TCP, TEST_PORT_53), "Deny on allowed port");
    fail_if(0 != zfwall_allowed(fire, PROTO_UDP, TEST_PORT_53), "Deny on allowed port");

    fail_if(0 == zfwall_allowed(fire, PROTO_TCP, TEST_PORT_80), "Allow on not allowed port");
    fail_if(0 == zfwall_allowed(fire, PROTO_UDP, TEST_PORT_80), "Allow on not allowed port");

    zfwall_destroy(fire);
}
END_TEST

START_TEST (test_firewall_deny)
{
    struct zfirewall *fire = zfwall_create();

    zfwall_add_rule(fire, PROTO_TCP, PORT_DENY, TEST_PORT_53);
    zfwall_add_rule(fire, PROTO_UDP, PORT_DENY, TEST_PORT_53);

    fail_if(0 == zfwall_allowed(fire, PROTO_TCP, TEST_PORT_53), "Allow on denied port");
    fail_if(0 == zfwall_allowed(fire, PROTO_UDP, TEST_PORT_53), "Allow on denied port");

    fail_if(0 != zfwall_allowed(fire, PROTO_TCP, TEST_PORT_80), "Deny on not denied port");
    fail_if(0 != zfwall_allowed(fire, PROTO_UDP, TEST_PORT_80), "Deny on not denied port");

    zfwall_destroy(fire);
}
END_TEST

START_TEST (test_firewall_mixed)
{
    struct zfirewall *fire = zfwall_create();

    zfwall_add_rule(fire, PROTO_TCP, PORT_ALLOW, TEST_PORT_53);
    zfwall_add_rule(fire, PROTO_UDP, PORT_ALLOW, TEST_PORT_53);
    zfwall_add_rule(fire, PROTO_TCP, PORT_DENY, TEST_PORT_53);
    zfwall_add_rule(fire, PROTO_UDP, PORT_DENY, TEST_PORT_53);

    fail_if(0 == zfwall_allowed(fire, PROTO_TCP, TEST_PORT_53), "Allow on denied port");
    fail_if(0 == zfwall_allowed(fire, PROTO_UDP, TEST_PORT_53), "Allow on denied port");

    fail_if(0 == zfwall_allowed(fire, PROTO_TCP, TEST_PORT_80), "Allow on not allowed port");
    fail_if(0 == zfwall_allowed(fire, PROTO_UDP, TEST_PORT_80), "Allow on not allowed port");

    zfwall_destroy(fire);
}
END_TEST

START_TEST (test_firewall_double_add)
{
    struct zfirewall *fire = zfwall_create();

    zfwall_add_rule(fire, PROTO_TCP, PORT_DENY, TEST_PORT_53);
    zfwall_add_rule(fire, PROTO_TCP, PORT_DENY, TEST_PORT_53);
    zfwall_del_rule(fire, PROTO_TCP, PORT_DENY, TEST_PORT_53);

    fail_if(0 != zfwall_allowed(fire, PROTO_TCP, TEST_PORT_53), "Double added rule failed");

    zfwall_destroy(fire);
}
END_TEST

Suite* create_test_suite()
{
    Suite *suite = suite_create("firewall");
    TCase *tcase = tcase_create("case");
    tcase_add_test(tcase, test_firewall_empty);
    tcase_add_test(tcase, test_firewall_allow);
    tcase_add_test(tcase, test_firewall_deny);
    tcase_add_test(tcase, test_firewall_mixed);
    tcase_add_test(tcase, test_firewall_double_add);
    suite_add_tcase(suite, tcase);
    return suite;
}

int main (int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    int number_failed;

    Suite *suite = create_test_suite();
    SRunner *runner = srunner_create(suite);
    srunner_run_all(runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(runner);
    srunner_free(runner);
    return number_failed;
}
