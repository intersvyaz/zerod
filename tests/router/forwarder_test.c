#include <check.h>

#include <router/forwarder.c>

#define TEST_PORT_53 htons(53)
#define TEST_PORT_80 htons(80)
#define TEST_IP 0x80808080
#define TEST_PORT 0x8080

START_TEST (test_forward)
{
    struct zfwd_rule rule;
    struct zforwarder *fwdr  = zfwd_create();

    zfwd_add_rule(fwdr, PROTO_TCP, TEST_PORT_53, TEST_IP, TEST_PORT);
    zfwd_add_rule(fwdr, PROTO_UDP, TEST_PORT_53, TEST_IP, TEST_PORT);

    fail_if(0 != zfwd_find_rule(fwdr, PROTO_TCP, TEST_PORT_53, &rule), "rule search fail");
    fail_if(TEST_IP != rule.fwd_ip, "rule search invalid ip");
    fail_if(TEST_PORT != rule.fwd_port, "rule search invalid port");

    fail_if(0 != zfwd_find_rule(fwdr, PROTO_UDP, TEST_PORT_53, &rule), "rule search fail");
    fail_if(TEST_IP != rule.fwd_ip, "rule search invalid ip");
    fail_if(TEST_PORT != rule.fwd_port, "rule search invalid port");

    fail_if(0 == zfwd_find_rule(fwdr, PROTO_TCP, TEST_PORT_80, &rule), "found not existent rule");
    fail_if(0 == zfwd_find_rule(fwdr, PROTO_UDP, TEST_PORT_80, &rule), "found not existent rule");

    zfwd_del_rule(fwdr, PROTO_TCP, TEST_PORT_53);
    fail_if(0 == zfwd_find_rule(fwdr, PROTO_TCP, TEST_PORT_53, &rule), "deleted rule search fail");

    zfwd_del_rule(fwdr, PROTO_UDP, TEST_PORT_53);
    fail_if(0 == zfwd_find_rule(fwdr, PROTO_UDP, TEST_PORT_53, &rule), "deleted rule search fail");

    zfwd_destroy(fwdr);
}
END_TEST

START_TEST (test_overwrite)
{
    struct zfwd_rule rule;
    struct zforwarder *fwdr  = zfwd_create();

    zfwd_add_rule(fwdr, PROTO_TCP, TEST_PORT_53, 0x55555555u, 0x5555u);
    zfwd_add_rule(fwdr, PROTO_TCP, TEST_PORT_53, TEST_IP, TEST_PORT);

    fail_if(0 != zfwd_find_rule(fwdr, PROTO_TCP, TEST_PORT_53, &rule), "rule search fail");
    fail_if(TEST_IP != rule.fwd_ip, "rule search invalid ip");
    fail_if(TEST_PORT != rule.fwd_port, "rule search invalid port");

    zfwd_destroy(fwdr);
}
END_TEST

Suite* create_test_suite()
{
    Suite *suite = suite_create("forwarder");
    TCase *tcase = tcase_create("case");
    tcase_add_test(tcase, test_forward);
    tcase_add_test(tcase, test_overwrite);
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
