#include <check.h>

#include <router/nat.c>

START_TEST (test_translation)
{
    struct znat *nat = znat_create();
    // x.x.x.x:1234 -> 8.8.8.8:53
    struct znat_origin origin = {1234, htons(53), 0x08080808};
    uint16_t port = znat_translate(nat, PROTO_TCP, &origin);
    fail_if(0 == port, "NAT translation returned zero port");

    struct znat_origin found_origin;
    fail_if(0 != znat_lookup(nat, PROTO_TCP, port, &found_origin), "NAT lookup failed");
    fail_if(origin.addr != found_origin.addr, "NAT lookup address not equals");
    fail_if(origin.dst_port != found_origin.dst_port, "NAT lookup dst port not equals");
    fail_if(origin.src_port != found_origin.src_port, "NAT lookup src port not equals");

    fail_if(0 == znat_lookup(nat, PROTO_UDP, 31337, &found_origin), "NAT lookup found untranslated entry");

    znat_destroy(nat);
}
END_TEST

Suite* create_test_suite()
{
    Suite *suite = suite_create("nat");
    TCase *tcase = tcase_create("case");
    tcase_add_test(tcase, test_translation);
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
