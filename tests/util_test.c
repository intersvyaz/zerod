#include <check.h>
#include <unistd.h>

#include <util.c>

START_TEST (test_ip_range_cmp)
{
    struct ip_range var1, var2;

    var1.ip_start = 0;
    var1.ip_end = 5;
    var2.ip_start = var2.ip_end = 7;
    fail_if(-1 != ip_range_cmp(&var1, &var2), "uint16_cmp() fail on greater variable");

    var1.ip_start = 6;
    var1.ip_end = 10;
    var2.ip_start = var2.ip_end = 4;
    fail_if(1 != ip_range_cmp(&var1, &var2), "uint16_cmp() fail on less variable");

    var1.ip_start = 0;
    var1.ip_end = 10;
    var2.ip_start = var2.ip_end = 5;
    fail_if(0 != ip_range_cmp(&var1, &var2), "uint16_cmp() fail on equal variables");
}
END_TEST


START_TEST (test_uint16_cmp)
{
    uint16_t var1, var2;

    var1 = 5;
    var2 = 6;
    fail_if(-1 != uint16_cmp(&var1, &var2), "uint16_cmp() fail on greater variable");

    var1 = 6;
    var2 = 5;
    fail_if(1 != uint16_cmp(&var1, &var2), "uint16_cmp() fail on less variable");

    var1 = var2 = 1;
    fail_if(0 != uint16_cmp(&var1, &var2), "uint16_cmp() fail on equal variables");
}
END_TEST

START_TEST (test_str_ends_with)
{
    fail_if(0 == str_ends_with("foobar", "bar"), "str_ends_with() fail on valid suffix");
    fail_if(0 != str_ends_with("foobar", "baz"), "str_ends_with() fail on invalid suffix");
    fail_if(0 != str_ends_with("foo", "barfoo"), "str_ends_with() fail on suffix bigger than string");
}
END_TEST

Suite* create_test_suite()
{
    Suite *suite = suite_create("util");
    TCase *tcase = tcase_create("case");
    tcase_add_test(tcase, test_ip_range_cmp);
    tcase_add_test(tcase, test_uint16_cmp);
    tcase_add_test(tcase, test_str_ends_with);
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
