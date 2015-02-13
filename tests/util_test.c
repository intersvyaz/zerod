#include <check.h>

#include <util.c>

START_TEST (test_ip_range_cmp)
    {
        struct ip_range var1, var2;

        var1.ip_start = 0;
        var1.ip_end = 5;
        var2.ip_start = var2.ip_end = 7;
        fail_if(-1 != ip_range_cmp(&var1, &var2), "ip_range_cmp() fail on greater variable");

        var1.ip_start = 6;
        var1.ip_end = 10;
        var2.ip_start = var2.ip_end = 4;
        fail_if(1 != ip_range_cmp(&var1, &var2), "ip_range_cmp() fail on less variable");

        var1.ip_start = 0;
        var1.ip_end = 10;
        var2.ip_start = var2.ip_end = 5;
        fail_if(0 != ip_range_cmp(&var1, &var2), "ip_range_cmp() fail on equal variables");

        var1.ip_start = var1.ip_end = var2.ip_start = var2.ip_end = 12;
        fail_if(0 != ip_range_cmp(&var1, &var2), "ip_range_cmp() fail on true equal variables");
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

START_TEST (test_str_to_u8)
    {
        uint8_t val = 1;
        fail_if(0 != str_to_u8("0", &val));
        fail_if(0 != val);

        fail_if(0 != str_to_u8("1", &val));
        fail_if(1 != val);

        fail_if(0 != str_to_u8("255", &val));
        fail_if(255 != val);

        fail_if(0 == str_to_u8("256", &val));
        fail_if(0 == str_to_u8("-1", &val));
    }
END_TEST

START_TEST (test_str_to_u16)
    {
        uint16_t val = 1;
        fail_if(0 != str_to_u16("0", &val));
        fail_if(0 != val);

        fail_if(0 != str_to_u16("1", &val));
        fail_if(1 != val);

        fail_if(0 != str_to_u16("65535", &val));
        fail_if(65535 != val);

        fail_if(0 == str_to_u16("65536", &val));
        fail_if(0 == str_to_u16("-1", &val));
    }
END_TEST

START_TEST (test_str_to_u32)
    {
        uint32_t val = 1;
        fail_if(0 != str_to_u32("0", &val));
        fail_if(0u != val);

        fail_if(0 != str_to_u32("1", &val));
        fail_if(1u != val);

        fail_if(0 != str_to_u32("4294967295", &val));
        fail_if(4294967295u != val);

        fail_if(0 == str_to_u32("4294967296", &val));
        fail_if(0 == str_to_u32("-1", &val));
    }
END_TEST

START_TEST (test_str_to_u64)
    {
        uint64_t val = 1;
        fail_if(0 != str_to_u64("0", &val));
        fail_if(0u != val);

        fail_if(0 != str_to_u64("1", &val));
        fail_if(1u != val);

        fail_if(0 != str_to_u64("0blah", &val));
        fail_if(0u != val);
        fail_if(0 != str_to_u64("321   ", &val));
        fail_if(321u != val);
        fail_if(0 != str_to_u64("   123   ", &val));
        fail_if(123u != val);

        fail_if(0 != str_to_u64("18446744073709551615", &val));
        fail_if(18446744073709551615u != val);

        fail_if(0 == str_to_u64("18446744073709551616", &val));
        // todo: fix function and enable case below
        //fail_if(0 == str_to_u64("-1", &val));
    }
END_TEST

START_TEST(test_ip_range_end)
    {
        uint32_t ip;
        uint16_t cidr = 32;
        ipv4_to_u32("12.12.12.12", &ip);
        fail_if(ip != IP_RANGE_END(ip, cidr), "IP_RANGE_END() failed");
    }
END_TEST

Suite *create_test_suite()
{
    Suite *suite = suite_create("util");
    TCase *tcase = tcase_create("case");
    tcase_add_test(tcase, test_ip_range_cmp);
    tcase_add_test(tcase, test_uint16_cmp);
    tcase_add_test(tcase, test_str_ends_with);
    tcase_add_test(tcase, test_str_to_u8);
    tcase_add_test(tcase, test_str_to_u16);
    tcase_add_test(tcase, test_str_to_u32);
    tcase_add_test(tcase, test_str_to_u64);
    tcase_add_test(tcase, test_ip_range_end);
    suite_add_tcase(suite, tcase);
    return suite;
}

int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;

    int number_failed;

    Suite *suite = create_test_suite();
    SRunner *runner = srunner_create(suite);
    //srunner_set_fork_status(runner, CK_NOFORK);
    srunner_run_all(runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(runner);
    srunner_free(runner);
    return number_failed;
}
