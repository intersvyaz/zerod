#include <check.h>
#include <util_string.c>

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

START_TEST (test_str_parse_si_unit)
    {
        fail_if(str_parse_si_unit('a', 1000) != 1u);
        fail_if(str_parse_si_unit('k', 1000) != 1000u);
        fail_if(str_parse_si_unit('m', 1000) != 1000000u);
        fail_if(str_parse_si_unit('g', 1000) != 1000000000u);
        fail_if(str_parse_si_unit('t', 1000) != 1000000000000u);
        fail_if(str_parse_si_unit('p', 1000) != 1000000000000000u);
        fail_if(str_parse_si_unit('e', 1000) != 1000000000000000000u);
    }
END_TEST

Suite *create_test_suite()
{
    Suite *suite = suite_create("util");
    TCase *tcase = tcase_create("case");
    tcase_add_test(tcase, test_str_ends_with);
    tcase_add_test(tcase, test_str_to_u8);
    tcase_add_test(tcase, test_str_to_u16);
    tcase_add_test(tcase, test_str_to_u32);
    tcase_add_test(tcase, test_str_to_u64);
    tcase_add_test(tcase, test_str_parse_si_unit);
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
