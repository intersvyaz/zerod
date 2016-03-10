#include <check.h>
#include <util.c>

START_TEST (test_ip_range_cmp)
    {
        ip_range_t var1, var2;

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

START_TEST(test_ip_range_end)
    {
        uint32_t ip;
        uint16_t cidr = 32;
        ipv4_to_u32("12.12.12.12", &ip);
        fail_if(ip != IP_RANGE_END(ip, cidr), "IP_RANGE_END() failed");
    }
END_TEST

START_TEST (test_mac48_bin_to_str)
    {
        uint8_t mac[] = {0xab, 0xcd, 0xef, 0x00, 0x55, 0x31};
        const char str_mac[] = "ab:cd:ef:00:55:31";
        char result[HWADDR_MAC48_STR_LEN];
        mac48_bin_to_str(mac, result, sizeof(result));
        fail_if(0 != strcmp(str_mac, result), "mac48_bin_to_str() failed: %s != %s", str_mac, result);
    }
END_TEST

START_TEST (test_mac48_str_to_bin)
    {
        uint8_t mac[] = {0xab, 0xcd, 0xef, 0x00, 0x55, 0x31};
        const char str_mac[] = "ab:cd:ef:00:55:31";
        uint8_t result[HWADDR_MAC48_LEN];
        mac48_str_to_bin(result, str_mac);
        fail_if(0 != memcmp(mac, result, sizeof(result)), "mac48_str_to_bin() failed");
    }
END_TEST

Suite *create_test_suite()
{
    Suite *suite = suite_create("util");
    TCase *tcase = tcase_create("case");
    tcase_add_test(tcase, test_ip_range_cmp);
    tcase_add_test(tcase, test_uint16_cmp);
    tcase_add_test(tcase, test_ip_range_end);
    tcase_add_test(tcase, test_mac48_bin_to_str);
    tcase_add_test(tcase, test_mac48_str_to_bin);
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
