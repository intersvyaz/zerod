#include <stdbool.h>
#include <arpa/inet.h>
#include <check.h>
#include <netproto.h>
#include <util.h>

START_TEST (netproto_ipv4_is_de_class)
    {
        struct {
            const char *ip;
            bool ret;
        } data[] = {
                {"1.0.0.0", false},
                {"222.0.0.0", false},
                {"223.0.0.0", false},
                {"224.0.0.0", true},
                {"225.0.0.0", true},
                {"239.0.0.0", true},
                {"240.0.0.0", true},
                {"241.0.0.0", true},
                {"255.0.0.0", true},
        };

        for(size_t i=0; i < ARRAYSIZE(data); i++) {
            struct in_addr ip;

            inet_pton(AF_INET, data[i].ip, &ip);
            fail_if(data[i].ret != IPV4_IS_DE_CLASS(ntohl(ip.s_addr)), "IPV4_IS_DE_CLASS(%s)");
        }
    }
END_TEST

Suite *create_test_suite()
{
    Suite *suite = suite_create("netproto");
    TCase *tcase = tcase_create("case");
    tcase_add_test(tcase, netproto_ipv4_is_de_class);

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

