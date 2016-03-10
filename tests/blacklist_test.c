#include <check.h>
#include <blacklist.c>

START_TEST (test_blacklist_reload)
    {
        zblacklist_t *bl = zblacklist_new();
        fail_if(zblacklist_reload(bl, TEST_DATA_PATH "/not_exists.txt"), "succeed to load not existing test file");
        fail_if(!zblacklist_reload(bl, TEST_DATA_PATH "/blacklist1.txt"), "failed to load test file");
        fail_if(!zblacklist_reload(bl, TEST_DATA_PATH "/blacklist1.txt"), "failed to reload load test file");
        zblacklist_free(bl);
    }
END_TEST

Suite *create_test_suite()
{
    Suite *suite = suite_create("blacklist");
    TCase *tcase = tcase_create("case");
    tcase_add_test(tcase, test_blacklist_reload);

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

