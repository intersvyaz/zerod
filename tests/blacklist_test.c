#include <check.h>
#include <blacklist.c>

START_TEST (test_blacklist_reload)
    {
        //struct zblacklist *bl = zbacklist_new();
        //zblacklist_reload(bl, "../../zerod.blacklist.dist");
        // TODO: make file path nonrelative
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

