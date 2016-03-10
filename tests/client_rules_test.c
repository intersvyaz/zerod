#include <check.h>
#include "client_rules.c"

START_TEST (test_parse_bw)
    {
        zclient_rule_parser_t *parser = zclient_rule_parser_new();
        zclient_rules_t rules;

        zclient_rules_init(&rules);
        fail_if(!zclient_rule_parse(parser, &rules, "bw.4096Kbit.down"));
        fail_if(!zclient_rule_parse(parser, &rules, "bw.2048kbit.up"));
        fail_if(!rules.have.bw_down);
        fail_if(!rules.have.bw_up);
        fail_if(4096*1024/8 != rules.bw_down);
        fail_if(2048*1024/8 != rules.bw_up);

        zclient_rules_init(&rules);
        fail_if(!zclient_rule_parse(parser, &rules, "bw.15bit.down"));
        fail_if(rules.bw_down != 1);
        fail_if(!zclient_rule_parse(parser, &rules, "bw.16bit.down"));
        fail_if(rules.bw_down != 2);
        fail_if(!zclient_rule_parse(parser, &rules, "bw.17bit.down"));
        fail_if(rules.bw_down != 2);
        fail_if(!zclient_rule_parse(parser, &rules, "bw.12kbit.down"));
        fail_if(rules.bw_down != 12*1024/8);
        fail_if(!zclient_rule_parse(parser, &rules, "bw.13mbit.down"));
        fail_if(rules.bw_down != 13ull*1024*1024/8);
        fail_if(!zclient_rule_parse(parser, &rules, "bw.14gbit.down"));
        fail_if(rules.bw_down != 14ull*1024*1024*1024/8);
        fail_if(!zclient_rule_parse(parser, &rules, "bw.15tbit.down"));
        fail_if(rules.bw_down != 15ull*1024*1024*1024*1024/8);

        zclient_rules_init(&rules);
        fail_if(zclient_rule_parse(parser, &rules, " bw.4096kbit.down"));
        fail_if(zclient_rule_parse(parser, &rules, "bw.4096kbit.down "));
        fail_if(zclient_rule_parse(parser, &rules, "bw.4096vbit.down"));
        fail_if(zclient_rule_parse(parser, &rules, "bw.4096"));
        fail_if(zclient_rule_parse(parser, &rules, "bw.4096 "));
        fail_if(zclient_rule_parse(parser, &rules, "bw.4096 bit.up"));

        zclient_rules_destroy(&rules);
    }
END_TEST

START_TEST (test_parse_identity)
    {
        zclient_rule_parser_t *parser = zclient_rule_parser_new();
        zclient_rules_t rules;
        zclient_rules_init(&rules);

        fail_if(!zclient_rule_parse(parser, &rules, "identity.31337.login"));
        fail_if(!rules.have.user_id);
        fail_if(!rules.have.login);
        fail_if(31337 != rules.user_id);
        fail_if(0 != strcmp("LOGIN", rules.login));

        fail_if(zclient_rule_parse(parser, &rules, "identity.31d337.login"));
        fail_if(zclient_rule_parse(parser, &rules, "identity.31337.login "));
        fail_if(zclient_rule_parse(parser, &rules, " identity.31337.login"));
        fail_if(zclient_rule_parse(parser, &rules, "identity.login"));

        zclient_rules_destroy(&rules);
        zclient_rule_parser_free(parser);
    }
END_TEST

START_TEST (test_ports)
    {
        const zcr_port_t test_data[] = {
                {PROTO_TCP, ACCESS_ALLOW, htons(21), 1},
                {PROTO_TCP, ACCESS_ALLOW, htons(22), 1},
                {PROTO_UDP, ACCESS_ALLOW, htons(23), 1},
                {PROTO_UDP, ACCESS_ALLOW, htons(24), 1},
                {PROTO_TCP, ACCESS_DENY, htons(25), 1},
                {PROTO_TCP, ACCESS_DENY, htons(26), 1},
                {PROTO_UDP, ACCESS_DENY, htons(27), 1},
                {PROTO_UDP, ACCESS_DENY, htons(28), 1},
                {PROTO_TCP, ACCESS_ALLOW, htons(29), 0},
                {PROTO_TCP, ACCESS_ALLOW, htons(30), 0},
                {PROTO_UDP, ACCESS_ALLOW, htons(31), 0},
                {PROTO_UDP, ACCESS_ALLOW, htons(32), 0},
                {PROTO_TCP, ACCESS_DENY, htons(33), 0},
                {PROTO_TCP, ACCESS_DENY, htons(34), 0},
                {PROTO_UDP, ACCESS_DENY, htons(35), 0},
                {PROTO_UDP, ACCESS_DENY, htons(36), 0},
        };

        zclient_rule_parser_t *parser = zclient_rule_parser_new();
        zclient_rules_t rules;
        zclient_rules_init(&rules);

        fail_if(!zclient_rule_parse(parser, &rules, "ports.allow.tcp.21.22"));
        fail_if(!zclient_rule_parse(parser, &rules, "ports.allow.udp.23.24"));
        fail_if(!zclient_rule_parse(parser, &rules, "ports.deny.tcp.25.26"));
        fail_if(!zclient_rule_parse(parser, &rules, "ports.deny.udp.27.28"));
        fail_if(!zclient_rule_parse(parser, &rules, "rmports.allow.tcp.29.30"));
        fail_if(!zclient_rule_parse(parser, &rules, "rmports.allow.udp.31.32"));
        fail_if(!zclient_rule_parse(parser, &rules, "rmports.deny.tcp.33.34"));
        fail_if(!zclient_rule_parse(parser, &rules, "rmports.deny.udp.35.36"));
        fail_if(!rules.have.port_rules);
        fail_if(ARRAYSIZE(test_data) != utarray_len(&rules.port_rules));

        for (size_t i = 0; i < ARRAYSIZE(test_data); i++) {
            zcr_port_t *rule = *(zcr_port_t **) utarray_eltptr(&rules.port_rules, i);
            fail_if(test_data[i].add != rule->add, "ports idx=%u add flag fail", i);
            fail_if(test_data[i].proto != rule->proto, "ports idx=%u proto fail", i);
            fail_if(test_data[i].policy != rule->policy, "ports idx=%u policy fail", i);
            fail_if(test_data[i].port != rule->port, "ports idx=%u port fail", i);
        }

        zclient_rules_destroy(&rules);
    }
END_TEST

START_TEST (test_fwd)
    {
        const zcr_forward_t test_data[] = {
                {PROTO_TCP, htons(53), 0x04030201, 0, 1},
                {PROTO_UDP, htons(53), 0x08070605, 0, 1},
                {PROTO_TCP, htons(80), 0x0C0B0A09, htons(83), 1},
                {PROTO_UDP, htons(80), 0x100F0E0D, htons(83), 1},
                {PROTO_TCP, htons(53), 0, 0, 0},
                {PROTO_UDP, htons(53), 0, 0, 0},
                {PROTO_TCP, htons(80), 0, 0, 0},
                {PROTO_UDP, htons(80), 0, 0, 0},
        };

        zclient_rule_parser_t *parser = zclient_rule_parser_new();
        zclient_rules_t rules;
        zclient_rules_init(&rules);

        fail_if(!zclient_rule_parse(parser, &rules, "fwd.tcp.53.1.2.3.4"));
        fail_if(!zclient_rule_parse(parser, &rules, "fwd.udp.53.5.6.7.8"));
        fail_if(!zclient_rule_parse(parser, &rules, "fwd.tcp.80.9.10.11.12:83"));
        fail_if(!zclient_rule_parse(parser, &rules, "fwd.udp.80.13.14.15.16:83"));
        fail_if(!zclient_rule_parse(parser, &rules, "rmfwd.tcp.53"));
        fail_if(!zclient_rule_parse(parser, &rules, "rmfwd.udp.53"));
        fail_if(!zclient_rule_parse(parser, &rules, "rmfwd.tcp.80"));
        fail_if(!zclient_rule_parse(parser, &rules, "rmfwd.udp.80"));
        fail_if(!rules.have.fwd_rules, "fwd have fail");
        fail_if(ARRAYSIZE(test_data) != utarray_len(&rules.fwd_rules));

        for (size_t i = 0; i < ARRAYSIZE(test_data); i++) {
            zcr_forward_t *rule = *(zcr_forward_t **) utarray_eltptr(&rules.fwd_rules, i);
            fail_if(test_data[i].add != rule->add, "fwd idx=%u add flag fail", i);
            fail_if(test_data[i].proto != rule->proto, "fwd idx=%u proto fail", i);
            fail_if(test_data[i].port != rule->port, "fwd idx=%u port fail", i);
            fail_if(test_data[i].fwd_ip != rule->fwd_ip, "fwd idx=%u fwd_ip fail (0x%X)", i, rule->fwd_ip);
            fail_if(test_data[i].fwd_port != rule->fwd_port, "fwd idx=%u fwd_port fail", i);
        }

        zclient_rules_destroy(&rules);
    }
END_TEST

START_TEST (test_deferred)
    {
        const zcr_deferred_t test_data[] = {
                {125, "foo"},
                {1, "bar"},
        };

        zclient_rule_parser_t *parser = zclient_rule_parser_new();
        zclient_rules_t rules;
        zclient_rules_init(&rules);

        fail_if(!zclient_rule_parse(parser, &rules, "deferred.125.foo"), "parse fail");
        fail_if(!zclient_rule_parse(parser, &rules, "deferred.1.bar"), "parse fail");
        fail_if(!rules.have.deferred_rules, "fwd have fail");
        fail_if(sizeof(test_data) / sizeof(test_data[0]) != utarray_len(&rules.deferred_rules), "count fail");

        for (size_t i = 0; i < sizeof(test_data) / sizeof(test_data[0]); i++) {
            zcr_deferred_t *rule = *(zcr_deferred_t **) utarray_eltptr(&rules.deferred_rules, i);
            fail_if(test_data[i].when != rule->when, "idx=%u seconds fail", i);
            fail_if(0 != strcmp(test_data[i].rule, rule->rule), "idx=%u rule fail", i);
        }

        zclient_rules_destroy(&rules);
    }
END_TEST

START_TEST (test_rmdeferred)
    {
        zclient_rule_parser_t *parser = zclient_rule_parser_new();
        zclient_rules_t rules;
        zclient_rules_init(&rules);

        fail_if(!zclient_rule_parse(parser, &rules, "rmdeferred"), "parse fail");

        zclient_rules_destroy(&rules);
    }
END_TEST

START_TEST (test_make_identity)
    {
        UT_string str;
        utstring_init(&str);

        zclient_rules_make_identity(&str, 31337, "ABABA");
        fail_if(0 != strcmp(utstring_body(&str), "identity.31337.ABABA"), "make identity str fail");

        utstring_done(&str);
    }
END_TEST

START_TEST (test_make_bw)
    {
        UT_string str;
        utstring_init(&str);

        zclient_rules_make_bw(&str, 524288, DIR_DOWN);
        fail_if(0 != strcmp(utstring_body(&str), "bw.4096KBit.down"), "make bw down str fail");
        utstring_clear(&str);

        zclient_rules_make_bw(&str, 524288, DIR_UP);
        fail_if(0 != strcmp(utstring_body(&str), "bw.4096KBit.up"), "make bw up str fail");

        utstring_done(&str);
    }
END_TEST

START_TEST (test_make_ports)
    {
        UT_string str;
        utstring_init(&str);

        uint16_t ports[] = {htons(53), htons(80), htons(443)};
        size_t count = sizeof(ports) / sizeof(ports[0]);

        zclient_rules_make_ports(&str, PROTO_TCP, ACCESS_ALLOW, ports, count);
        fail_if(0 != strcmp(utstring_body(&str), "ports.allow.tcp.53.80.443"), "make ports str fail");
        utstring_clear(&str);

        zclient_rules_make_ports(&str, PROTO_UDP, ACCESS_ALLOW, ports, count);
        fail_if(0 != strcmp(utstring_body(&str), "ports.allow.udp.53.80.443"), "make ports str fail");
        utstring_clear(&str);

        zclient_rules_make_ports(&str, PROTO_TCP, ACCESS_DENY, ports, count);
        fail_if(0 != strcmp(utstring_body(&str), "ports.deny.tcp.53.80.443"), "make ports str fail");
        utstring_clear(&str);

        zclient_rules_make_ports(&str, PROTO_UDP, ACCESS_DENY, ports, count);
        fail_if(0 != strcmp(utstring_body(&str), "ports.deny.udp.53.80.443"), "make ports str fail");

        utstring_done(&str);
    }
END_TEST

START_TEST (test_make_fwd)
    {
        UT_string str;
        utstring_init(&str);

        zfwd_rule_t rule;
        rule.port = htons(80);
        rule.fwd_ip = 0x04030201;
        rule.fwd_port = htons(83);

        zclient_rules_make_fwd(&str, PROTO_TCP, &rule);
        fail_if(0 != strcmp(utstring_body(&str), "fwd.tcp.80.1.2.3.4:83"), "make fwd str fail");
        utstring_clear(&str);

        zclient_rules_make_fwd(&str, PROTO_UDP, &rule);
        fail_if(0 != strcmp(utstring_body(&str), "fwd.udp.80.1.2.3.4:83"), "make fwd str fail");
        utstring_clear(&str);

        rule.fwd_port = 0;

        zclient_rules_make_fwd(&str, PROTO_UDP, &rule);
        fail_if(0 != strcmp(utstring_body(&str), "fwd.udp.80.1.2.3.4"), "make fwd str fail");

        utstring_done(&str);
    }
END_TEST

Suite *create_test_suite()
{
    Suite *suite = suite_create("client_rules");
    TCase *tcase = tcase_create("case");
    tcase_add_test(tcase, test_parse_bw);
    tcase_add_test(tcase, test_parse_identity);
    tcase_add_test(tcase, test_ports);
    tcase_add_test(tcase, test_fwd);
    tcase_add_test(tcase, test_deferred);
    tcase_add_test(tcase, test_rmdeferred);
    tcase_add_test(tcase, test_make_identity);
    tcase_add_test(tcase, test_make_bw);
    tcase_add_test(tcase, test_make_ports);
    tcase_add_test(tcase, test_make_fwd);
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

