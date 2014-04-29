#include <check.h>

#include <crules.c>

START_TEST (test_parse_identity)
{
    struct zcrules rules;
    crules_init(&rules);

    fail_if(0 != crules_parse(&rules, "identity.31337.login"), "identity parse fail");
    fail_if(!rules.have.user_id, "identity user_id have fail");
    fail_if(!rules.have.login, "identity login have fail");
    fail_if(31337 != rules.user_id, "identity user_id value fail");
    fail_if(0 != strcmp("LOGIN", rules.login), "identity login value fail");

    crules_free(&rules);
}
END_TEST

START_TEST (test_parse_bw)
{
    struct zcrules rules;
    crules_init(&rules);

    fail_if(0 != crules_parse(&rules, "bw.4096Kbit.down"), "bw parse fail");
    fail_if(0 != crules_parse(&rules, "bw.2048Kbit.up"), "bw parse fail");
    fail_if(!rules.have.bw_down, "bw in have fail");
    fail_if(!rules.have.bw_up, "bw out have fail");
    fail_if(524288 != rules.bw_down, "bw in value fail");
    fail_if(262144 != rules.bw_up, "bw out value fail");

    crules_free(&rules);
}
END_TEST

START_TEST (test_p2p_policer)
{
    struct zcrules rules;
    crules_init(&rules);

    fail_if(0 != crules_parse(&rules, "p2p_policer.77"), "p2p_policer parse fail");
    fail_if(!rules.have.p2p_policer, "p2p_policer have fail");
    fail_if(77 != rules.p2p_policer, "p2p_policer value fail");

    crules_free(&rules);
}
END_TEST

START_TEST (test_ports)
{
    const struct zrule_port test_data[] = {
        {PROTO_TCP, PORT_ALLOW, htons(21), 1},
        {PROTO_TCP, PORT_ALLOW, htons(22), 1},
        {PROTO_UDP, PORT_ALLOW, htons(23), 1},
        {PROTO_UDP, PORT_ALLOW, htons(24), 1},
        {PROTO_TCP, PORT_DENY, htons(25), 1},
        {PROTO_TCP, PORT_DENY, htons(26), 1},
        {PROTO_UDP, PORT_DENY, htons(27), 1},
        {PROTO_UDP, PORT_DENY, htons(28), 1},
        {PROTO_TCP, PORT_ALLOW, htons(29), 0},
        {PROTO_TCP, PORT_ALLOW, htons(30), 0},
        {PROTO_UDP, PORT_ALLOW, htons(31), 0},
        {PROTO_UDP, PORT_ALLOW, htons(32), 0},
        {PROTO_TCP, PORT_DENY, htons(33), 0},
        {PROTO_TCP, PORT_DENY, htons(34), 0},
        {PROTO_UDP, PORT_DENY, htons(35), 0},
        {PROTO_UDP, PORT_DENY, htons(36), 0},
    };

    struct zcrules rules;
    crules_init(&rules);

    fail_if(0 != crules_parse(&rules, "ports.allow.tcp.21.22"), "ports parse fail");
    fail_if(0 != crules_parse(&rules, "ports.allow.udp.23.24"), "ports parse fail");
    fail_if(0 != crules_parse(&rules, "ports.deny.tcp.25.26"), "ports parse fail");
    fail_if(0 != crules_parse(&rules, "ports.deny.udp.27.28"), "ports parse fail");
    fail_if(0 != crules_parse(&rules, "rmports.allow.tcp.29.30"), "ports parse fail");
    fail_if(0 != crules_parse(&rules, "rmports.allow.udp.31.32"), "ports parse fail");
    fail_if(0 != crules_parse(&rules, "rmports.deny.tcp.33.34"), "ports parse fail");
    fail_if(0 != crules_parse(&rules, "rmports.deny.udp.35.36"), "ports parse fail");
    fail_if(!rules.have.port_rules, "ports have fail");
    fail_if(sizeof(test_data)/sizeof(test_data[0]) != utarray_len(&rules.port_rules), "ports count fail");

    for (size_t i=0; i< sizeof(test_data)/sizeof(test_data[0]); i++) {
        struct zrule_port *rule = *(struct zrule_port **)utarray_eltptr(&rules.port_rules, i);
        fail_if(test_data[i].add != rule->add, "ports idx=%u add flag fail", i);
        fail_if(test_data[i].proto != rule->proto, "ports idx=%u proto fail", i);
        fail_if(test_data[i].type != rule->type, "ports idx=%u type fail", i);
        fail_if(test_data[i].port != rule->port, "ports idx=%u port fail", i);
    }

    crules_free(&rules);
}
END_TEST

START_TEST (test_fwd)
{
    const struct zrule_fwd test_data[] = {
        {PROTO_TCP, htons(53), 0x04030201, 0, 1},
        {PROTO_UDP, htons(53), 0x08070605, 0, 1},
        {PROTO_TCP, htons(80), 0x0C0B0A09, htons(83), 1},
        {PROTO_UDP, htons(80), 0x100F0E0D, htons(83), 1},
        {PROTO_TCP, htons(53), 0, 0, 0},
        {PROTO_UDP, htons(53), 0, 0, 0},
        {PROTO_TCP, htons(80), 0, 0, 0},
        {PROTO_UDP, htons(80), 0, 0, 0},
    };

    struct zcrules rules;
    crules_init(&rules);

    fail_if(0 != crules_parse(&rules, "fwd.tcp.53.1.2.3.4"), "fwd parse fail");
    fail_if(0 != crules_parse(&rules, "fwd.udp.53.5.6.7.8"), "fwd parse fail");
    fail_if(0 != crules_parse(&rules, "fwd.tcp.80.9.10.11.12:83"), "fwd parse fail");
    fail_if(0 != crules_parse(&rules, "fwd.udp.80.13.14.15.16:83"), "fwd parse fail");
    fail_if(0 != crules_parse(&rules, "rmfwd.tcp.53"), "fwd parse fail");
    fail_if(0 != crules_parse(&rules, "rmfwd.udp.53"), "fwd parse fail");
    fail_if(0 != crules_parse(&rules, "rmfwd.tcp.80"), "fwd parse fail");
    fail_if(0 != crules_parse(&rules, "rmfwd.udp.80"), "fwd parse fail");
    fail_if(!rules.have.fwd_rules, "fwd have fail");
    fail_if(sizeof(test_data)/sizeof(test_data[0]) != utarray_len(&rules.fwd_rules), "fwd count fail");

    for (size_t i = 0; i < sizeof(test_data)/sizeof(test_data[0]); i++) {
        struct zrule_fwd *rule = *(struct zrule_fwd **)utarray_eltptr(&rules.fwd_rules, i);
        fail_if(test_data[i].add != rule->add, "fwd idx=%u add flag fail", i);
        fail_if(test_data[i].proto != rule->proto, "fwd idx=%u proto fail", i);
        fail_if(test_data[i].port != rule->port, "fwd idx=%u port fail", i);
        fail_if(test_data[i].fwd_ip != rule->fwd_ip, "fwd idx=%u fwd_ip fail (0x%X)", i, rule->fwd_ip);
        fail_if(test_data[i].fwd_port != rule->fwd_port, "fwd idx=%u fwd_port fail", i);
    }

    crules_free(&rules);
}
END_TEST

START_TEST (test_make_identity)
{
    UT_string str;
    utstring_init(&str);

    crules_make_identity(&str, 31337, "ABABA");
    fail_if(0 != strcmp(utstring_body(&str), "identity.31337.ABABA"), "make identity str fail");

    utstring_done(&str);
}
END_TEST

START_TEST (test_make_bw)
{
    UT_string str;
    utstring_init(&str);

    crules_make_bw(&str, 524288, DIR_DOWN);
    fail_if(0 != strcmp(utstring_body(&str), "bw.4096KBit.down"), "make bw down str fail");
    utstring_clear(&str);

    crules_make_bw(&str, 524288, DIR_UP);
    fail_if(0 != strcmp(utstring_body(&str), "bw.4096KBit.up"), "make bw up str fail");

    utstring_done(&str);
}
END_TEST

START_TEST (test_make_p2p_policer)
{
    UT_string str;
    utstring_init(&str);

    crules_make_p2p_policer(&str, 0);
    fail_if(0 != strcmp(utstring_body(&str), "p2p_policer.0"), "make p2p_policer str fail");
    utstring_clear(&str);

    crules_make_p2p_policer(&str, 1);
    fail_if(0 != strcmp(utstring_body(&str), "p2p_policer.1"), "make p2p_policer str fail");

    utstring_done(&str);
}
END_TEST

START_TEST (test_make_ports)
{
    UT_string str;
    utstring_init(&str);

    uint16_t ports[] = { htons(53), htons(80), htons(443)};
    size_t count = sizeof(ports)/sizeof(ports[0]);

    crules_make_ports(&str, PROTO_TCP, PORT_ALLOW, ports,  count);
    fail_if(0 != strcmp(utstring_body(&str), "ports.allow.tcp.53.80.443"), "make ports str fail");
    utstring_clear(&str);

    crules_make_ports(&str, PROTO_UDP, PORT_ALLOW, ports,  count);
    fail_if(0 != strcmp(utstring_body(&str), "ports.allow.udp.53.80.443"), "make ports str fail");
    utstring_clear(&str);

    crules_make_ports(&str, PROTO_TCP, PORT_DENY, ports,  count);
    fail_if(0 != strcmp(utstring_body(&str), "ports.deny.tcp.53.80.443"), "make ports str fail");
    utstring_clear(&str);

    crules_make_ports(&str, PROTO_UDP, PORT_DENY, ports,  count);
    fail_if(0 != strcmp(utstring_body(&str), "ports.deny.udp.53.80.443"), "make ports str fail");

    utstring_done(&str);
}
END_TEST

START_TEST (test_make_fwd)
{
    UT_string str;
    utstring_init(&str);

    struct zfwd_rule rule;
    rule.port = htons(80);
    rule.fwd_ip = 0x04030201;
    rule.fwd_port = htons(83);

    crules_make_fwd(&str, PROTO_TCP, &rule);
    fail_if(0 != strcmp(utstring_body(&str), "fwd.tcp.80.1.2.3.4:83"), "make fwd str fail");
    utstring_clear(&str);

    crules_make_fwd(&str, PROTO_UDP, &rule);
    fail_if(0 != strcmp(utstring_body(&str), "fwd.udp.80.1.2.3.4:83"), "make fwd str fail");
    utstring_clear(&str);

    rule.fwd_port = 0;

    crules_make_fwd(&str, PROTO_UDP, &rule);
    fail_if(0 != strcmp(utstring_body(&str), "fwd.udp.80.1.2.3.4"), "make fwd str fail");

    utstring_done(&str);
}
END_TEST

Suite* create_test_suite()
{
    Suite *suite = suite_create("rules");
    TCase *tcase = tcase_create("case");
    tcase_add_test(tcase, test_parse_identity);
    tcase_add_test(tcase, test_parse_bw);
    tcase_add_test(tcase, test_p2p_policer);
    tcase_add_test(tcase, test_ports);
    tcase_add_test(tcase, test_fwd);
    tcase_add_test(tcase, test_make_identity);
    tcase_add_test(tcase, test_make_bw);
    tcase_add_test(tcase, test_make_p2p_policer);
    tcase_add_test(tcase, test_make_ports);
    tcase_add_test(tcase, test_make_fwd);
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

