#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>

#include "config.h"
#include "netmap.h"
#include "log.h"
#include "zero.h"

enum zero_args {
    ZARG_NONE = 0x80,
#ifdef DEBUG
    ZARG_HEXDUMP
#endif
};

// command line options
static const char *opt_string = "VhvI:c:C:d";
static const struct option long_opts[] = {
        {"version", no_argument, NULL, 'V'},
        {"help", no_argument, NULL, 'h'},
        {"verbose", no_argument, NULL, 'v'},
        {"info", required_argument, NULL, 'I'},
        {"config", required_argument, NULL, 'c'},
        {"config-check", required_argument, NULL, 'C'},
        {"daemonize", no_argument, NULL, 'd'},
#ifdef DEBUG
        {"hex-dump", no_argument, NULL, ZARG_HEXDUMP},
#endif
        {NULL, no_argument, NULL, 0}
};

static void display_version(void)
{
    puts(
            "zerod v" ZEROD_VER_STR " (c) Intersvyaz 2013-\n"
            "Build: "
#ifdef DEBUG
            "DEBUG "
#endif
            "" __DATE__ " " __TIME__ "\n"
    );
}

static void display_usage(void)
{
    puts(
            "Usage: zerod [-vVhC] [-c path] [-I if]\n"
                    "Options:\n"
                    "\t-h, --help\tshow this help\n"
                    "\t-V, --version\tprint version\n"
                    "\t-v, --verbose\tverbose output (repeat for more verbosity)\n"
                    "\t-c, --config <file>\tconfiguration file path\n"
                    "\t-C, --config-check <file>\tcheck configuration file sanity\n"
                    "\t-I, --info <iface>\tshow <iface> information\n"
                    "\t-d, --daemonize (detach from console, run in background)\n"
#ifdef DEBUG
            "Debug options:\n"
            "\t--hex-dump, dump all packets in hex to stdout\n"
#endif
            "\nDefault configuration file: " ZEROD_DEFAULT_CONFIG "\n"
    );
}

static void display_if_info(const char *ifname)
{
    struct nmreq nm_req;

    if (0 != znm_info(ifname, &nm_req)) {
        return;
    }

    printf(
            "Interface: %s\n"
                    "\tMemory: %" PRIu32 " MB\n"
                    "\tRx rings/slots: %" PRIu16 "/%" PRIu32 "\n"
                    "\tTx rings/slots: %" PRIu16 "/%" PRIu32 "\n",
            ifname, nm_req.nr_memsize >> 20,
            nm_req.nr_rx_rings, nm_req.nr_rx_slots,
            nm_req.nr_tx_rings, nm_req.nr_tx_slots
    );
}

int main(int argc, char *argv[])
{
    struct zconfig zconf;
    const char *config_path = NULL;
    bool daemonize = false, config_check = false;

    bzero(&zconf, sizeof(zconf));

    // parse command line arguments
    int opt, long_index = 0;
    opt = getopt_long(argc, argv, opt_string, long_opts, &long_index);
    while (-1 != opt) {
        switch (opt) {
            case 'V':
                display_version();
                return EXIT_SUCCESS;

            case 'h':
                display_usage();
                return EXIT_SUCCESS;

            case 'v':
                g_verbosity++;
                if (20 == g_verbosity) {
                    puts("More verbosity? Are you kidding? ;)");
                }
                break;

            case 'd':
                daemonize = true;
                break;

            case 'I':
                display_if_info(optarg);
                return EXIT_SUCCESS;

            case 'c':
                config_path = optarg;
                break;

            case 'C':
                config_path = optarg;
                config_check = true;
                break;
#ifdef DEBUG
            case ZARG_HEXDUMP:
                zconf.dbg.hexdump = true;
                break;
#endif
            default:
                return EXIT_FAILURE;
        }

        opt = getopt_long(argc, argv, opt_string, long_opts, &long_index);
    }

    zero_openlog();

    if (NULL == config_path) {
        config_path = ZEROD_DEFAULT_CONFIG;
    }

    if (0 != zero_config_load(config_path, &zconf)) {
        return EXIT_FAILURE;
    }

    if (config_check) {
        puts("Configuration file seems to be sane. Good luck! :)");
    } else {
        if (zconf.enable_coredump) {
            enable_coredump();
        }

        if (0 == zero_instance_init(&zconf)) {
            if (daemonize) {
                pid_t pid = fork();
                if (pid < 0) {
                    ZERO_ELOG(LOG_ERR, "Fork failed");
                } else if (0 == pid) {
                    close(0);
                    close(1);
                    close(2);
                    setsid();
                    // do this or working directory will be locked
                    if (0 == chdir("/")) {
                        zero_instance_run();
                    } else {
                        ZERO_ELOG(LOG_ERR, "Chdir / failed");
                    }
                }
            } else {
                zero_instance_run();
            }

            zero_instance_free();
        }
    }

    zero_config_free(&zconf);
    zero_closelog();

    return EXIT_SUCCESS;
}

