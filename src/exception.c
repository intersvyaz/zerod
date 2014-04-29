#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <err.h>
#include <stdint.h>
#include <execinfo.h>
#include <unistd.h>

#include "util.h"
#include "log.h"

#define MAX_STACK_FRAMES 64

static uint8_t alternate_stack[SIGSTKSZ];
static void *stack_traces[MAX_STACK_FRAMES];

void print_stack_trace()
{
    int trace_size = 0;
    char **messages = NULL;

    trace_size = backtrace(stack_traces, MAX_STACK_FRAMES);
    messages = backtrace_symbols(stack_traces, trace_size);

    for (int i = 0; i < trace_size; i++) {
        zero_syslog(LOG_ERR, "#%d: %s", i, messages[i]);
    }

    if (messages) free(messages);
}

void exception_handler(int sig, siginfo_t *siginfo, void *context)
{
    const char *sig_name = "Unknown signal";
    (void)context;

    switch (sig) {
    case SIGSEGV:
        sig_name = "SIGSEGV";
        break;
    case SIGABRT:
        sig_name = "SIGABRT";
        break;
    case SIGFPE:
        switch(siginfo->si_code)
        {
        case FPE_INTDIV:
            sig_name = "SIGFPE(FPE_INTDIV)";
            break;
        case FPE_INTOVF:
            sig_name = "SIGFPE(FPE_INTOVF)";
            break;
        case FPE_FLTDIV:
            sig_name = "SIGFPE(FPE_FLTDIV)";
            break;
        case FPE_FLTOVF:
            sig_name = "SIGFPE(FPE_FLTOVF)";
            break;
        case FPE_FLTUND:
            sig_name = "SIGFPE(FPE_FLTUND)";
            break;
        case FPE_FLTRES:
            sig_name = "SIGFPE(FPE_FLTRES)";
            break;
        case FPE_FLTINV:
            sig_name = "SIGFPE(FPE_FLTINV)";
            break;
        case FPE_FLTSUB:
            sig_name = "SIGFPE(FPE_FLTSUB)";
            break;
        default:
            sig_name = "SIGFPE";
            break;
        }
    case SIGILL:
        switch(siginfo->si_code)
        {
        case ILL_ILLOPC:
            sig_name = "SIGILL(ILL_ILLOPC)";
            break;
        case ILL_ILLOPN:
            sig_name = "SIGILL(ILL_ILLOPN)";
            break;
        case ILL_ILLADR:
            sig_name = "SIGILL(ILL_ILLADR)";
            break;
        case ILL_ILLTRP:
            sig_name = "SIGILL(ILL_ILLTRP)";
            break;
        case ILL_PRVOPC:
            sig_name = "SIGILL(ILL_PRVOPC)";
            break;
        case ILL_PRVREG:
            sig_name = "SIGILL(ILL_PRVREG)";
            break;
        case ILL_COPROC:
            sig_name = "SIGILL(ILL_COPROC)";
            break;
        case ILL_BADSTK:
            sig_name = "SIGILL(ILL_BADSTK)";
            break;
        default:
            sig_name = "SIGILL";
            break;
        }
        break;
    }

    zero_syslog(LOG_ERR, "Caught %s signal", sig_name);
    print_stack_trace();

    // pass to default handler to generate core dump if neccessary
    signal(sig, SIG_DFL);
    kill(getpid(), sig);
}

/**
 * Set unexpected behavior handlers.
 * @return Zero on success.
 */
int set_exception_handler()
{
    // setup alternate stack
    stack_t ss;
    bzero(&ss, sizeof(ss));
    ss.ss_sp = (void*)alternate_stack;
    ss.ss_size = SIGSTKSZ;
    ss.ss_flags = 0;

    if (0 != sigaltstack(&ss, NULL)) {
        ZERO_LOG(LOG_ERR, "Failed to set alternative stack for signal handler");
        return -1;
    }

    struct sigaction sig_action;
    bzero(&sig_action, sizeof(sig_action));
    sig_action.sa_sigaction = exception_handler;
    sigemptyset(&sig_action.sa_mask);

    sig_action.sa_flags = SA_SIGINFO | SA_ONSTACK;

    if (0 != sigaction(SIGSEGV, &sig_action, NULL)) {
        ZERO_LOG(LOG_ERR, "Failed to set SIGSEGV handler");
        return -1;
    }
    if (0 != sigaction(SIGFPE,  &sig_action, NULL)) {
        ZERO_LOG(LOG_ERR, "Failed to set SIGFPE handler");
        return -1;
    }
    if (0 != sigaction(SIGILL,  &sig_action, NULL)) {
        ZERO_LOG(LOG_ERR, "Failed to set SIGILL handler");
        return -1;
    }
    if (0 != sigaction(SIGABRT, &sig_action, NULL)) {
        ZERO_LOG(LOG_ERR, "Failed to set SIGABRT handler");
        return -1;
    }

    return 0;
}
