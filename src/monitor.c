#include "monitor.h"

#include <stdlib.h>
#include <pcap/pcap.h>
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "util.h"
#include "log.h"
#include "zero.h"

#define PCAP_SAVEFILE_MAGIC 0xa1b2c3d4
#define MONITOR_SNAPLEN     2000
#define MONITOR_BUFSIZE     5*1024*1024 // 5mb

struct pcap_timeval {
    // seconds
    bpf_int32 tv_sec;
    // microseconds
    bpf_int32 tv_usec;
};

struct pcap_sf_pkthdr {
    // time stamp
    struct pcap_timeval ts;
    // length of portion present
    bpf_u_int32 caplen;
    // length this packet (off wire)
    bpf_u_int32 len;
};

struct monitor {
    struct bufferevent *bev;
    struct bpf_program bpf;
    struct token_bucket bw;
    bool has_file_header;
};

/**
* @return New monitor instance.
*/
struct monitor *monitor_new(void)
{
    struct monitor *mon = malloc(sizeof(*mon));
    bzero(mon, sizeof(*mon));
    token_bucket_init(&mon->bw, zcfg()->monitors_conn_bw_limit);

    return mon;
}

/**
* @param[in] Monitor instance.
* Free monitor instance.
*/
void monitor_free(struct monitor *mon)
{
    if (mon->bev) {
        bufferevent_free(mon->bev);
    }
    pcap_freecode(&mon->bpf);
    free(mon);
}

/**
* Activate monitor.
* @param[in] mon Monitor instance.
*/
void monitor_activate(struct monitor *mon)
{
    pthread_rwlock_wrlock(&zinst()->monitors_lock);
    utarray_push_back(&zinst()->monitors, &mon);
    pthread_rwlock_unlock(&zinst()->monitors_lock);
}

/**
* Deactivate monitor.
* @param[in] mon Monitor instance.
*/
void monitor_deactivate(struct monitor *mon)
{
    pthread_rwlock_wrlock(&zinst()->monitors_lock);

    struct monitor **ptr = (struct monitor **) utarray_front(&zinst()->monitors);
    while (ptr) {
        if (*ptr == mon) {
            ssize_t idx = utarray_eltidx(&zinst()->monitors, ptr);
            utarray_erase(&zinst()->monitors, idx, 1);
            break;
        }
        ptr = (struct monitor **) utarray_next(&zinst()->monitors, ptr);
    }

    pthread_rwlock_unlock(&zinst()->monitors_lock);
}

/**
* @param[in,out] mon Monitor instance.
* @param[in] filter Filter string
* @return Zero on success.
*/
int monitor_set_filter(struct monitor *mon, const char *filter)
{
    pcap_t *cap = pcap_open_dead(DLT_EN10MB, MONITOR_SNAPLEN);
    pcap_freecode(&mon->bpf);

    if (0 != pcap_compile(cap, &mon->bpf, filter, 1, PCAP_NETMASK_UNKNOWN)) {
        ZERO_LOG(LOG_INFO, "Invalid monitor filter \"%s\": %s", filter, pcap_geterr(cap));
        pcap_close(cap);
        return -1;
    }

    pcap_close(cap);
    return 0;
}

/**
* Event handler for monitor connection.
* @param[in] bev
* @param[in] events
* @param[in] ctx
*/
static void monitor_event_cb(struct bufferevent *bev, short events, void *ctx)
{
    struct monitor *mon = (struct monitor *) ctx;

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        bufferevent_unlock(bev);
        monitor_deactivate(mon);
        bufferevent_lock(bev);
        monitor_free(mon);
    }
}

/**
* Associate bufferevent with monitor.
* @param[in] mon Monitor instance.
* @param[in] bev Bufferevent instance.
*/
void monitor_set_listener(struct monitor *mon, struct bufferevent *bev)
{
    bufferevent_priority_set(bev, LOW_PRIO);
    bufferevent_disable(bev, EV_READ);
    bufferevent_setcb(bev, NULL, NULL, monitor_event_cb, mon);
    mon->bev = bev;
}

/**
* Apply filters on packet and send it to listeners on success.
* @param[in] mon Monitor instance.
* @param[in] packet Packet buffer.
* @param[in] len Packet length.
* @return Zero on match.
*/
void monitor_mirror_packet(unsigned const char *packet, size_t len)
{
    pthread_rwlock_rdlock(&zinst()->monitors_lock);

    if (likely(!utarray_len(&zinst()->monitors))) {
        goto end;
    }

    uint64_t ts = ztime(false);
    struct pcap_pkthdr pkthdr = {
            .ts = {0},
            .caplen = (uint32_t) len,
            .len = (uint32_t) len
    };
    struct pcap_sf_pkthdr sf_pkthdr = {
            .ts = {.tv_sec = (uint32_t) (ts / 1000000), .tv_usec = (uint32_t) (ts % 1000000)},
            .caplen = (uint32_t) len,
            .len = (uint32_t) len
    };

    struct monitor **pmon = (struct monitor **) utarray_front(&zinst()->monitors);
    while (pmon) {
        size_t bufsize = evbuffer_get_length(bufferevent_get_output((*pmon)->bev));
        if (bufsize > MONITOR_BUFSIZE) {
            break;
        }

        if ((0 == (*pmon)->bpf.bf_len) || (0 != pcap_offline_filter(&(*pmon)->bpf, &pkthdr, packet))) {
            if (0 != token_bucket_update(&(*pmon)->bw, len)) {
                break;
            }
            if (0 != token_bucket_update(&zinst()->monitors_bucket, len)) {
                token_bucket_rollback(&(*pmon)->bw, len);
                break;
            }

            bufferevent_lock((*pmon)->bev);
            if (unlikely(!(*pmon)->has_file_header)) {
                // todo: this code does not work if it placed in monitor_set_listener()
                struct pcap_file_header sf_hdr = {
                        .magic = PCAP_SAVEFILE_MAGIC,
                        .version_major = PCAP_VERSION_MAJOR,
                        .version_minor = PCAP_VERSION_MINOR,
                        .thiszone = 0,
                        .sigfigs = 0,
                        .snaplen = MONITOR_SNAPLEN,
                        .linktype = DLT_EN10MB,
                };
                bufferevent_write((*pmon)->bev, &sf_hdr, sizeof(sf_hdr));
                (*pmon)->has_file_header = true;
            }
            bufferevent_write((*pmon)->bev, &sf_pkthdr, sizeof(sf_pkthdr));
            bufferevent_write((*pmon)->bev, packet, len);
            bufferevent_unlock((*pmon)->bev);
        }
        pmon = (struct monitor **) utarray_next(&zinst()->monitors, pmon);
    }
    end:
    pthread_rwlock_unlock(&zinst()->monitors_lock);
}
