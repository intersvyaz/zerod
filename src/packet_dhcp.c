#include "packet.h"

/**
 *
 */
static void zpkt_dhcp_bootreply(zpacket_t *packet, const struct dhcp_header *dhcph, size_t len)
{
    uint32_t session_ip = ntohl(dhcph->yiaddr);
    packet->dst_ip = session_ip;

    zscope_t *scope = zpacket_guess_scope(packet);
    if (!scope || !scope->cfg->security.dhcp_snooping) {
        return;
    }

    bool is_ack = false;
    uint64_t lease_time = 0;
    const struct dhcp_opt *opt = dhcph->opts;

    while (len >= DHCP_OPT_SIZE(opt)) {
        switch (opt->code) {
            case DHCP_OPT_MESSAGE:
                if ((sizeof(uint8_t) == opt->len) && (DHCPACK == opt->data.u8[0])) {
                    is_ack = true;
                } else {
                    // skip all non-ack packets
                    return;
                }
                break;
            case DHCP_OPT_LEASE_TIME:
                if (sizeof(uint32_t) == opt->len) {
                    lease_time = SEC2USEC(ntohl(opt->data.u32[0]));
                } else {
                    return;
                }
                break;
            default:
                break;
        }

        len -= DHCP_OPT_SIZE(opt);
        opt = DHCP_OPT_NEXT(opt);
    }

    if (is_ack && lease_time) {
        zscope_dhcp_bind(scope, dhcph->chaddr, session_ip, lease_time);
    }
}

/**
 * Process DHCP packets.
 * @param[in] packet Packet.
 * @param[in] dhcph DHCP packet.
 */
void zpacket_process_dhcp(zpacket_t *packet, struct dhcp_header *dhcph, size_t len)
{
    if ((sizeof(*dhcph) > len) || (HWADDR_MAC48_LEN != dhcph->hlen)) {
        return;
    }

    switch (dhcph->op) {
        case BOOTREPLY:
            zpkt_dhcp_bootreply(packet, dhcph, len);
        default:
            break;
    }
}
