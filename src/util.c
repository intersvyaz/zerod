#include <stdio.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include "util.h"
#include "netproto.h"

const UT_icd ut_uint16_icd _UNUSED_ = {sizeof(uint16_t), NULL, NULL, NULL};
const UT_icd ut_uint32_icd _UNUSED_ = {sizeof(uint32_t), NULL, NULL, NULL};
const UT_icd ut_ip_range_icd _UNUSED_ = {sizeof(ip_range_t), NULL, NULL, NULL};

/**
 * IP range comparator.
 * @param[in] arg1
 * @param[in] arg2
 * @return Same as strcmp.
 */
int ip_range_cmp(const void *arg1, const void *arg2)
{
    const ip_range_t *ip1 = arg1, *ip2 = arg2;

    if (ip1->ip_end < ip2->ip_start) return -1;
    if (ip1->ip_start > ip2->ip_end) return 1;
    return 0;
}

/**
 * uint16_t comparator.
 * @param[in] arg1
 * @param[in] arg2
 * @return Same as strcmp.
 */
int uint16_cmp(const void *arg1, const void *arg2)
{
    const uint16_t *num1 = arg1, *num2 = arg2;

    if (*num1 < *num2) return -1;
    if (*num1 > *num2) return 1;
    return 0;
}

/**
 * Convert machine ipv4 to string.
 * @param[in] ip IP address (network order).
 * @param[in,out] buf Destination buffer.
 * @param[in] len Buffer size.
 * @return Zero on success.
 */
int ipv4_to_str(uint32_t ip, char *buf, uint32_t buf_len)
{
    if (NULL == inet_ntop(AF_INET, &ip, buf, buf_len)) {
        snprintf(buf, buf_len, "(invalid)");
        return -1;
    }

    return 0;
}

/**
 * Convert IPv4 address from string to uint32_t (host order).
 * @param[in] src Source IPv4 string.
 * @param[out] dst Destination buffer.
 * @return Zero on success.
 */
int ipv4_to_u32(const char *src, uint32_t *dst)
{
    struct in_addr addr;
    if (0 < inet_pton(AF_INET, src, &addr)) {
        *dst = ntohl(addr.s_addr);
        return 0;
    } else {
        *dst = 0;
        return -1;
    }
}

/**
 * Get socket peer address string.
 * @param[in] socket Socket descriptor.
 * @return String address representation.
 */
int getpeerip(int socket, char *buf, uint32_t buf_len)
{
    struct sockaddr_storage sa;
    socklen_t len = sizeof(sa);

    if (0 != getpeername(socket, (struct sockaddr *) &sa, &len)) {
        strncpy(buf, "(invalid)", buf_len);
        return -1;
    }

    struct sockaddr_in *sa4 = (struct sockaddr_in *) &sa;
    return ipv4_to_str(sa4->sin_addr.s_addr, buf, buf_len);
}

/**
 *
 */
int mac48_bin_to_str(const uint8_t *mac, char *buf, size_t buf_len)
{
    snprintf(buf, buf_len, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return 0;
}

/**
 *
 */
void mac48_str_to_bin(uint8_t *mac, const char *str)
{
    for (size_t i = 0; i < HWADDR_MAC48_LEN; i++) {
        mac[i] = (uint8_t) strtol(&str[i * 3], NULL, 16);
    }
}

/**
 * Update internet checksum.
 * Only for updating data aligned to word boundary.
 * @see rfc1624 for details.
 * @param old_csum Old checksum.
 * @param len Data length in words.
 * @param old_data Old data.
 * @param new_data New data.
 * @return New checksum.
 */
uint16_t in_csum_update(uint16_t old_csum, uint16_t len, const uint16_t *old_data, const uint16_t *new_data)
{
    uint32_t csum = (uint16_t) ~old_csum;

    while (len--) {
        csum += (uint16_t) ~*old_data + *new_data;
        old_data++;
        new_data++;
    }

    while (csum >> 16) {
        csum = (csum & 0xffff) + (csum >> 16);
    }

    return (uint16_t) ~csum;
}

/**
 * Enable core dump file.
 * @return Zero on success.
 */
int util_enable_coredump(void)
{
    if (-1 == prctl(PR_SET_DUMPABLE, 1, 0, 0, 0)) {
        return -1;
    }

    struct rlimit lim = {.rlim_max = RLIM_INFINITY, .rlim_cur = RLIM_INFINITY};
    if (setrlimit(RLIMIT_CORE, &lim) == 0) {
        return 0;
    } else {
        return -1;
    }
}
