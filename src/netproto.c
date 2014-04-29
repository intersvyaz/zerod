#include "netproto.h"

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
    uint32_t csum = (uint16_t)~old_csum;

    while (len--) {
        csum += (uint16_t)~*old_data + *new_data;
        old_data++;
        new_data++;
    }

    while (csum >> 16) {
        csum = (csum & 0xffff) + (csum >> 16);
    }

    return ~csum;
}
