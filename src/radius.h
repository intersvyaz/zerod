#ifndef ZEROD_RADIUS_H
#define ZEROD_RADIUS_H

#include <freeradius-client.h>
#include "session.h"
#include "scope.h"

typedef enum zrad_status_enum
{
    ZRAD_OTHER = -3,
    ZRAD_BADRESP = BADRESP_RC,
    ZRAD_ERROR = ERROR_RC,
    ZRAD_OK = OK_RC,
    ZRAD_TIMEOUT = TIMEOUT_RC,
    ZRAD_REJECT = REJECT_RC
} zrad_status_t;

zrad_status_t zradius_session_auth(zscope_t *scope, zsession_t *session);

zrad_status_t zradius_session_acct(zscope_t *scope, zsession_t *session, uint32_t status, uint32_t term_cause);

const char *zrad_decode_state(int code);

const char *zrad_decode_term_cause(int code);

#endif // ZEROD_RADIUS_H
